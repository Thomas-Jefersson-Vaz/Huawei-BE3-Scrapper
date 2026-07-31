"""
Async HTTP client for Huawei WiFi BE3 (WS8100) router API.

Handles the full authentication lifecycle:
  1. Fetch login page to extract CSRF token from HTML meta tags
  2. SCRAM challenge-response via user_login_nonce / user_login_proof
  3. Session cookie (SessionID_R3) management
  4. Automatic endpoint fallbacks (e.g. for connected devices & WAN stats)

Based on reverse-engineering from:
https://github.com/vmakeev/huawei_mesh_router
"""

import asyncio
import json
import logging
import re
from typing import Any, Dict, List, Optional

import aiohttp

from crypto import generate_nonce, get_client_proof

logger = logging.getLogger(__name__)

# --- Constants ---
SESSION_COOKIE = "SessionID_R3"
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=10)

# Endpoints
URL_DEVICE_INFO = "api/system/deviceinfo"
URL_DEVICE_TOPOLOGY = "api/device/topology"
URL_WANDETECT = "api/ntwk/wandetect"

# Devices endpoints to try in order
HOST_INFO_ENDPOINTS = [
    "api/system/HostInfo",
    "api/system/hostinfo",
    "api/wlan/host-list",
    "api/wlan/host_list",
    "api/ntwk/lan_device_info",
]

# WAN info endpoints to try in order
WAN_INFO_ENDPOINTS = [
    "api/ntwk/wan?type=active",
    "api/ntwk/wan_info",
    "api/ntwk/wan",
]


class AuthenticationError(Exception):
    """Raised when authentication with the router fails."""

    def __init__(self, message: str, reason: str = "unknown"):
        super().__init__(message)
        self.reason = reason


class ApiCallError(Exception):
    """Raised when an API call returns an error response."""

    def __init__(self, message: str, code: Optional[int] = None, category: Optional[str] = None):
        super().__init__(message)
        self.code = code
        self.category = category


class HuaweiClient:
    """
    Async client for the Huawei WiFi BE3 router API.

    Usage:
        async with HuaweiClient("192.168.3.1", 80, "admin", "password") as client:
            info = await client.get_router_info()
            devices = await client.get_connected_devices()
    """

    def __init__(
        self,
        host: str,
        port: int = 80,
        user: str = "admin",
        password: str = "",
        use_ssl: bool = False,
    ):
        self._host = host
        self._port = port
        self._user = user
        self._password = password
        self._use_ssl = use_ssl
        self._session: Optional[aiohttp.ClientSession] = None
        self._csrf: Optional[Dict[str, str]] = None
        self._authenticated = False
        self._lock = asyncio.Lock()
        self._working_host_info_endpoint: Optional[str] = None
        self._working_wan_info_endpoint: Optional[str] = None

        schema = "https" if use_ssl else "http"
        self._base_url = f"{schema}://{host}:{port}"

    async def __aenter__(self):
        await self._create_session()
        return self

    async def __aexit__(self, *args):
        await self.disconnect()

    async def _create_session(self):
        """Create an aiohttp session with unsafe cookies (needed for IP-based hosts)."""
        if self._session is None or self._session.closed:
            jar = aiohttp.CookieJar(unsafe=True)
            self._session = aiohttp.ClientSession(
                cookie_jar=jar,
                timeout=REQUEST_TIMEOUT,
            )
            self._csrf = None
            self._authenticated = False

    async def disconnect(self):
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            try:
                await self._try_logout()
            except Exception:
                pass
            await self._session.close()
            self._session = None
            self._authenticated = False

    # ─── Authentication ───────────────────────────────────────────────

    async def authenticate(self):
        """
        Perform full SCRAM authentication with the router.

        Flow:
          1. GET html/index.html#/login → extract CSRF meta tags
          2. POST api/system/user_login_nonce → get salt, iterations, server nonce
          3. Compute client proof via PBKDF2-SHA256 + HMAC
          4. POST api/system/user_login_proof → validate proof
        """
        async with self._lock:
            await self._create_session()

            # Clear existing cookies
            self._session.cookie_jar.clear()
            self._csrf = None

            # Step 1: Get initial CSRF from login page
            if not await self._init_csrf():
                raise AuthenticationError("Failed to get initial CSRF token", "csrf_init")

            # Step 2: Send client nonce
            first_nonce = generate_nonce()

            resp = await self._post_raw(
                "api/system/user_login_nonce",
                {
                    "csrf": self._csrf,
                    "data": {"username": self._user, "firstnonce": first_nonce},
                },
            )

            if resp.status != 200:
                raise AuthenticationError(
                    f"Nonce request failed with status {resp.status}", "nonce_failed"
                )

            result = await self._parse_response(resp)
            self._update_csrf(result)
            self._check_errors(result)

            server_nonce = result["servernonce"]
            iterations = int(result["iterations"])
            salt = result["salt"]

            # Step 3: Compute and send client proof
            client_proof = get_client_proof(
                self._password, salt, iterations, first_nonce, server_nonce
            )

            resp = await self._post_raw(
                "api/system/user_login_proof",
                {
                    "csrf": self._csrf,
                    "data": {
                        "clientproof": client_proof,
                        "finalnonce": server_nonce,
                    },
                },
            )

            if resp.status != 200:
                raise AuthenticationError(
                    f"Proof request failed with status {resp.status}", "proof_failed"
                )

            result = await self._parse_response(resp)
            self._update_csrf(result)
            self._check_errors(result)

            self._authenticated = True
            logger.info("✅ Authentication successful")

    async def _init_csrf(self) -> bool:
        """Extract CSRF token from the router's login page HTML."""
        try:
            resp = await self._session.get(
                f"{self._base_url}/html/index.html#/login",
                allow_redirects=True,
                ssl=False,
            )

            if resp.status != 200:
                logger.error("Failed to load login page: status %d", resp.status)
                return False

            content = await resp.content.read()
            text = content.decode("utf-8", errors="ignore")

            param_match = re.search(r'<meta name="csrf_param" content="(.+?)"/>', text)
            token_match = re.search(r'<meta name="csrf_token" content="(.+?)"/>', text)

            if not param_match or not token_match:
                logger.error("CSRF meta tags not found in login page")
                return False

            self._csrf = {
                "csrf_param": param_match.group(1),
                "csrf_token": token_match.group(1),
            }
            logger.debug("CSRF initialized: param=%s", self._csrf["csrf_param"])
            return True

        except Exception as e:
            logger.error("Failed to init CSRF: %s", e)
            return False

    async def _try_logout(self):
        """Attempt graceful logout."""
        try:
            if self._csrf:
                await self._post_raw(
                    "api/system/user_logout",
                    {"csrf": self._csrf},
                )
        except Exception:
            pass

    # ─── HTTP Primitives ──────────────────────────────────────────────

    async def _get_raw(self, path: str) -> aiohttp.ClientResponse:
        """Perform a raw GET request."""
        url = f"{self._base_url}/{path}"
        return await self._session.get(url, allow_redirects=True, ssl=False)

    async def _post_raw(
        self, path: str, data: Dict, headers: Optional[Dict] = None
    ) -> aiohttp.ClientResponse:
        """Perform a raw POST request with JSON body."""
        url = f"{self._base_url}/{path}"
        return await self._session.post(
            url, data=json.dumps(data), ssl=False, headers=headers
        )

    @staticmethod
    async def _parse_response(resp: aiohttp.ClientResponse) -> Optional[Any]:
        """Read and parse response as JSON."""
        content = await resp.content.read()
        text = content.decode("utf-8", errors="ignore")
        if not text:
            return None
        try:
            return json.loads(text)
        except Exception:
            # HTML response or non-JSON
            return None

    def _update_csrf(self, data: Optional[Any]):
        """Update CSRF tokens if present in response data."""
        if isinstance(data, dict) and "csrf_param" in data and "csrf_token" in data:
            self._csrf = {
                "csrf_param": data["csrf_param"],
                "csrf_token": data["csrf_token"],
            }

    def _check_errors(self, data: Optional[Any]):
        """Raise ApiCallError if the response contains error indicators."""
        if not isinstance(data, dict):
            return

        if "err" in data and data["err"] != 0:
            category = data.get("errorCategory", "unknown")
            raise ApiCallError(f"API error: {category}", data["err"], category)

        if "errcode" in data and data["errcode"] != 0:
            category = "csrf_error" if data.get("csrf") == "Menu.csrf_err" else None
            raise ApiCallError(f"API errcode: {data['errcode']}", data["errcode"], category)

    # ─── Authenticated API Calls ──────────────────────────────────────

    async def _ensure_authenticated(self):
        """Authenticate if not already done."""
        if not self._authenticated:
            await self.authenticate()

    async def get(self, path: str) -> Optional[Any]:
        """
        Perform an authenticated GET request.
        Returns None if endpoint returns 404 (Not Found).
        Does NOT trigger re-auth on 404.
        """
        await self._ensure_authenticated()

        resp = await self._get_raw(path)

        # 404 means endpoint path doesn't exist on this router model
        if resp.status == 404:
            logger.debug("Endpoint 404 (Not Found): %s", path)
            return None

        # 401 / 403 means session expired or unauthorized
        if resp.status in (401, 403):
            logger.warning("Got %d on %s, re-authenticating...", resp.status, path)
            await self.authenticate()
            resp = await self._get_raw(path)
            if resp.status in (401, 403, 404):
                return None

        result = await self._parse_response(resp)
        self._update_csrf(result)
        self._check_errors(result)
        return result

    # ─── High-Level Data Methods ──────────────────────────────────────

    async def get_router_info(self) -> Dict[str, Any]:
        """
        Get router hardware/software information.
        """
        data = await self.get(URL_DEVICE_INFO)
        if not isinstance(data, dict):
            return {}

        return {
            "name": data.get("FriendlyName", "Huawei BE3"),
            "model": data.get("custinfo", {}).get("CustDeviceName", "Huawei BE3"),
            "serial_number": data.get("SerialNumber", ""),
            "software_version": data.get("SoftwareVersion", ""),
            "hardware_version": data.get("HardwareVersion", ""),
            "harmony_os_version": data.get("HarmonyOSVersion", ""),
            "uptime": data.get("UpTime", 0),
        }

    async def get_connected_devices(self) -> List[Dict[str, Any]]:
        """
        Get all known/connected devices.
        Tries alternative endpoints if the default one 404s.
        If all direct endpoints 404, extracts devices from topology.
        """
        # If we previously found a working endpoint, try it first
        endpoints_to_try = (
            [self._working_host_info_endpoint] + HOST_INFO_ENDPOINTS
            if self._working_host_info_endpoint
            else HOST_INFO_ENDPOINTS
        )

        for endpoint in endpoints_to_try:
            if not endpoint:
                continue
            data = await self.get(endpoint)
            if data is not None:
                self._working_host_info_endpoint = endpoint
                logger.debug("Connected devices endpoint found: %s", endpoint)
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict) and "HostList" in data:
                    return data["HostList"]

        # Fallback: Extract connected devices from topology tree
        logger.debug("Direct device endpoints 404'd, extracting from topology tree")
        topology = await self.get_device_topology()
        return self._extract_devices_from_topology(topology)

    def _extract_devices_from_topology(self, node: Any) -> List[Dict[str, Any]]:
        """Recursively extract devices from mesh topology JSON."""
        devices = []
        if isinstance(node, list):
            for item in node:
                devices.extend(self._extract_devices_from_topology(item))
        elif isinstance(node, dict):
            connected = node.get("ConnectedDevices", [])
            for dev in connected:
                if isinstance(dev, dict):
                    devices.append({
                        "MACAddress": dev.get("MACAddress", ""),
                        "IPAddress": dev.get("IPAddress", ""),
                        "HostName": dev.get("HostName", dev.get("DeviceName", "Unknown")),
                        "AccessType": dev.get("AccessType", dev.get("ConnectType", dev.get("PortType", dev.get("Band", "")))),
                        "UpRate": dev.get("UpSpeed", dev.get("UpRate", 0)),
                        "DownRate": dev.get("DownSpeed", dev.get("DownRate", 0)),
                        "IsOnline": True,
                    })
                    # Recurse for nested devices
                    devices.extend(self._extract_devices_from_topology(dev))
        return devices

    async def get_wan_info(self) -> Dict[str, Any]:
        """
        Get WAN connection status and bandwidth.
        """
        detect_data = await self.get(URL_WANDETECT)
        if not isinstance(detect_data, dict):
            detect_data = {}

        rate_data = None
        endpoints_to_try = (
            [self._working_wan_info_endpoint] + WAN_INFO_ENDPOINTS
            if self._working_wan_info_endpoint
            else WAN_INFO_ENDPOINTS
        )

        for endpoint in endpoints_to_try:
            if not endpoint:
                continue
            res = await self.get(endpoint)
            if res is not None and isinstance(res, dict):
                self._working_wan_info_endpoint = endpoint
                rate_data = res
                break

        if not rate_data:
            rate_data = {}

        external_ip = (
            detect_data.get("ExternalIPAddress")
            or detect_data.get("ExternalIP")
            or detect_data.get("ExternalIp")
            or detect_data.get("WanIP")
            or detect_data.get("WanIp")
            or detect_data.get("IPAddress")
            or rate_data.get("ExternalIPAddress")
            or rate_data.get("ExternalIP")
            or rate_data.get("IPAddress")
            or ""
        )

        return {
            "connected": detect_data.get("Status") == "Connected" or bool(external_ip),
            "external_ip": external_ip,
            "uptime": detect_data.get("Uptime", rate_data.get("Uptime", 0)),
            "upload_rate": rate_data.get("UpBandwidth", rate_data.get("UpRate", 0)),
            "download_rate": rate_data.get("DownBandwidth", rate_data.get("DownRate", 0)),
        }

    async def get_device_topology(self) -> Any:
        """
        Get mesh network topology.
        """
        data = await self.get(URL_DEVICE_TOPOLOGY)
        return data if data is not None else []
