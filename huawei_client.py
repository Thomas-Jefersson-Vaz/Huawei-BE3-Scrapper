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

DEVICE_INFO_ENDPOINTS = [
    "api/system/deviceinfo",
    "api/system/device_info",
    "api/system/HostInfo",
    "api/system/status",
    "api/system/information",
]

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
    "api/ntwk/wandetect",
    "api/ntwk/wan?type=active",
    "api/ntwk/wan_info",
    "api/ntwk/wan",
    "api/ntwk/wanstatus",
    "api/ntwk/wan_status",
    "api/system/waninfo",
]


def _extract_ip(obj: Any) -> str:
    """Recursively extract a valid IPv4 address from nested structures."""
    if not obj:
        return ""
    if isinstance(obj, str):
        val = obj.strip()
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val) and val != "0.0.0.0":
            return val
        return ""
    if isinstance(obj, dict):
        # High priority keys first
        for key in [
            "ExternalIPAddress", "ExternalIP", "ExternalIp", "WanIP", "WanIp",
            "IPAddress", "ip_address", "ipv4_address", "wan_ip", "IPv4Address",
            "IpAddress", "external_ip", "ip"
        ]:
            if key in obj:
                res = _extract_ip(obj[key])
                if res:
                    return res
        for v in obj.values():
            res = _extract_ip(v)
            if res:
                return res
    elif isinstance(obj, list):
        for item in obj:
            res = _extract_ip(item)
            if res:
                return res
    return ""


def _extract_version(obj: Any, keys: List[str]) -> str:
    """Recursively extract version strings from nested dicts using key candidates."""
    if not obj:
        return ""
    if isinstance(obj, str):
        return obj.strip()
    if isinstance(obj, dict):
        for key in keys:
            if key in obj:
                val = obj[key]
                if isinstance(val, str) and val.strip():
                    return val.strip()
        for v in obj.values():
            if isinstance(v, dict):
                res = _extract_version(v, keys)
                if res:
                    return res
    return ""


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
        Get router hardware/software information with fallback endpoints and key discovery.
        """
        data = None
        for endpoint in DEVICE_INFO_ENDPOINTS:
            res = await self.get(endpoint)
            if isinstance(res, dict) and res:
                data = res
                logger.debug("Device info endpoint matched: %s", endpoint)
                break

        if not data:
            data = {}

        software = _extract_version(data, [
            "SoftwareVersion", "Software_Version", "ProductSoftwareVersion",
            "sw_version", "version", "SysVersion", "Software"
        ])

        harmony = _extract_version(data, [
            "HarmonyOSVersion", "HarmonyVersion", "harmony_version",
            "OSVersion", "os_version", "HarmonyOS"
        ])

        # Fallback HarmonyOS to software version if not separately specified
        if not harmony and software:
            harmony = software

        hardware = _extract_version(data, [
            "HardwareVersion", "Hardware_Version", "hw_version", "Hardware"
        ])

        serial = _extract_version(data, [
            "SerialNumber", "serial_number", "SN", "sn", "DeviceSN"
        ])

        name = (
            data.get("FriendlyName")
            or data.get("DeviceName")
            or _extract_version(data, ["CustDeviceName", "FriendlyName", "DeviceName"])
            or "Huawei BE3"
        )

        model = (
            data.get("custinfo", {}).get("CustDeviceName")
            if isinstance(data.get("custinfo"), dict)
            else None
        ) or data.get("CustDeviceName") or name

        uptime = (
            data.get("UpTime")
            or data.get("uptime")
            or data.get("Uptime")
            or 0
        )

        logger.debug(
            "Extracted router info: model=%s, software=%s, harmonyos=%s, serial=%s",
            model, software, harmony, serial
        )

        return {
            "name": name,
            "model": model,
            "serial_number": serial,
            "software_version": software,
            "hardware_version": hardware,
            "harmony_os_version": harmony,
            "uptime": uptime,
        }

    async def get_connected_devices(self) -> List[Dict[str, Any]]:
        """
        Get all known/connected devices.
        Tries alternative endpoints if the default one 404s.
        If all direct endpoints 404, extracts devices from topology.
        """
        endpoints_to_try = (
            [self._working_host_info_endpoint] + HOST_INFO_ENDPOINTS
            if self._working_host_info_endpoint
            else HOST_INFO_ENDPOINTS
        )

        raw_devices = []
        for endpoint in endpoints_to_try:
            if not endpoint:
                continue
            data = await self.get(endpoint)
            if data is not None:
                self._working_host_info_endpoint = endpoint
                logger.debug("Connected devices endpoint found: %s", endpoint)
                if isinstance(data, list):
                    raw_devices = data
                    break
                elif isinstance(data, dict):
                    for k in [
                        "HostList", "host_list", "hosts", "devices",
                        "DeviceList", "device_list", "HostInfo", "host_info", "data"
                    ]:
                        if k in data and isinstance(data[k], list):
                            raw_devices = data[k]
                            break
                    if raw_devices:
                        break

        if not raw_devices:
            # Fallback: Extract connected devices from topology tree
            logger.debug("Direct device endpoints 404'd, extracting from topology tree")
            topology = await self.get_device_topology()
            raw_devices = self._extract_devices_from_topology(topology)

        # Deduplicate devices by MAC / IP
        seen_macs = set()
        unique_devices = []
        for d in raw_devices:
            if not isinstance(d, dict):
                continue
            mac = (d.get("MACAddress") or d.get("MacAddress") or d.get("mac") or "").upper().replace(":", "").replace("-", "")
            if mac:
                if mac in seen_macs:
                    continue
                seen_macs.add(mac)
            unique_devices.append(d)

        logger.debug("Found %d total unique devices from API", len(unique_devices))
        return unique_devices

    def _extract_devices_from_topology(self, node: Any) -> List[Dict[str, Any]]:
        """Recursively extract devices from mesh topology JSON."""
        devices = []
        if isinstance(node, list):
            for item in node:
                devices.extend(self._extract_devices_from_topology(item))
        elif isinstance(node, dict):
            # Check if this node itself represents a connected host/device
            mac = (
                node.get("MACAddress")
                or node.get("MacAddress")
                or node.get("mac")
                or node.get("MAC")
                or ""
            )
            ip = (
                node.get("IPAddress")
                or node.get("IpAddress")
                or node.get("ip")
                or node.get("IP")
                or ""
            )

            # Avoid adding the router itself as a client device if marked as Master/Gateway
            role = str(node.get("Role", node.get("DeviceType", ""))).lower()
            if (mac or ip) and "gateway" not in role and "master" not in role:
                devices.append({
                    "MACAddress": mac,
                    "IPAddress": ip,
                    "HostName": node.get("HostName", node.get("DeviceName", node.get("Name", "Unknown"))),
                    "AccessType": node.get("AccessType", node.get("ConnectType", node.get("PortType", node.get("Band", "")))),
                    "UpRate": node.get("UpSpeed", node.get("UpRate", 0)),
                    "DownRate": node.get("DownSpeed", node.get("DownRate", 0)),
                    "IsOnline": True,
                })

            # Check all possible child list keys in topology nodes
            for key in [
                "ConnectedDevices", "connected_devices", "Hosts", "HostList",
                "host_list", "Devices", "DeviceList", "device_list", "Children",
                "children", "SlaveNodes", "slave_nodes", "AssociatedClients", "Clients", "Nodes", "nodes"
            ]:
                children = node.get(key)
                if isinstance(children, list):
                    for dev in children:
                        devices.extend(self._extract_devices_from_topology(dev))
        return devices

    async def get_wan_info(self) -> Dict[str, Any]:
        """
        Get WAN connection status, external IP, and bandwidth.
        """
        detect_data = await self.get(URL_WANDETECT)
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
            if res is not None:
                self._working_wan_info_endpoint = endpoint
                rate_data = res
                logger.debug("WAN info endpoint matched: %s", endpoint)
                break

        external_ip = _extract_ip(detect_data) or _extract_ip(rate_data)

        connected = False
        if isinstance(detect_data, dict):
            connected = detect_data.get("Status") == "Connected" or bool(external_ip)
        elif external_ip:
            connected = True

        uptime = 0
        if isinstance(detect_data, dict):
            uptime = detect_data.get("Uptime", 0)
        if not uptime and isinstance(rate_data, dict):
            uptime = rate_data.get("Uptime", rate_data.get("UpTime", 0))

        upload_rate = 0
        download_rate = 0
        if isinstance(rate_data, dict):
            upload_rate = rate_data.get("UpBandwidth", rate_data.get("UpRate", rate_data.get("UpSpeed", 0)))
            download_rate = rate_data.get("DownBandwidth", rate_data.get("DownRate", rate_data.get("DownSpeed", 0)))

        logger.debug("Extracted WAN info: connected=%s, external_ip=%s", connected, external_ip)

        return {
            "connected": connected,
            "external_ip": external_ip,
            "uptime": uptime,
            "upload_rate": upload_rate,
            "download_rate": download_rate,
        }

    async def get_device_topology(self) -> Any:
        """
        Get mesh network topology.
        """
        data = await self.get(URL_DEVICE_TOPOLOGY)
        return data if data is not None else []
