"""
Zabbix Sender wrapper for pushing Huawei router metrics.

Uses py-zabbix to send metrics via the Zabbix Trapper protocol (port 10051).
Supports both simple metrics and Low-Level Discovery (LLD) for
automatic item creation in Zabbix.
"""

import json
import logging
import time
from typing import Any, Dict, List

from pyzabbix import ZabbixMetric, ZabbixSender, ZabbixResponse

logger = logging.getLogger(__name__)


def extract_hostname(device: Dict[str, Any], mac: str) -> str:
    """Extract best available name/hostname for a device."""
    for key in ("HostName", "ActualName", "DeviceName", "Name", "UserDeviceName"):
        val = str(device.get(key) or "").strip()
        if val and val.lower() not in ("unknown", "null", "none"):
            return val
    ip = str(device.get("IPAddress") or "").strip()
    if ip:
        return f"Device ({ip})"
    return f"Device-{mac}"


def extract_access_type(device: Dict[str, Any]) -> str:
    """Extract connection band/type (2.4 GHz, 5 GHz, Ethernet, etc.)."""
    raw = ""
    for key in (
        "AccessType",
        "accessType",
        "AccessMode",
        "ConnectType",
        "PortType",
        "Access",
        "Band",
        "Radio",
        "InterfaceType",
        "PortName",
        "WirelessBand",
    ):
        val = str(device.get(key) or "").strip()
        if val:
            raw = val
            break

    val_lower = raw.lower()
    if "2.4" in val_lower or "2g" in val_lower:
        return "2.4 GHz"
    elif "5" in val_lower:
        return "5 GHz"
    elif "6" in val_lower:
        return "6 GHz"
    elif "eth" in val_lower or "cable" in val_lower or "wire" in val_lower or "lan" in val_lower:
        return "Ethernet"
    elif raw:
        return raw
    return "Unknown"


def _is_device_online(d: Dict[str, Any]) -> bool:
    """Check if a device dictionary represents an active/online device."""
    for key in ["Active", "IsOnline", "is_online", "online", "OnlineStatus", "Status", "ConnectStatus"]:
        if key in d:
            val = d[key]
            if val is True or val == 1 or val == "1" or str(val).lower() in ("true", "online", "connected"):
                return True
            if val is False or val == 0 or val == "0" or str(val).lower() in ("false", "offline", "disconnected"):
                return False

    # Default to online if MAC or IP is present without explicit offline indicator
    if d.get("IPAddress") or d.get("MACAddress") or d.get("MacAddress") or d.get("mac"):
        return True
    return False


class ZabbixPusher:
    """
    Pushes scraped router data to Zabbix via the Trapper protocol.

    All metrics are batched per scrape cycle and sent in a single
    ZabbixSender.send() call for efficiency. Includes a device TTL cache
    to debounce transient Wi-Fi sleep and API drops.
    """

    def __init__(self, server: str, port: int, host_name: str, device_ttl: int = 120):
        """
        Args:
            server: Zabbix server IP or hostname.
            port: Zabbix trapper port (default 10051).
            host_name: The technical host name in Zabbix (must match exactly).
            device_ttl: Seconds to keep an active device in cache during transient sleep/drops (default 120s).
        """
        self._server = server
        self._port = port
        self._host = host_name
        self._sender = ZabbixSender(zabbix_server=server, zabbix_port=port)
        self._device_cache: Dict[str, Dict[str, Any]] = {}
        self._device_ttl = device_ttl

    def get_active_devices(self, raw_devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Return stabilized active devices list using TTL state caching.
        Smooths out 1-2 scrape cycle Wi-Fi power saving sleep or API drops.
        """
        now = time.time()

        # Update cache with currently active devices reported by API
        current_active = [d for d in raw_devices if _is_device_online(d)]
        for dev in current_active:
            mac = (dev.get("MACAddress") or dev.get("MacAddress") or dev.get("mac") or "").upper().replace(":", "").replace("-", "")
            key = mac or str(dev.get("IPAddress") or dev.get("HostName") or "")
            if key:
                self._device_cache[key] = {
                    "data": dev,
                    "last_seen": now
                }

        # Expire devices not seen for longer than device_ttl
        expired_keys = [k for k, info in self._device_cache.items() if now - info["last_seen"] > self._device_ttl]
        for k in expired_keys:
            del self._device_cache[k]

        return [info["data"] for info in self._device_cache.values()]

    def push_all(
        self,
        router_info: Dict[str, Any],
        wan_info: Dict[str, Any],
        devices: List[Dict[str, Any]],
    ) -> bool:
        """
        Push all scraped data to Zabbix in a single batch.

        Args:
            router_info: Router hardware/software info dict.
            wan_info: WAN connection status dict.
            devices: List of connected device dicts.

        Returns:
            True if all metrics were accepted by Zabbix.
        """
        metrics: List[ZabbixMetric] = []

        # ── Router Info ───────────────────────────────────────────────
        metrics.extend([
            self._metric("huawei.router.name", router_info.get("name", "")),
            self._metric("huawei.router.model", router_info.get("model", "")),
            self._metric("huawei.router.firmware", router_info.get("software_version", "")),
            self._metric("huawei.router.hardware", router_info.get("hardware_version", "")),
            self._metric("huawei.router.harmonyos", router_info.get("harmony_os_version", "")),
            self._metric("huawei.router.serial", router_info.get("serial_number", "")),
            self._metric("huawei.router.uptime", router_info.get("uptime", 0)),
        ])

        # ── WAN Info ──────────────────────────────────────────────────
        metrics.extend([
            self._metric("huawei.wan.status", 1 if wan_info.get("connected") else 0),
            self._metric("huawei.wan.external_ip", wan_info.get("external_ip", "")),
            self._metric("huawei.wan.uptime", wan_info.get("uptime", 0)),
            self._metric("huawei.wan.upload_rate", wan_info.get("upload_rate", 0)),
            self._metric("huawei.wan.download_rate", wan_info.get("download_rate", 0)),
        ])

        # ── Device Count (Stabilized via TTL Cache) ───────────────────
        online_devices = self.get_active_devices(devices)
        metrics.append(self._metric("huawei.devices.count", len(online_devices)))

        # ── LLD Discovery for Devices ─────────────────────────────────
        discovery_data = self._build_lld_discovery(online_devices)
        metrics.append(self._metric("huawei.devices.discovery", json.dumps(discovery_data)))

        # ── Per-Device Metrics ────────────────────────────────────────
        for device in online_devices:
            mac = device.get("MACAddress", "").upper().replace(":", "").replace("-", "")
            if not mac:
                continue
            hostname = extract_hostname(device, mac)
            access_type = extract_access_type(device)

            metrics.extend([
                self._metric(f"huawei.device.ip[{mac}]", device.get("IPAddress", "")),
                self._metric(f"huawei.device.hostname[{mac}]", hostname),
                self._metric(f"huawei.device.access_type[{mac}]", access_type),
                self._metric(f"huawei.device.upload[{mac}]", device.get("UpRate", device.get("UpSpeed", 0))),
                self._metric(f"huawei.device.download[{mac}]", device.get("DownRate", device.get("DownSpeed", 0))),
            ])

        # ── Send All ──────────────────────────────────────────────────
        return self._send_batch(metrics)

    def _metric(self, key: str, value: Any) -> ZabbixMetric:
        """Create a ZabbixMetric for this host."""
        return ZabbixMetric(self._host, key, str(value))

    def _build_lld_discovery(self, devices: List[Dict[str, Any]]) -> Dict:
        """
        Build Zabbix Low-Level Discovery JSON payload.

        This tells Zabbix which devices exist so it can auto-create
        per-device items from the template prototypes.
        """
        lld_data = []
        for device in devices:
            mac = device.get("MACAddress", "").upper().replace(":", "").replace("-", "")
            if not mac:
                continue
            hostname = extract_hostname(device, mac)
            access_type = extract_access_type(device)
            lld_data.append({
                "{#MAC}": mac,
                "{#HOSTNAME}": hostname,
                "{#IP}": device.get("IPAddress", ""),
                "{#ACCESSTYPE}": access_type,
            })

        return {"data": lld_data}

    def _send_batch(self, metrics: List[ZabbixMetric]) -> bool:
        """Send a batch of metrics to Zabbix and log the result."""
        if not metrics:
            logger.warning("No metrics to send")
            return True

        try:
            result: ZabbixResponse = self._sender.send(metrics)
            processed = getattr(result, "processed", 0)
            failed = getattr(result, "failed", 0)
            total = getattr(result, "total", len(metrics))

            if failed > 0:
                logger.warning(
                    "⚠️  Zabbix: %d/%d metrics failed (processed: %d)",
                    failed, total, processed,
                )
            else:
                logger.info(
                    "📊 Zabbix: %d metrics sent successfully", processed
                )

            return failed == 0

        except Exception as e:
            logger.error("❌ Failed to send metrics to Zabbix: %s", e)
            return False
