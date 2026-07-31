#!/usr/bin/env python3
"""
Huawei WiFi BE3 Router Scraper → Zabbix

Main entry point. Runs an async polling loop that:
  1. Authenticates with the Huawei router via SCRAM
  2. Scrapes router info, WAN status, and connected devices
  3. Pushes all metrics to Zabbix via the Trapper protocol

Configuration is done entirely via environment variables (Docker-friendly).
"""

import asyncio
import logging
import os
import signal
import sys
from datetime import datetime, timezone

from huawei_client import HuaweiClient, AuthenticationError, ApiCallError
from zabbix_push import ZabbixPusher

# ── Configuration from Environment ────────────────────────────────────

ROUTER_HOST = os.getenv("ROUTER_HOST", "192.168.3.1")
ROUTER_PORT = int(os.getenv("ROUTER_PORT", "80"))
# NOTE: Huawei WiFi BE3 has no username field in the web UI.
# The firmware always uses 'admin' internally for the SCRAM auth.
ROUTER_USER = "admin"
ROUTER_PASSWORD = os.getenv("ROUTER_PASSWORD", "")
USE_SSL = os.getenv("USE_SSL", "false").lower() in ("true", "1", "yes")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "30"))

ZABBIX_SERVER = os.getenv("ZABBIX_SERVER", "127.0.0.1")
ZABBIX_PORT = int(os.getenv("ZABBIX_PORT", "10051"))
ZABBIX_HOST = os.getenv("ZABBIX_HOST", "HuaweiBE3")

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# ── Logging Setup ─────────────────────────────────────────────────────

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s │ %(levelname)-7s │ %(name)s │ %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)

logger = logging.getLogger("scraper")

# Suppress noisy aiohttp logs
logging.getLogger("aiohttp").setLevel(logging.WARNING)
logging.getLogger("charset_normalizer").setLevel(logging.WARNING)


# ── Main Loop ─────────────────────────────────────────────────────────

async def scrape_cycle(client: HuaweiClient, pusher: ZabbixPusher) -> bool:
    """
    Execute a single scrape cycle.

    Returns True if the cycle completed successfully.
    """
    try:
        # Scrape all data concurrently
        router_info, wan_info, devices = await asyncio.gather(
            client.get_router_info(),
            client.get_wan_info(),
            client.get_connected_devices(),
        )

        # Stabilized active devices count
        online = pusher.get_active_devices(devices)

        logger.info(
            "📡 Scraped: router=%s | WAN=%s (%s) | ↑%.1f KB/s ↓%.1f KB/s | %d devices online",
            router_info.get("model", "?"),
            "UP" if wan_info.get("connected") else "DOWN",
            wan_info.get("external_ip", "?"),
            wan_info.get("upload_rate", 0) / 1024,
            wan_info.get("download_rate", 0) / 1024,
            len(online),
        )

        # Log connected devices
        for device in online:
            hostname = device.get("HostName", device.get("ActualName", "Unknown"))
            ip = device.get("IPAddress", "?")
            mac = device.get("MACAddress", "?")
            logger.debug("  └─ %s (%s) [%s]", hostname, ip, mac)

        # Push to Zabbix
        success = pusher.push_all(router_info, wan_info, devices)
        return success

    except AuthenticationError as e:
        logger.error("🔒 Authentication failed: %s (reason: %s)", e, e.reason)
        # Force re-authentication on next cycle
        client._authenticated = False
        return False

    except ApiCallError as e:
        logger.error("🌐 API error: %s (code: %s, category: %s)", e, e.code, e.category)
        if e.category == "Too_Many_user":
            logger.warning("⏳ Router rejected auth due to active session limit (Too_Many_user). Sleeping 60s for session timeout...")
            client._authenticated = False
            await asyncio.sleep(60)
        elif e.category in ("csrf_error", "unauthorized"):
            client._authenticated = False
        return False

    except Exception as e:
        logger.error("💥 Unexpected error during scrape: %s", e, exc_info=True)
        return False


async def main():
    """Main entry point — runs the polling loop."""
    # ── Validate config ───────────────────────────────────────────
    if not ROUTER_PASSWORD:
        logger.error("❌ ROUTER_PASSWORD environment variable is required")
        sys.exit(1)

    logger.info("=" * 60)
    logger.info("🚀 Huawei WiFi BE3 Scraper starting")
    logger.info("=" * 60)
    logger.info("  Router:   %s://%s:%d (user: %s)",
                "https" if USE_SSL else "http", ROUTER_HOST, ROUTER_PORT, ROUTER_USER)
    logger.info("  Zabbix:   %s:%d (host: %s)", ZABBIX_SERVER, ZABBIX_PORT, ZABBIX_HOST)
    logger.info("  Interval: %ds", POLL_INTERVAL)
    logger.info("=" * 60)

    # ── Set up Zabbix pusher ──────────────────────────────────────
    pusher = ZabbixPusher(
        server=ZABBIX_SERVER,
        port=ZABBIX_PORT,
        host_name=ZABBIX_HOST,
    )

    # ── Graceful shutdown ─────────────────────────────────────────
    shutdown_event = asyncio.Event()

    def _signal_handler():
        logger.info("🛑 Shutdown signal received")
        shutdown_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass

    # ── Polling loop ──────────────────────────────────────────────
    consecutive_failures = 0
    max_failures = 10

    async with HuaweiClient(
        host=ROUTER_HOST,
        port=ROUTER_PORT,
        user=ROUTER_USER,
        password=ROUTER_PASSWORD,
        use_ssl=USE_SSL,
    ) as client:
        while not shutdown_event.is_set():
            cycle_start = datetime.now(timezone.utc)

            success = await scrape_cycle(client, pusher)

            if success:
                consecutive_failures = 0
            else:
                consecutive_failures += 1
                if consecutive_failures >= max_failures:
                    logger.error(
                        "❌ %d consecutive failures, forcing full reconnection",
                        consecutive_failures,
                    )
                    await client.disconnect()
                    await client._create_session()
                    consecutive_failures = 0

            # Wait for next cycle (or shutdown)
            elapsed = (datetime.now(timezone.utc) - cycle_start).total_seconds()
            wait_time = max(0, POLL_INTERVAL - elapsed)

            try:
                await asyncio.wait_for(shutdown_event.wait(), timeout=wait_time)
                break  # Shutdown was triggered during wait
            except asyncio.TimeoutError:
                pass  # Normal timeout, continue to next cycle

    logger.info("👋 Scraper stopped cleanly")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("👋 Interrupted by user")
