import asyncio
from core.scanner.arp_scan import arp_scan
from core.scanner.port_scan import deep_scan_device
from core.profiler.firmware_checker import estimate_firmware_age
from core.enrichment.shodan_lookup import shodan_lookup
from core.risk.rule_engine import rule_score
from core.risk.ai_engine import ai_score
from core.risk.score_blender import blend_scores
from core.storage.database import (
    upsert_device, save_scan, save_alert,
    start_scan_session, end_scan_session, tag_device_to_session,
    get_device_by_ip
)

_scan_lock      = asyncio.Lock()
_deep_scan_lock = asyncio.Lock()   # one deep scan at a time — avoids nmap collisions


# ── Shared analysis logic ─────────────────────────────────────────────────────

async def _analyze_and_broadcast(device: dict, port_data: dict, broadcast_fn=None) -> dict:
    """
    Enrichment + AI scoring for a device that has already been port-scanned.
    Saves results to DB and broadcasts via WebSocket.
    Called by both the auto-scan path and the per-device deep scan path.
    """
    ip   = device["ip"]
    loop = asyncio.get_running_loop()

    print(f"[NetGuard] Analyzing {ip}...")

    banners = [p.get("banner", "") for p in port_data["ports"]]

    # Shodan + firmware run concurrently
    shodan_data, firmware = await asyncio.gather(
        loop.run_in_executor(None, shodan_lookup, ip),
        loop.run_in_executor(None, estimate_firmware_age, banners)
    )

    profile = {
        "ip":             ip,
        "os":             port_data["os"],
        "ports":          port_data["ports"],
        "firmware":       firmware,
        "cves":           shodan_data["cves"],
        "shodan_summary": shodan_data["summary"],
    }

    ai_result = await loop.run_in_executor(None, ai_score, profile)
    rules     = rule_score(
        ai_result.get("dangerous_ports", []),
        shodan_data["cves"],
        firmware
    )
    result = blend_scores(ai_result, rules)

    has_real_data = bool(port_data["ports"] or shodan_data["cves"] or shodan_data["summary"])
    if not has_real_data:
        result["final_score"] = None
        result["severity"]    = "unknown"
        result["explanation"] = "No dangerous open ports found on this device."
        result["remediation"] = "Device appears clean. Re-scan periodically to stay updated."

    result["ip"]              = ip
    result["mac"]             = device.get("mac",      "")
    result["hostname"]        = device.get("hostname", "")
    result["vendor"]          = device.get("vendor",   {})
    result["os"]              = port_data["os"]
    result["ports"]           = port_data["ports"]
    result["port_analysis"]   = ai_result.get("port_analysis",   [])
    result["dangerous_ports"] = ai_result.get("dangerous_ports", [])
    result["cves"]            = shodan_data["cves"]
    result["shodan_tags"]     = shodan_data["tags"]
    result["shodan_summary"]  = shodan_data["summary"]

    # Persist
    device["os"] = port_data["os"]
    upsert_device(device)
    save_scan(ip, result)

    if result["severity"] in ("critical", "high"):
        save_alert(ip, result["severity"], result["explanation"])

    print(f"[NetGuard] {ip} analysis done — score:{result['final_score']} "
          f"severity:{result['severity']}")

    if broadcast_fn:
        await broadcast_fn({**result,
                            "event": "deep_scan_complete",
                            "ports":           result["ports"],
                            "port_analysis":   result["port_analysis"],
                            "dangerous_ports": result["dangerous_ports"],
                            "cves":            result["cves"],
                            "shodan_tags":     result["shodan_tags"]})

    return result


# ── ARP discovery scan ────────────────────────────────────────────────────────

async def run_full_scan(subnet: str, broadcast_fn=None) -> list:
    """
    Phase 1 only: ARP discovery.
    Finds all live devices on the subnet and saves them to DB.
    No port scanning — users trigger deep scan per device.
    """
    if _scan_lock.locked():
        print("[NetGuard] Discovery scan already running, skipping.")
        return []

    async with _scan_lock:
        loop = asyncio.get_running_loop()

        if broadcast_fn:
            await broadcast_fn({"event": "scan_started", "subnet": subnet})

        devices = await loop.run_in_executor(None, arp_scan, subnet)

        if not devices:
            if broadcast_fn:
                await broadcast_fn({"event": "scan_complete", "subnet": subnet, "found": 0})
            return []

        # Persist discovered devices and create a session so get_live_devices works
        session_id = start_scan_session(subnet)
        for device in devices:
            upsert_device(device)
            tag_device_to_session(device["ip"], session_id)
        end_scan_session(session_id)

        if broadcast_fn:
            await broadcast_fn({
                "event":  "arp_complete",
                "subnet": subnet,
                "found":  len(devices),
                "ips":    [d["ip"] for d in devices]
            })
            await broadcast_fn({
                "event": "scan_complete",
                "subnet": subnet,
                "found": len(devices)
            })

        return devices


# ── Per-device deep scan ──────────────────────────────────────────────────────

async def run_deep_scan(ip: str, broadcast_fn=None) -> dict:
    """
    Deep scan a single device:
      1. TCP connect port scan on dangerous ports
      2. Version + OS detection
      3. Shodan enrichment + AI risk analysis
    Serialised via _deep_scan_lock to prevent nmap collisions.
    """
    async with _deep_scan_lock:
        loop = asyncio.get_running_loop()

        if broadcast_fn:
            await broadcast_fn({"event": "deep_scan_started", "ip": ip})

        # Look up device metadata from DB (mac, hostname, vendor)
        device = await loop.run_in_executor(None, get_device_by_ip, ip)
        if not device:
            device = {"ip": ip, "mac": "", "hostname": "unknown", "vendor": {}}

        # TCP connect scan — blocking, run in executor
        port_data = await loop.run_in_executor(None, deep_scan_device, ip)

        result = await _analyze_and_broadcast(device, port_data, broadcast_fn)
        return result
