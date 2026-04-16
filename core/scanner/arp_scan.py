import os
import sys
import nmap

if getattr(sys, "frozen", False):
    NMAP_PATH = os.path.join(sys._MEIPASS, "nmap", "nmap.exe")
else:
    NMAP_PATH = "nmap"

# ── ARP scan arguments ─────────────────────────────────────────────────
#
# -sn               Ping scan only — no port scanning, just finds live hosts
# -T4               Aggressive but WiFi-safe timing
# --max-retries 1   ARP is local so one retry is enough — no need to wait more
# --host-timeout 3s Skip unresponsive IPs after 3 seconds each
#
ARP_ARGS = "-sn -T4 --max-retries 1 --host-timeout 3s"


def arp_scan(subnet: str) -> list[dict]:
    """
    Fast discovery scan — finds all live devices on subnet.
    Should complete in 5-15 seconds on a typical home network.
    """
    nm = nmap.PortScanner(nmap_search_path=(NMAP_PATH,))

    try:
        nm.scan(hosts=subnet, arguments=ARP_ARGS)
    except Exception as e:
        print(f"[NetGuard] ARP scan failed: {e}")
        return []

    devices = []
    for host in nm.all_hosts():
        devices.append({
            "ip":       host,
            "mac":      nm[host]["addresses"].get("mac", "unknown"),
            "hostname": nm[host].hostname() or "unknown",
            "vendor":   nm[host].get("vendor", {})
        })

    print(f"[NetGuard] ARP scan found {len(devices)} devices on {subnet}")
    return devices