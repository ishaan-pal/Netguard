import os
import sys
import nmap

if getattr(sys, "frozen", False):
    NMAP_PATH = os.path.join(sys._MEIPASS, "nmap", "nmap.exe")
else:
    NMAP_PATH = "nmap"

# ── Scan flags ────────────────────────────────────────────────────────────────
# TCP connect (-sT) instead of SYN (-sS):
#   • SYN scan requires root/Administrator — TCP connect does not
#   • On a local LAN both are equally fast; SYN's stealth advantage is irrelevant
#   • TCP connect is reliable across all OS and permission levels
SCAN_FLAGS = (
    "-sT "              # TCP connect — no root required
    "-T4 "              # Aggressive timing (safe on LAN)
    "--max-retries 2 "  # 2 retries is enough on local network
    "--host-timeout 4m "
    "--min-parallelism 50 "
    "--max-parallelism 100 "
)

# ── Dangerous ports only ──────────────────────────────────────────────────────
DANGEROUS_PORTS = [
    # Remote access
    21, 22, 23, 3389, 5900, 5901, 5902, 4444,
    # Windows / SMB
    135, 137, 138, 139, 445,
    # Network infra
    53, 161, 389, 636, 514, 500, 4500,
    # Web / APIs
    80, 443, 8080, 8443, 8008, 3000, 5000, 9000, 8888,
    # Email
    25, 110, 143, 587, 993, 995,
    # Databases
    1433, 1521, 3306, 5432, 6379, 9200, 9300, 27017, 5984, 7474,
    # IoT / Industrial
    1883, 8883, 502, 44818, 47808,
    # Container / orchestration
    2375, 2376, 6443, 10250, 9090,
    # Monitoring / dashboards
    5601, 9100,
    # Media / file sharing
    554, 8554, 111, 2049,
]

DANGEROUS_PORT_STR = ",".join(str(p) for p in sorted(set(DANGEROUS_PORTS)))


def deep_scan_device(ip: str) -> dict:
    """
    Deep scan a single device:
      - TCP connect scan on dangerous ports (no root required)
      - Version detection on open ports
      - OS fingerprinting
    All in one nmap call — fast because we only hit ~70 targeted ports.
    """
    nm     = nmap.PortScanner(nmap_search_path=(NMAP_PATH,))
    result = {"ip": ip, "os": "unknown", "ports": []}

    scan_args = (
        f"{SCAN_FLAGS}"
        f"-sV "                   # version detection (only on open ports — fast)
        f"-O "                    # OS fingerprinting
        f"-Pn "                   # skip host discovery ping (scan unconditionally)
        f"--open "                # only show open ports
        f"-p {DANGEROUS_PORT_STR} "
        f"--version-intensity 5 " # balanced — not too noisy, not too shallow
    )

    print(f"[NetGuard] Deep scanning {ip} — TCP connect on {len(DANGEROUS_PORTS)} dangerous ports...")

    try:
        nm.scan(hosts=ip, arguments=scan_args)
    except Exception as e:
        print(f"[NetGuard] Deep scan failed for {ip}: {e}")
        return result

    if ip not in nm.all_hosts():
        # nmap may return a slightly different key; try to find any host
        all_hosts = nm.all_hosts()
        if not all_hosts:
            print(f"[NetGuard] {ip} returned no results from deep scan")
            return result
        ip = all_hosts[0]   # use whatever nmap found

    host = nm[ip]

    if host.get("osmatch"):
        result["os"] = host["osmatch"][0]["name"]

    for proto in host.all_protocols():
        for port in host[proto].keys():
            info = host[proto][port]
            if info["state"] == "open":
                result["ports"].append({
                    "port":    port,
                    "proto":   proto,
                    "state":   info["state"],
                    "service": info["name"],
                    "version": info.get("version", ""),
                    "product": info.get("product", ""),
                    "banner":  info.get("extrainfo", ""),
                })

    result["ports"].sort(key=lambda p: p["port"])
    print(f"[NetGuard] {ip} deep scan done → OS: {result['os']}, "
          f"{len(result['ports'])} dangerous open ports")
    return result
