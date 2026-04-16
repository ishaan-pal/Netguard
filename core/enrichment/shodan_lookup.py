import requests


def shodan_lookup(ip: str) -> dict:
    """
    Query Shodan InternetDB for everything it knows about this IP.

    Returns:
    - cves      : known CVEs linked to this IP/device
    - tags      : device classification e.g. ['camera', 'iot', 'vulnerable']
    - hostnames : reverse DNS hostnames — helps identify device type
    - ports     : ports Shodan has seen open on this IP historically
    - summary   : human readable string built from all of the above,
                  passed directly to the AI so it has full Shodan context

    This is the primary source of external threat intelligence.
    The AI uses this alongside nmap data to make risk decisions.
    """
    empty = {
        "cves":      [],
        "tags":      [],
        "hostnames": [],
        "ports":     [],
        "summary":   "No Shodan data available for this IP."
    }

    try:
        res = requests.get(
            f"https://internetdb.shodan.io/{ip}",
            timeout=5
        )

        if res.status_code == 404:
            return empty

        if res.status_code != 200:
            return empty

        data = res.json()

        cves      = data.get("vulns",     [])
        tags      = data.get("tags",      [])
        hostnames = data.get("hostnames", [])
        ports     = data.get("ports",     [])

        # Build a rich summary for the AI prompt
        parts = []
        if tags:
            parts.append(f"Device identified as: {', '.join(tags)}")
        if hostnames:
            parts.append(f"Hostnames: {', '.join(hostnames)}")
        if ports:
            parts.append(f"Shodan has seen these ports open: {', '.join(map(str, ports))}")
        if cves:
            parts.append(f"Known CVEs on this device: {', '.join(cves)}")
        else:
            parts.append("No known CVEs found in Shodan.")

        return {
            "cves":      cves,
            "tags":      tags,
            "hostnames": hostnames,
            "ports":     ports,
            "summary":   " | ".join(parts) if parts else "No significant Shodan data."
        }

    except Exception:
        return empty