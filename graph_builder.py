import networkx as nx
from typing import Dict, List

RISK_COLORS = {
    "critical": "#FF1744",
    "high":     "#FF6D00",
    "medium":   "#FFD600",
    "low":      "#00E676"
}

def build_graph(devices: List[Dict]) -> Dict:
    G = nx.Graph()
    router = _find_router(devices)

    for d in devices:
        G.add_node(d["ip"], **{
            "ip":         d["ip"],
            "label":      d.get("hostname") or d.get("ip"),
            "risk_score": d.get("final_score", 0),
            "risk_level": d.get("severity", "low"),
            "open_ports": [p["port"] for p in d.get("ports", [])],
            "os":         d.get("os", "unknown"),
            "color":      RISK_COLORS.get(d.get("severity", "low"), "#00E676"),
            "is_router":  d["ip"] == router,
        })

    for d in devices:
        if d["ip"] != router and router:
            G.add_edge(router, d["ip"],
                       weight=d.get("final_score", 0),
                       connection_type="wifi")

    _add_lateral_edges(G, devices)
    return _graph_to_json(G)

def _find_router(devices):
    for d in devices:
        last = int(d["ip"].split(".")[-1])
        if last in (1, 254):
            return d["ip"]
    return devices[0]["ip"] if devices else ""

def _add_lateral_edges(G, devices):
    windows = [d["ip"] for d in devices
               if any(p["port"] in [445, 139] for p in d.get("ports", []))]
    for i in range(len(windows)):
        for j in range(i+1, len(windows)):
            G.add_edge(windows[i], windows[j],
                       connection_type="smb_lateral", weight=50)

def _graph_to_json(G):
    nodes = []
    for nid, a in G.nodes(data=True):
        nodes.append({
            "id":         nid,
            "label":      a.get("label", nid),
            "risk_score": a.get("risk_score", 0),
            "risk_level": a.get("risk_level", "low"),
            "open_ports": a.get("open_ports", []),
            "os":         a.get("os", "unknown"),
            "color":      a.get("color", "#00E676"),
            "is_router":  a.get("is_router", False),
            "size":       max(20, a.get("risk_score", 0) / 2),
        })
    edges = []
    for src, dst, a in G.edges(data=True):
        edges.append({
            "source":          src,
            "target":          dst,
            "weight":          a.get("weight", 10),
            "connection_type": a.get("connection_type", "normal"),
        })
    return {"nodes": nodes, "edges": edges}