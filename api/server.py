from graph_builder import build_graph
from attack_simulator import AttackSimulator, ATTACK_SCENARIOS
import asyncio
import json
import os
import socket
import ipaddress
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

from core.pipeline import run_full_scan, run_deep_scan
from core.storage.database import (
    init_db,
    get_live_devices,
    get_device_history,
    get_unread_alerts,
    mark_alerts_read
)

load_dotenv()

SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", 120))
clients: list[WebSocket] = []
simulator = AttackSimulator(api_key=os.getenv("GROQ_API_KEY", ""))


def get_local_subnet() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()
    network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
    return str(network)


def get_free_port(preferred: int = 8000) -> int:
    for port in range(preferred, preferred + 10):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


PORT = get_free_port(8000)
print(f"[NetGuard] Running on port: {PORT}")


async def broadcast(data: dict):
    message = json.dumps(data)
    for client in clients.copy():
        try:
            await client.send_text(message)
        except Exception:
            clients.remove(client)


async def scan_loop():
    """Periodic ARP discovery — finds devices, no port scanning."""
    while True:
        try:
            subnet = get_local_subnet()
            print(f"[NetGuard] Discovery scan: {subnet}")
            await run_full_scan(subnet, broadcast_fn=broadcast)
        except Exception as e:
            print(f"[NetGuard] Scan error: {e}")
        await asyncio.sleep(SCAN_INTERVAL)


async def delayed_start():
    await asyncio.sleep(2)
    await scan_loop()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    asyncio.create_task(delayed_start())
    yield


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    clients.append(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        if ws in clients:
            clients.remove(ws)


@app.get("/api/devices")
def get_devices():
    subnet = get_local_subnet()
    return get_live_devices(subnet)


@app.get("/api/devices/{ip}/history")
def device_history(ip: str):
    return get_device_history(ip)


@app.get("/api/alerts")
def alerts():
    return get_unread_alerts()


@app.post("/api/alerts/read")
def read_alerts():
    mark_alerts_read()
    return {"status": "ok"}


@app.post("/api/scan")
async def trigger_scan():
    """Trigger ARP discovery scan — finds devices on the network."""
    subnet = get_local_subnet()
    asyncio.create_task(run_full_scan(subnet, broadcast_fn=broadcast))
    return {"status": "discovery scan started", "subnet": subnet}


@app.post("/api/devices/{ip}/deep-scan")
async def trigger_deep_scan(ip: str):
    """
    Trigger a full deep scan for a single device:
    TCP port scan → version/OS detection → Shodan → AI risk analysis.
    Result is broadcast via WebSocket as it completes.
    """
    asyncio.create_task(run_deep_scan(ip, broadcast_fn=broadcast))
    return {"status": "deep scan started", "ip": ip}


@app.post("/api/scan/deep-all")
async def trigger_deep_scan_all():
    """
    Deep scan all devices that have been discovered but not yet fully scanned.
    Scans run sequentially (one at a time) to avoid nmap collisions.
    """
    subnet  = get_local_subnet()
    devices = get_live_devices(subnet)
    # Only scan devices with no score yet
    pending = [d for d in devices if d.get("final_score") is None]

    async def scan_all():
        for device in pending:
            try:
                await run_deep_scan(device["ip"], broadcast_fn=broadcast)
            except Exception as e:
                print(f"[NetGuard] Deep scan failed for {device['ip']}: {e}")

    asyncio.create_task(scan_all())
    return {"status": "bulk deep scan started", "pending": len(pending)}


@app.get("/api/status")
def status():
    subnet = get_local_subnet()
    return {"status": "ok", "subnet": subnet, "port": PORT}


class ChatRequest(BaseModel):
    ip:             str
    ports:          list
    cves:           list
    shodan_summary: str
    os_info:        str
    question:       str


@app.post("/api/chat")
async def chat(req: ChatRequest):
    from core.risk.ai_engine import ai_chat
    loop   = asyncio.get_event_loop()
    answer = await loop.run_in_executor(
        None, ai_chat,
        req.ip, req.ports, req.cves,
        req.shodan_summary, req.os_info, req.question
    )
    return {"answer": answer}


@app.get("/api/topology")
def get_topology():
    devices = get_live_devices(get_local_subnet())
    if not devices:
        return {"nodes": [], "edges": []}
    for d in devices:
        if isinstance(d.get("ports"), str):
            try:
                d["ports"] = json.loads(d["ports"])
            except Exception:
                d["ports"] = []
    return build_graph(devices)


@app.post("/api/simulate/{attack_type}")
async def simulate_attack(attack_type: str):
    valid = ["wannacry", "mirai", "mitm", "bruteforce", "ransomware"]
    if attack_type not in valid:
        return {"error": f"Invalid attack type. Choose from: {valid}"}
    devices = get_live_devices(get_local_subnet())
    if not devices:
        return {"error": "No devices scanned yet — run a scan first"}
    for d in devices:
        if isinstance(d.get("ports"), str):
            try:
                d["ports"] = json.loads(d["ports"])
            except Exception:
                d["ports"] = []
    result = await simulator.simulate(devices, attack_type)
    return result


class CopilotRequest(BaseModel):
    question: str
    history:  list = []   # [{role, content}, ...] for multi-turn


@app.post("/api/copilot")
async def copilot(req: CopilotRequest):
    """
    Network-wide AI copilot. Gets full device context automatically,
    so the frontend only needs to send the user question + chat history.
    """
    from core.risk.ai_engine import network_copilot
    devices = get_live_devices(get_local_subnet())
    loop    = asyncio.get_event_loop()
    answer  = await loop.run_in_executor(
        None, network_copilot, devices, req.question, req.history or []
    )
    return {"answer": answer}


app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
