from graph_builder import build_graph
from attack_simulator import AttackSimulator
import os
import uvicorn
import threading
import webbrowser
import time
from api.server import PORT
from api.server import app
from fastapi import HTTPException

def open_browser():
    # Wait 1.5s for server to start then open browser
    time.sleep(1.5)
    webbrowser.open(f"http://127.0.0.1:{PORT}")

simulator = AttackSimulator(api_key=os.getenv("GROQ_API_KEY"))

if __name__ == "__main__":
    threading.Thread(target=open_browser, daemon=True).start()
    uvicorn.run(
        "api.server:app",
        host="127.0.0.1",
        port=PORT,
        reload=False
    )