import os
import json
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))
MODEL  = os.getenv("GROQ_MODEL")

FALLBACK = {
    "score":           0,
    "severity":        "low",
    "explanation":     "AI analysis unavailable. Score reflects rule-based checks only.",
    "remediation":     "Check open ports manually and update device firmware.",
    "dangerous_ports": [],
    "port_analysis":   []
}


def ai_score(profile: dict) -> dict:
    """
    AI agent — sole decision maker for risk assessment.
    Receives raw nmap + Shodan data, returns structured risk analysis.
    """
    port_lines = []
    for p in profile["ports"]:
        line = f"  Port {p['port']}/{p.get('proto','tcp')} — service:{p['service']}"
        if p.get("product"): line += f" product:{p['product']}"
        if p.get("version"): line += f" version:{p['version']}"
        if p.get("banner"):  line += f" info:{p['banner']}"
        port_lines.append(line)

    ports_text = "\n".join(port_lines) if port_lines else "  No open ports found"

    prompt = f"""
You are an expert network security analyst reviewing a device scan result.
Assess the real risk of this device to its owner's home or office network.

--- DEVICE PROFILE ---
IP Address : {profile['ip']}
OS         : {profile['os']}
Firmware   : {profile['firmware']}

--- NMAP SCAN RESULTS ---
{ports_text}

--- SHODAN INTELLIGENCE ---
{profile['shodan_summary']}

--- KNOWN CVEs ---
{', '.join(profile['cves']) if profile['cves'] else 'None found'}

--- INSTRUCTIONS ---
1. Analyze ALL ports in context of the device type
2. Do NOT rely on port numbers alone — explain the real risk
3. Consider combination of factors together

Respond with ONLY this JSON — no markdown, no extra text:
{{
  "score": <integer 0-100>,
  "severity": "<critical|high|medium|low>",
  "explanation": "<2-3 plain English sentences>",
  "remediation": "<one specific action to take right now>",
  "dangerous_ports": [
    {{
      "port": <number>,
      "service": "<name>",
      "risk": "<critical|high|medium|low>",
      "reason": "<why this port is risky on THIS specific device>"
    }}
  ],
  "port_analysis": [
    {{
      "port": <number>,
      "service": "<name>",
      "risk": "<critical|high|medium|low>",
      "reason": "<brief context-aware explanation>"
    }}
  ]
}}
"""

    try:
        res = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1000,
            temperature=0.1
        )
        content = res.choices[0].message.content.strip()
        content = content.replace("```json", "").replace("```", "").strip()
        return json.loads(content)

    except Exception as e:
        print(f"[NetGuard] AI scoring failed for {profile['ip']}: {e}")
        return FALLBACK


def ai_chat(ip: str, ports: list, cves: list, shodan_summary: str,
            os_info: str, question: str) -> str:
    """
    AI assistant for the device detail panel.
    Answers plain English questions about a specific device's security.
    Explains ports, risks and how to close them.
    """
    port_lines = [
        f"  Port {p['port']}/{p.get('service','unknown')}"
        + (f" — {p.get('version','')}" if p.get("version") else "")
        for p in ports
    ]
    ports_text = "\n".join(port_lines) if port_lines else "  No open ports"

    prompt = f"""
You are a friendly network security assistant helping a home user understand
their device's security. Explain things in simple plain English — no jargon.

Device context:
- IP: {ip}
- OS: {os_info}
- Open ports:\n{ports_text}
- Shodan info: {shodan_summary}
- Known CVEs: {', '.join(cves) if cves else 'None'}

User question: {question}

Answer clearly and helpfully. If they ask how to close a port, give specific
step-by-step instructions for Windows. Keep the response concise.
"""

    try:
        res = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500,
            temperature=0.3
        )
        return res.choices[0].message.content.strip()

    except Exception as e:
        print(f"[NetGuard] AI chat failed: {e}")
        return "Sorry, AI assistant is currently unavailable. Please check your Groq API key."

def network_copilot(devices: list, question: str, history: list = None) -> str:
    """
    Network-wide AI copilot. Has full context of all scanned devices
    and answers questions about the overall network security posture.
    """
    import json

    scanned = [d for d in devices if d.get("final_score") is not None]
    unscanned = len(devices) - len(scanned)

    critical = [d for d in scanned if d.get("severity") == "critical"]
    high     = [d for d in scanned if d.get("severity") == "high"]
    medium   = [d for d in scanned if d.get("severity") == "medium"]
    low      = [d for d in scanned if d.get("severity") == "low"]

    device_lines = []
    for d in scanned:
        try:
            ports = json.loads(d.get("ports", "[]")) if isinstance(d.get("ports"), str) else (d.get("ports") or [])
            dangerous = json.loads(d.get("dangerous_ports", "[]")) if isinstance(d.get("dangerous_ports"), str) else (d.get("dangerous_ports") or [])
            cves = json.loads(d.get("cves", "[]")) if isinstance(d.get("cves"), str) else (d.get("cves") or [])
        except Exception:
            ports, dangerous, cves = [], [], []

        port_strs = [f"{p['port']}/{p.get('service','?')}({p.get('risk','?')})" for p in dangerous[:8]]
        line = (
            f"  {d['ip']} | {d.get('os','unknown')} | "
            f"score:{d.get('final_score','?')} severity:{d.get('severity','?')} | "
            f"dangerous_ports:[{', '.join(port_strs) or 'none'}] | "
            f"CVEs:{len(cves)}"
        )
        device_lines.append(line)

    network_summary = "\n".join(device_lines) if device_lines else "  No devices scanned yet."

    messages = [{"role": "user", "content": f"""You are NetGuard Copilot — an expert network security AI assistant.
You have full visibility into this network's security scan results.

--- NETWORK OVERVIEW ---
Total devices discovered: {len(devices)}
Fully scanned: {len(scanned)}  |  Not yet scanned: {unscanned}
Critical: {len(critical)}  |  High: {len(high)}  |  Medium: {len(medium)}  |  Low/Safe: {len(low)}

--- SCANNED DEVICES ---
{network_summary}

--- USER QUESTION ---
{question}

Answer in plain English. Be specific and actionable. Reference actual IPs and port numbers from the data above when relevant.
If asked to prioritize, rank by severity then score. Keep your response focused and under 300 words unless a detailed breakdown is explicitly requested."""}]

    # Inject conversation history if provided
    if history:
        messages = history + [messages[-1]]

    try:
        res = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            max_tokens=700,
            temperature=0.3
        )
        return res.choices[0].message.content.strip()
    except Exception as e:
        print(f"[NetGuard] Copilot failed: {e}")
        return "Sorry, the AI copilot is temporarily unavailable. Please check your Groq API key."
