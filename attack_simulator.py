import json, logging, time, asyncio
from typing import Dict, List
import httpx

log = logging.getLogger("attack_simulator")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

ATTACK_SCENARIOS = {
    "wannacry":   {"name": "WannaCry Ransomware",       "entry_ports": [445, 139], "color": "#FF1744", "icon": "💀", "description": "Exploits SMB to spread across network"},
    "mirai":      {"name": "Mirai Botnet",              "entry_ports": [23, 2323], "color": "#FF6D00", "icon": "🤖", "description": "Targets IoT devices with default credentials"},
    "mitm":       {"name": "Man-in-the-Middle",         "entry_ports": [80, 21],   "color": "#AA00FF", "icon": "👁",  "description": "Intercepts unencrypted traffic"},
    "bruteforce": {"name": "Default Credential Attack", "entry_ports": [22, 3389], "color": "#FF6D00", "icon": "🔑", "description": "Tries default passwords on exposed services"},
    "ransomware": {"name": "Generic Ransomware",        "entry_ports": [445, 3389],"color": "#FF1744", "icon": "🔒", "description": "Encrypts files after gaining network access"},
}

PROMPT = """You are a cybersecurity expert simulating a {attack_name} attack on a home network.

Network:
{network_json}

Attack description: {attack_description}
Typically enters through ports: {entry_ports}

Return ONLY this JSON:
{{
  "attack_name": "{attack_name}",
  "success": true,
  "time_to_compromise": "e.g. 2 minutes",
  "entry_device": "IP address",
  "attack_path": [
    {{
      "step": 1,
      "device_ip": "IP",
      "device_type": "windows_pc",
      "action": "What attacker does",
      "vulnerability_used": "CVE or technique",
      "time_elapsed": "0 seconds",
      "severity": "critical"
    }}
  ],
  "compromised_devices": ["IP list"],
  "data_at_risk": ["files", "passwords"],
  "critical_fix": "One action to stop this",
  "prevention_tip": "How to prevent"
}}"""


class AttackSimulator:
    def __init__(self, api_key: str):
        self.api_key = api_key or ""
        self.client  = httpx.AsyncClient(timeout=60.0)
        self._last   = 0.0

    async def simulate(self, devices: List[Dict], attack_type: str) -> Dict:
        scenario = ATTACK_SCENARIOS.get(attack_type)
        if not scenario:
            return {"error": f"Unknown attack type: {attack_type}"}

        summary = [{
            "ip":         d["ip"],
            "os":         d.get("os", "unknown"),
            "open_ports": [p["port"] for p in d.get("ports", [])],
            "risk_score": d.get("final_score", 0),
            "severity":   d.get("severity", "low"),
        } for d in devices]

        prompt = PROMPT.format(
            attack_name=scenario["name"],
            attack_description=scenario["description"],
            entry_ports=scenario["entry_ports"],
            network_json=json.dumps(summary, indent=2)
        )

        raw = await self._call_groq(prompt)
        if raw:
            try:
                result = json.loads(raw)
                result["scenario"]    = scenario
                result["attack_type"] = attack_type
                return result
            except Exception:
                pass

        return self._fallback(devices, attack_type, scenario)

    async def _call_groq(self, prompt: str):
        if not self.api_key:
            return None
        wait = 2.0 - (time.time() - self._last)
        if wait > 0:
            await asyncio.sleep(wait)
        try:
            resp = await self.client.post(
                GROQ_URL,
                headers={"Authorization": f"Bearer {self.api_key}",
                         "Content-Type": "application/json"},
                json={"model": "llama-3.3-70b-versatile",
                      "messages": [{"role": "user", "content": prompt}],
                      "max_tokens": 2000, "temperature": 0.2,
                      "response_format": {"type": "json_object"}}
            )
            self._last = time.time()
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"]
        except Exception as e:
            log.error(f"Groq failed: {e}")
        return None

    def _fallback(self, devices, attack_type, scenario):
        entry_ports = set(scenario["entry_ports"])
        vulnerable  = [d for d in devices
                       if any(p["port"] in entry_ports
                              for p in d.get("ports", []))]
        if not vulnerable:
            return {"attack_name": scenario["name"], "success": False,
                    "attack_path": [], "compromised_devices": [],
                    "critical_fix": "No vulnerable entry points found",
                    "scenario": scenario, "attack_type": attack_type}

        entry = max(vulnerable, key=lambda d: d.get("final_score", 0))
        path  = [{"step": 1, "device_ip": entry["ip"],
                  "device_type": entry.get("os", "unknown"),
                  "action": f"Entry via port {entry_ports & {p['port'] for p in entry.get('ports',[])}}",
                  "vulnerability_used": scenario["description"],
                  "time_elapsed": "0 seconds", "severity": "critical"}]
        compromised = [entry["ip"]]

        for i, d in enumerate(devices):
            if d["ip"] != entry["ip"] and d.get("final_score", 0) > 20:
                path.append({"step": i+2, "device_ip": d["ip"],
                             "action": "Lateral movement",
                             "time_elapsed": f"{(i+1)*30} seconds",
                             "severity": d.get("severity", "medium")})
                compromised.append(d["ip"])

        return {"attack_name": scenario["name"], "success": True,
                "time_to_compromise": f"{len(path)*30} seconds",
                "entry_device": entry["ip"], "attack_path": path,
                "compromised_devices": compromised,
                "data_at_risk": ["files", "passwords", "camera feeds"],
                "critical_fix": f"Close ports {list(entry_ports)} on {entry['ip']}",
                "scenario": scenario, "attack_type": attack_type}