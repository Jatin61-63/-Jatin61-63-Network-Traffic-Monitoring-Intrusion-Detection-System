from flask import Flask, render_template, jsonify, request
from pathlib import Path
from datetime import datetime, timezone
import json, random, threading
from ml_model import TrafficAnomalyModel

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
LOG_PATH = DATA_DIR / "traffic_logs.jsonl"
app = Flask(__name__)
model = TrafficAnomalyModel()
lock = threading.Lock()

def ensure_data():
    DATA_DIR.mkdir(exist_ok=True)
    if not LOG_PATH.exists():
        # Safe demo data; these are synthetic records, not real network traffic.
        demo = []
        for i in range(28):
            suspicious = i in (7, 16, 24)
            demo.append({
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "src_ip": f"192.168.1.{10 + (i % 12)}",
                "dst_ip": random.choice(["192.168.1.1", "8.8.8.8", "10.0.0.12"]),
                "protocol": random.choice(["TCP", "UDP", "ICMP"]),
                "src_port": random.choice([443, 51514, 53001, 22, 80]),
                "dst_port": random.choice([53, 80, 443, 22, 3389]),
                "packet_size": random.randint(60, 1450),
                "duration": round(random.uniform(0.01, 3.5), 3),
                "flags": random.choice(["S", "A", "PA", ""]),
                "label": "Suspicious" if suspicious else "Normal",
                "confidence": round(random.uniform(.72, .98), 2) if suspicious else round(random.uniform(.70, .96), 2),
                "source": "synthetic-demo"
            })
        with LOG_PATH.open("w", encoding="utf-8") as f:
            for row in demo:
                f.write(json.dumps(row) + "\n")

def read_logs():
    ensure_data()
    rows = []
    for line in LOG_PATH.read_text(encoding="utf-8").splitlines()[-300:]:
        try: rows.append(json.loads(line))
        except json.JSONDecodeError: continue
    return list(reversed(rows))

def append_event(event):
    ensure_data()
    with lock, LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

@app.route("/")
def index():
    return render_template("index.html")

@app.get("/api/summary")
def summary():
    rows = read_logs()
    suspicious = sum(1 for x in rows if x.get("label") == "Suspicious")
    return jsonify({"total": len(rows), "normal": len(rows)-suspicious, "suspicious": suspicious,
                    "alerts": [x for x in rows if x.get("label") == "Suspicious"][:8],
                    "recent": rows[:20]})

@app.post("/api/simulate")
def simulate():
    # Adds one clearly labeled synthetic event for UI/demo testing.
    kind = request.json.get("kind", "normal") if request.is_json else "normal"
    suspicious = kind == "suspicious"
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "src_ip": f"192.168.1.{random.randint(10, 240)}",
        "dst_ip": random.choice(["192.168.1.1", "10.0.0.12", "8.8.8.8"]),
        "protocol": random.choice(["TCP", "UDP", "ICMP"]),
        "src_port": random.choice([443, 51514, 53001, 22, 80]),
        "dst_port": random.choice([53, 80, 443, 22, 3389]),
        "packet_size": random.randint(60, 1450),
        "duration": round(random.uniform(.01, 4.0), 3),
        "flags": random.choice(["S", "A", "PA", ""]),
        "label": "Suspicious" if suspicious else "Normal",
        "confidence": round(random.uniform(.75, .99), 2),
        "source": "synthetic-demo"
    }
    append_event(event)
    return jsonify({"ok": True, "event": event})

if __name__ == "__main__":
    ensure_data()
    print("Demo dashboard: http://127.0.0.1:5000")
    print("This default mode uses synthetic demo records, not live packet capture.")
    app.run(host="127.0.0.1", port=5000, debug=False)
