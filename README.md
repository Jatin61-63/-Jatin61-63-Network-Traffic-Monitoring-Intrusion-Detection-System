Network Traffic Monitoring & Intrusion Detection System (Network IDS)
Engineering/final-year starter project using Python, Scapy, Isolation Forest, Flask, and JSONL logs.

Features
Local Flask dashboard with event counts, recent events, and alert list.
Synthetic demo data so the application runs without admin/root privileges.
Scapy packet metadata collection from an authorized interface or an existing PCAP.
Isolation Forest anomaly detector; metadata only, no packet payload storage.
JSONL event log that the dashboard reads.
Explicit authorization flag before packet capture.
Project structure
network-ids-project/
├── app.py                 # Flask dashboard/API
├── packet_sniffer.py      # Authorized live capture / PCAP analysis
├── ml_model.py            # Isolation Forest training and inference
├── requirements.txt
├── templates/index.html
├── static/style.css
├── data/                  # Runtime event log
└── models/                # Generated ML model
Windows setup (PowerShell)
Install Python 3.10+ and verify:
py --version
Extract the ZIP and open PowerShell in the network-ids-project folder.
Create and activate a virtual environment:
py -m venv .venv
.\.venv\Scripts\Activate.ps1
If script execution is blocked for this session, use .\.venv\Scripts\python.exe instead of activating.
Install dependencies:
python -m pip install --upgrade pip
pip install -r requirements.txt
Train the demo model once:
python ml_model.py
Start the dashboard:
python app.py
Open http://127.0.0.1:5000 in your browser. Use the buttons to add clearly marked synthetic normal/suspicious demo events.
Linux/macOS setup
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python ml_model.py
python app.py
Then open http://127.0.0.1:5000.

Authorized packet capture
Only monitor networks/interfaces you own or administer, or where you have explicit written permission. Live capture may require administrator/root privileges and a compatible packet-capture driver (Npcap on Windows).

List available interfaces with Scapy/Python or your OS tools, then run one of these examples:

Live interface (replace Ethernet with your actual interface name):

python packet_sniffer.py --authorized --interface "Ethernet" --count 100
Offline PCAP file:

python packet_sniffer.py --authorized --pcap "C:\path\to\authorized-capture.pcap"
Captured records are appended to data/traffic_logs.jsonl; only packet metadata is recorded. Refresh the dashboard to see new events. Stop live capture with Ctrl+C. The live capture feature is optional; the demo dashboard does not need it.
