# Network Traffic Monitoring & Intrusion Detection System (Network IDS)

Engineering/final-year starter project using Python, Scapy, Isolation Forest, Flask, and JSONL logs.

## Features
- Local Flask dashboard with event counts, recent events, and alert list.
- Synthetic demo data so the application runs without admin/root privileges.
- Scapy packet metadata collection from an authorized interface or an existing PCAP.
- Isolation Forest anomaly detector; metadata only, no packet payload storage.
- JSONL event log that the dashboard reads.
- Explicit authorization flag before packet capture.

## Project structure
```text
network-ids-project/
├── app.py                 # Flask dashboard/API
├── packet_sniffer.py      # Authorized live capture / PCAP analysis
├── ml_model.py            # Isolation Forest training and inference
├── requirements.txt
├── templates/index.html
├── static/style.css
├── data/                  # Runtime event log
└── models/                # Generated ML model
```

## Windows setup (PowerShell)
1. Install Python 3.10+ and verify:
   ```powershell
   py --version
   ```
2. Extract the ZIP and open PowerShell in the `network-ids-project` folder.
3. Create and activate a virtual environment:
   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
   If script execution is blocked for this session, use `.\.venv\Scripts\python.exe` instead of activating.
4. Install dependencies:
   ```powershell
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```
5. Train the demo model once:
   ```powershell
   python ml_model.py
   ```
6. Start the dashboard:
   ```powershell
   python app.py
   ```
7. Open `http://127.0.0.1:5000` in your browser. Use the buttons to add clearly marked synthetic normal/suspicious demo events.

## Linux/macOS setup
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python ml_model.py
python app.py
```
Then open `http://127.0.0.1:5000`.

## Authorized packet capture
Only monitor networks/interfaces you own or administer, or where you have explicit written permission. Live capture may require administrator/root privileges and a compatible packet-capture driver (Npcap on Windows).

List available interfaces with Scapy/Python or your OS tools, then run one of these examples:

**Live interface (replace `Ethernet` with your actual interface name):**
```powershell
python packet_sniffer.py --authorized --interface "Ethernet" --count 100
```

**Offline PCAP file:**
```powershell
python packet_sniffer.py --authorized --pcap "C:\path\to\authorized-capture.pcap"
```

Captured records are appended to `data/traffic_logs.jsonl`; only packet metadata is recorded. Refresh the dashboard to see new events. Stop live capture with Ctrl+C. The live capture feature is optional; the demo dashboard does not need it.

## Important engineering notes
- Isolation Forest is trained on generated synthetic feature distributions. Its output is a learning/demo signal, not a validated production IDS and not a probability of attack.
- `duration` is currently set to `0.0` per packet; accurate flow-level duration, connection aggregation, thresholds, and labeled datasets are future improvements.
- Validate the model on a suitable authorized dataset (e.g., a properly licensed benchmark) before drawing security conclusions.
- For production, add authentication, HTTPS, role-based access, retention controls, input validation, monitoring, and tests. Do not expose the development server to the public internet.
