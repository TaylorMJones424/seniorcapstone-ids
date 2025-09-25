# seniorcapstone-ids
# Senior Capstone — Network IDS (SYN Flood Detector)

**One-line:** Proof-of-concept Network Intrusion Detection System that simulates SYN-flood attacks, captures PCAPs, analyzes packet behavior, logs to a SQL DB and triggers alerts on a VM.

---

## Repository contents
- `scripts/` — analysis & alert scripts.
- `pcap_samples/` — sanitized sample PCAPs (not real internal IPs).
- `docs/` — architecture, sample queries, and testing notes.
- `demo/` — demo GIF/video (20–60s) and instructions.
- `config.example.env` — example environment variables (fill and copy to `.env`).
- `Dockerfile` — optional reproducible environment.

---

## Quick start (local)
1. Install prerequisites:
   - Python 3.9+.
   - Wireshark/tshark installed and in PATH (required by `pyshark`).
   - ODBC driver for SQL Server (or your chosen DB driver). For Linux, FreeTDS + unixODBC may be required.
2. Create a virtualenv:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
