# NGoya SOC Starter

A local educational SOC dashboard built with Flask, SQLite and psutil.

## Kali Linux setup

```bash
cd NGoya_SOC_Starter
sudo apt update
sudo apt install -y python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

Initial login: `admin` / `ChangeMe123!`

This is a development starter. Change the default password and `SOC_SECRET_KEY` before any deployment. Keep the server bound to localhost. The test-alert button creates simulated events, not real detections. Interface counters are cumulative host statistics, not packet inspection. Only monitor systems and networks you own or are authorized to administer.
