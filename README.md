# fraudlogix

Bulk proxy IP checker against [FraudLogix](https://www.fraudlogix.com/ip-fraud-score-checker/) free IP fraud score API. Replicates the browser flow with TLS-accurate Chrome 145 fingerprinting via [rnet](https://pypi.org/project/rnet/).

## Usage

```
echo "host:port:user:pass" > proxies.txt
uv run main.py --tag mytag -c 100
```

Flags:
- `--tag` — label for the batch (default: `default`)
- `-c` / `--concurrency` — parallel workers (default: `50`)
- `-o` / `--output` — output CSV path (default: `results.csv`)
- `-r` / `--resume` — skip proxies already in output CSV

## Output

CSV with 21 columns: `tag`, `proxy`, `IP`, `RiskScore`, `RecentlySeen`, `ConnectionType`, `Proxy`, `VPN`, `TOR`, `DataCenter`, `SearchEngineBot`, `MaskedDevices`, `AbnormalTraffic`, `ASN`, `ISP`, `Organization`, `City`, `Region`, `Country`, `CountryCode`, `Timezone`.

## Install

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```
uv sync
```
