# AI-based Threat Detection System

Small IDS project for detecting suspicious network packets.

## Quick checks before submission

- Run tests:

  ```bash
  pytest -q
  ```

- Run linters and formatters:

  ```bash
  flake8 ids tests scripts main.py --max-line-length=120
  black --check --line-length 120 .
  ```

- To run the system locally (demo):

  ```bash
  python main.py
  ```

## Notes
- Tests include a `tests/test_malware_detection.py` that verifies signature detection for C2-style payloads and end-to-end alert storage.
- CI workflow (`.github/workflows/ci.yml`) runs the test and style checks on push/PR.

### Packet logging and terminal output 🔧
- Per-packet logging is controlled by the following config keys in `config/main.yaml`:
  - `logging.log_packets` (boolean) — when true, the IDS prints a concise line for captured packets to the terminal.
  - `logging.packet_log_every` (integer) — log every Nth packet when `log_packets` is true (default: 1 = every packet). Use a higher value (e.g., `10`) to reduce console noise.
- On Windows the console encoding may not support some Unicode characters (e.g., arrows). The logger uses ASCII `->` to ensure packet lines display reliably across platforms.

