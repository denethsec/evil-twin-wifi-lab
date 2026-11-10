# Evil Twin Wi-Fi Lab (educational simulation)

A CustomTkinter dashboard that simulates an Evil Twin attack **entirely in memory** and demonstrates how to
detect it. No radio, no scanning, no packets, no real SSIDs, no credentials.

**Explicitly NOT implemented:** impersonating real networks, interfering with nearby Wi-Fi, deauthentication,
traffic interception, credential collection. A unit test fails if `socket`, `subprocess`, `scapy`, `requests`
etc. are ever imported by the project.

## Architecture
```
GUI thread (CustomTkinter)  <--polls every 100 ms--  EventBus (queue)  <--publishes--  Simulation worker thread
        gui/app.py                                    core/events.py                     core/simulation.py
                                                                                                |
                                                                                       core/detection.py (defender)
```
* `core/models.py` – dataclasses (AccessPoint, Client, TrustedProfile, SimEvent, enums)
* `core/validators.py` – SSID / BSSID / channel / delay validation
* `core/simulation.py` – scripted 7-stage scenario, client join logic, simulated RSSI, start/stop/reset
* `core/detection.py` – duplicate SSID, BSSID/security/channel/OUI checks, signal anomaly, risk score, recommendations
* `gui/` – theme, widgets (lifecycle, topology, signal chart, log view), main window, Learn-tab text

## Folder structure
```
evil_twin_lab/
├── main.py            ├── requirements.txt     ├── README.md
├── core/  __init__.py models.py events.py validators.py detection.py simulation.py
├── gui/   __init__.py theme.py content.py widgets.py app.py
└── tests/ __init__.py test_core.py test_gui_smoke.py
```

## Installation
Requires Python 3.9+ with Tk.
```bash
cd evil_twin_lab
python -m venv .venv
# Windows:  .venv\Scripts\activate        Linux/macOS:  source .venv/bin/activate
pip install -r requirements.txt
# Linux only, if tkinter is missing:   sudo apt install python3-tk
```

## Running
1. `python main.py`
2. Optionally change the **Lab SSID** (1-32 chars) and the rogue AP security (*Open* or *WPA2-PSK*), and the **step speed**.
3. Click **▶ Start**. Watch the Dashboard (lifecycle + live log), **Network Simulation** (APs, clients – red = lured to rogue),
   and **Detection Lab** (scan table, findings, risk bar, signal chart, recommendations).
4. **■ Stop** halts at any point; **↺ Reset** clears everything; you can start again.
5. In **Detection Lab** use **Run detection scan** at any time after the APs exist. Turn off *Use admin trusted profile*
   to see why duplicate-SSID alone is ambiguous (legitimate multi-AP networks exist).
6. **Event Log** tab: filter by level and export to a text file.

Console-only run (no display needed): `python main.py --headless [--rogue-security WPA2-PSK] [--seed 3]`

Try both rogue modes: with *Open*, only the legacy IoT sensor is lured (modern clients refuse an Open network for a saved
WPA2 SSID); with *WPA2-PSK* (attacker knows the shared key) the auto-connect laptop is lured too. The BSSID-pinned phone
and the manual-select laptop are never lured.

## Troubleshooting
| Symptom | Fix |
|---|---|
| `ModuleNotFoundError: customtkinter` | `pip install -r requirements.txt` (activate your venv first) |
| `No module named tkinter` | Linux: `sudo apt install python3-tk`; Windows: re-run the Python installer and tick *tcl/tk* |
| `no display name and no $DISPLAY` | Run on a desktop session, or use `--headless`, or `xvfb-run -a python main.py` |
| Blurry / wrongly scaled window on Windows HiDPI | Right-click python.exe → Properties → Compatibility → Change high DPI settings |
| Start button greyed out | A run is active – press Stop or Reset |
| "SSID must…" message | The SSID must be 1-32 bytes, no control characters |
| Harmless `invalid command name ...` lines when closing | CustomTkinter's internal timers firing after window destruction; safe to ignore |

## Testing
```bash
python -m unittest discover -s tests -v          # 14 core tests (+ GUI tests are skipped without a display)
xvfb-run -a python -m unittest tests.test_gui_smoke -v     # Linux headless GUI test; on a desktop just omit xvfb-run
```
Checklist: syntax compile · imports · Start/Stop/Reset · double-start rejected · settings locked while running ·
invalid SSID rejected · scan before start rejected · both rogue modes · pinned/manual clients resist · detection with and
without trusted profile · log filter + export · worker exception handled (engine stays usable) · no network imports.
