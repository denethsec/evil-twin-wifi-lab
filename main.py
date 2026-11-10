#!/usr/bin/env python3
"""Evil Twin Wi-Fi Lab - educational simulation. Entry point.

Usage:
    python main.py               # launch the GUI
    python main.py --headless    # run the scenario in the console (no display needed)
"""
from __future__ import annotations

import argparse
import logging
import sys


def run_headless(security: str, seed: int) -> int:
    from core.events import EventBus
    from core.models import Security
    from core.simulation import ScenarioConfig, SimState, SimulationEngine

    bus = EventBus()
    engine = SimulationEngine(bus, ScenarioConfig(rogue_security=Security(security), step_delay=0.0, seed=seed))
    engine.run_blocking()
    for event in bus.history():
        print(event.formatted())
    return 0 if engine.state == SimState.COMPLETED else 1


def run_gui() -> int:
    try:
        import customtkinter  # noqa: F401
    except ImportError:
        print("CustomTkinter is missing. Install it with:  pip install -r requirements.txt", file=sys.stderr)
        return 2
    try:
        from gui.app import App
        app = App()
    except Exception as exc:  # most commonly: no display / Tk not installed
        print(f"Could not start the GUI: {exc}\n"
              "On Linux make sure a display is available and python3-tk is installed "
              "(sudo apt install python3-tk). Use --headless to run without a display.", file=sys.stderr)
        return 3
    app.mainloop()
    return 0


def main() -> int:
    if sys.version_info < (3, 9):
        print("Python 3.9 or newer is required.", file=sys.stderr)
        return 1
    parser = argparse.ArgumentParser(description="Evil Twin Wi-Fi educational simulation")
    parser.add_argument("--headless", action="store_true", help="run the scenario in the console")
    parser.add_argument("--rogue-security", choices=["Open", "WPA2-PSK"], default="Open")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    return run_headless(args.rogue_security, args.seed) if args.headless else run_gui()


if __name__ == "__main__":
    sys.exit(main())
