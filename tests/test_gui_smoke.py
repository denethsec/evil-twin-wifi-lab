"""GUI smoke test: drives every button through a real (virtual) display.
Run:  xvfb-run -a python -m unittest tests.test_gui_smoke -v   (Linux)  or plainly on a desktop."""
import pathlib
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import tkinter

try:
    from gui.app import App
    from core.simulation import SimState
    _probe = tkinter.Tk(); _probe.destroy()
    HAVE_DISPLAY = True
except Exception:  # no display / no Tk
    HAVE_DISPLAY = False


def pump(app, seconds=0.0, until=None, timeout=15.0):
    """Process Tk events (and the app's poll timer) for a while."""
    end = time.time() + (timeout if until else seconds)
    while time.time() < end:
        app.update()
        if until and until():
            return True
        time.sleep(0.01)
    return until() if until else True


@unittest.skipUnless(HAVE_DISPLAY, "no display available")
class GuiSmoke(unittest.TestCase):
    def setUp(self):
        self.app = App(poll_ms=20)
        self.app.speed.set(0.1)
        self.app._on_speed(0.1)

    def tearDown(self):
        self.app._on_close()

    def test_start_runs_to_completion_and_updates_widgets(self):
        self.app.start_button.invoke()
        pump(self.app, 0.3)
        self.assertEqual(self.app.engine.state, SimState.RUNNING)
        self.assertEqual(str(self.app.start_button.cget("state")), "disabled")
        self.assertEqual(str(self.app.stop_button.cget("state")), "normal")
        self.assertTrue(pump(self.app, until=lambda: self.app.engine.state == SimState.COMPLETED))
        pump(self.app, 0.3)
        self.assertEqual(self.app.status.label.cget("text"), "COMPLETED")
        self.assertIn("02:13:37:AB:CD:EF", self.app.rogue_card.values["BSSID"].cget("text"))
        self.assertEqual(self.app.legit_card.values["SSID"].cget("text"), "LabCorp-WiFi")
        self.assertEqual(len(self.app.tree.get_children()), 2)
        self.assertIn("ALERT", self.app.verdict_label.cget("text"))
        self.assertNotEqual(self.app.tile_alerts.value.cget("text"), "0")
        self.assertIn("Verdict", self.app.live_log.box.get("1.0", "end"))
        self.assertEqual(self.app.lifecycle.done, 6)

    def test_stop_button(self):
        self.app.speed.set(1.0); self.app._on_speed(1.0)
        self.app.start_button.invoke()
        pump(self.app, 0.3)
        self.app.stop_button.invoke()
        pump(self.app, 0.3)
        self.assertEqual(self.app.engine.state, SimState.STOPPED)
        self.assertEqual(str(self.app.start_button.cget("state")), "normal")

    def test_invalid_ssid_shows_error_and_does_not_start(self):
        self.app.ssid_var.set("")
        self.app.start_button.invoke()
        pump(self.app, 0.1)
        self.assertIn("SSID", self.app.error_label.cget("text"))
        self.assertEqual(self.app.engine.state, SimState.IDLE)

    def test_scan_before_start_and_after(self):
        self.app.scan_button.invoke()
        self.assertIn("Start the simulation", self.app.error_label.cget("text"))
        self.app.start_button.invoke()
        pump(self.app, until=lambda: self.app.engine.state == SimState.COMPLETED)
        self.app.trust_switch.deselect()
        self.app.scan_button.invoke()
        pump(self.app, 0.3)
        self.assertIn("without trusted profile", self.app.full_log.box.get("1.0", "end"))

    def test_wpa2_option_filter_export_reset(self):
        self.app.sec_menu.set("WPA2-PSK (shared key known)")
        self.app.start_button.invoke()
        pump(self.app, until=lambda: self.app.engine.state == SimState.COMPLETED)
        pump(self.app, 0.3)
        self.assertIn("Laptop-Alice associated with the ROGUE", self.app.full_log.box.get("1.0", "end"))
        self.app._on_filter("ATTACK")
        text = self.app.full_log.box.get("1.0", "end")
        self.assertIn("ROGUE", text); self.assertNotIn("[INFO", text)
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "log.txt"
            self.assertGreater(self.app.export_log(str(path)), 10)
            self.assertIn("[detector]", path.read_text())
        self.app.reset_button.invoke()
        pump(self.app, 0.3)
        self.assertEqual(self.app.engine.state, SimState.IDLE)
        self.assertEqual(len(self.app.tree.get_children()), 0)
        self.assertEqual(self.app.rogue_card.values["BSSID"].cget("text"), "-")

    def test_restart_after_reset_and_tabs(self):
        for name in ("Dashboard", "Network Simulation", "Detection Lab", "Learn", "Event Log"):
            self.app.tabs.set(name); pump(self.app, 0.05)
        self.app.start_button.invoke()
        pump(self.app, until=lambda: self.app.status.label.cget("text") == "COMPLETED")
        self.app.reset_button.invoke()
        pump(self.app, until=lambda: self.app.status.label.cget("text") == "IDLE")
        self.app.start_button.invoke()
        self.assertTrue(pump(self.app, until=lambda: self.app.engine.state == SimState.COMPLETED))


if __name__ == "__main__":
    unittest.main()
