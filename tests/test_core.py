"""Unit tests for core logic (no display needed). Run: python -m unittest discover -s tests -v"""
import pathlib
import re
import sys
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from core.detection import DetectionEngine, is_locally_administered, vendor_for
from core.events import EventBus
from core.models import AccessPoint, Security, TrustedProfile
from core.simulation import (LEGIT_BSSID, ROGUE_BSSID, ScenarioConfig, SimState, SimulationEngine,
                             SimulationError)
from core.validators import ValidationError, validate_bssid, validate_channel, validate_delay, validate_ssid


def make_engine(security=Security.OPEN, delay=0.0, seed=5):
    bus = EventBus()
    return bus, SimulationEngine(bus, ScenarioConfig(rogue_security=security, step_delay=delay, seed=seed))


class ValidatorTests(unittest.TestCase):
    def test_ssid(self):
        self.assertEqual(validate_ssid("Lab Net"), "Lab Net")
        for bad in ("", "   ", "x" * 33, "bad\nname", "é" * 17):
            with self.assertRaises(ValidationError):
                validate_ssid(bad)

    def test_bssid_channel_delay(self):
        self.assertEqual(validate_bssid("aa:bb:cc:00:11:22"), "AA:BB:CC:00:11:22")
        for bad in ("aabbcc001122", "ZZ:BB:CC:00:11:22", ""):
            with self.assertRaises(ValidationError):
                validate_bssid(bad)
        with self.assertRaises(ValidationError):
            validate_channel(0)
        with self.assertRaises(ValidationError):
            validate_delay("abc")
        with self.assertRaises(ValidationError):
            validate_delay(99)


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.legit = AccessPoint("Corp", LEGIT_BSSID, 6, Security.WPA2, -58, vendor_for(LEGIT_BSSID))
        self.rogue = AccessPoint("Corp", ROGUE_BSSID, 11, Security.OPEN, -40, "Unknown")
        self.trusted = TrustedProfile("Corp", LEGIT_BSSID, 6, Security.WPA2, -58.0)
        self.hist = {LEGIT_BSSID: [-58, -57, -59, -58], ROGUE_BSSID: [-40, -39, -41, -40]}

    def test_rogue_flagged_legit_trusted(self):
        rep = DetectionEngine().analyze([self.legit, self.rogue], self.trusted, self.hist)
        by = {a.ap.bssid: a for a in rep.assessments}
        self.assertEqual(by[LEGIT_BSSID].verdict, "Trusted")
        self.assertEqual(by[ROGUE_BSSID].verdict, "Likely rogue")
        codes = {f.code for f in by[ROGUE_BSSID].findings}
        for code in ("DUPLICATE_SSID", "BSSID_MISMATCH", "SECURITY_MISMATCH", "SIGNAL_ANOMALY", "LOCAL_ADMIN_MAC"):
            self.assertIn(code, codes)
        self.assertTrue(rep.verdict.startswith("ALERT"))
        self.assertGreaterEqual(rep.alert_count, 2)

    def test_without_profile_is_ambiguous(self):
        rep = DetectionEngine().analyze([self.legit, self.rogue], None, self.hist)
        self.assertFalse(any(a.trusted for a in rep.assessments))
        self.assertFalse(any(f.code == "BSSID_MISMATCH" for f in rep.findings))
        self.assertTrue(any(f.code == "DUPLICATE_SSID" for f in rep.findings))

    def test_single_ap_clean(self):
        rep = DetectionEngine().analyze([self.legit], self.trusted, {LEGIT_BSSID: [-58] * 4})
        self.assertEqual(rep.overall_score, 0)
        self.assertTrue(rep.verdict.startswith("No evil-twin"))

    def test_helpers(self):
        self.assertTrue(is_locally_administered(ROGUE_BSSID))
        self.assertFalse(is_locally_administered(LEGIT_BSSID))


class SimulationTests(unittest.TestCase):
    def test_full_run_open(self):
        bus, eng = make_engine(Security.OPEN)
        eng.run_blocking()
        self.assertEqual(eng.state, SimState.COMPLETED)
        snap = eng.snapshot()
        on = {c.name: c.connected_bssid for c in snap["clients"]}
        self.assertEqual(on["Phone-Bob"], LEGIT_BSSID)       # pinned BSSID resists
        self.assertEqual(on["Laptop-Carol"], LEGIT_BSSID)    # manual selection
        self.assertEqual(on["Laptop-Alice"], LEGIT_BSSID)    # refuses Open downgrade
        self.assertEqual(snap["report"].overall_score, 100)
        text = "\n".join(e.message for e in bus.history())
        self.assertIn("ROGUE AP", text)
        self.assertIn("IoT-Sensor associated with the ROGUE AP", text)  # logged before mitigation

    def test_wpa2_rogue_lures_auto_connect_client(self):
        _, eng = make_engine(Security.WPA2)
        # stop right after association by running steps manually
        eng._begin()
        for step in eng._steps()[:6]:
            step()
        on = {c.name: c.connected_bssid for c in eng.clients}
        self.assertEqual(on["Laptop-Alice"], ROGUE_BSSID)
        self.assertEqual(on["Phone-Bob"], LEGIT_BSSID)

    def test_events_have_expected_kinds(self):
        bus, eng = make_engine()
        eng.run_blocking()
        kinds = {e.kind for e in bus.drain(10000)}
        self.assertTrue({"state", "phase", "ap", "client", "signal", "detection", "log", "reset"} <= kinds)

    def test_start_stop(self):
        _, eng = make_engine(delay=0.2)
        eng.start()
        time.sleep(0.15)
        self.assertEqual(eng.state, SimState.RUNNING)
        with self.assertRaises(SimulationError):
            eng.start()
        with self.assertRaises(SimulationError):
            eng.configure(ScenarioConfig())
        self.assertTrue(eng.stop())
        self.assertEqual(eng.state, SimState.STOPPED)
        self.assertFalse(eng.stop())
        eng.reset()
        self.assertEqual(eng.state, SimState.IDLE)
        self.assertIsNone(eng.snapshot()["rogue"])

    def test_restart_after_completion(self):
        _, eng = make_engine()
        eng.run_blocking()
        eng.run_blocking()
        self.assertEqual(eng.state, SimState.COMPLETED)

    def test_error_handling(self):
        _, eng = make_engine()
        with self.assertRaises(SimulationError):
            eng.run_detection()                              # nothing exists yet
        with self.assertRaises(ValidationError):
            ScenarioConfig(ssid="").validated()
        with self.assertRaises(ValidationError):
            ScenarioConfig(step_delay=-1).validated()
        eng._steps = lambda: [lambda: 1 / 0]                 # inject a failing step
        eng.run_blocking()
        self.assertEqual(eng.state, SimState.STOPPED)
        self.assertTrue(any(e.level.value == "ERROR" for e in eng.bus.history()))

    def test_on_demand_detection_without_profile(self):
        _, eng = make_engine()
        eng.run_blocking()
        rep = eng.run_detection(use_trusted=False)
        self.assertFalse(rep.used_trusted_profile)

    def test_no_real_network_or_wireless_imports(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        forbidden = re.compile(r"^\s*(import|from)\s+(socket|subprocess|scapy|requests|urllib|http|os\.system|"
                               r"pywifi|wifi|netifaces|asyncio)\b", re.M)
        for path in list(root.glob("core/*.py")) + list(root.glob("gui/*.py")) + [root / "main.py"]:
            self.assertIsNone(forbidden.search(path.read_text()), f"forbidden import in {path}")


if __name__ == "__main__":
    unittest.main()
