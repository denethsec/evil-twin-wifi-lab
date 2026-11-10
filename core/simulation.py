"""Simulation engine: a scripted, fully virtual Evil Twin scenario.

SAFETY: this module imports no networking, subprocess or wireless libraries.
Every access point, client, signal reading and "connection" is a Python object.
"""
from __future__ import annotations

import random
import statistics
import threading
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Any, Callable, Dict, List, Optional

from .detection import DetectionEngine, DetectionReport, vendor_for
from .events import EventBus
from .models import AccessPoint, Client, Level, Security, SimEvent, TrustedProfile
from .validators import ValidationError, validate_bssid, validate_delay, validate_ssid

LEGIT_BSSID = "00:00:5E:00:53:10"      # IANA documentation range (RFC 7042)
ROGUE_BSSID = "02:13:37:AB:CD:EF"      # locally administered, clearly fictional


class SimulationError(RuntimeError):
    """Raised for invalid operations (e.g. starting twice)."""


class SimState(str, Enum):
    IDLE = "IDLE"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    STOPPED = "STOPPED"


class Phase(IntEnum):
    LEGIT_AP = 0
    SSID_CLONING = 1
    ROGUE_BROADCAST = 2
    CLIENT_ASSOCIATION = 3
    EXPOSURE_RISK = 4
    DETECTION = 5
    MITIGATION = 6


PHASE_INFO: Dict[Phase, str] = {
    Phase.LEGIT_AP: "Legitimate AP online",
    Phase.SSID_CLONING: "Attacker clones SSID",
    Phase.ROGUE_BROADCAST: "Rogue AP broadcasts",
    Phase.CLIENT_ASSOCIATION: "Clients associate",
    Phase.EXPOSURE_RISK: "Exposure & risk",
    Phase.DETECTION: "Defender detects",
    Phase.MITIGATION: "Mitigation",
}


@dataclass
class ScenarioConfig:
    ssid: str = "LabCorp-WiFi"
    rogue_security: Security = Security.OPEN
    step_delay: float = 1.2
    seed: Optional[int] = None

    def validated(self) -> "ScenarioConfig":
        validate_ssid(self.ssid)
        validate_delay(self.step_delay)
        if not isinstance(self.rogue_security, Security):
            raise ValidationError("Rogue security must be a Security value.")
        return self


class SimulationEngine:
    """Runs the scenario on a worker thread and publishes SimEvents on a bus."""

    def __init__(self, bus: EventBus, config: Optional[ScenarioConfig] = None) -> None:
        self.bus = bus
        self.config = (config or ScenarioConfig()).validated()
        self.detector = DetectionEngine()
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.state = SimState.IDLE
        self.phase: Optional[Phase] = None
        self._reset_world()

    # ---------------------------------------------------------------- control
    def configure(self, config: ScenarioConfig) -> None:
        """Replace the scenario config (not allowed while running)."""
        with self._lock:
            if self.state == SimState.RUNNING:
                raise SimulationError("Stop the simulation before changing its settings.")
            self.config = config.validated()

    def start(self) -> None:
        """Start the scenario on a background thread."""
        self._begin()
        self._thread = threading.Thread(target=self._run, name="sim-worker", daemon=True)
        self._thread.start()

    def run_blocking(self) -> None:
        """Run the full scenario synchronously (used by tests and --headless)."""
        self._begin()
        self._run()

    def stop(self, timeout: float = 3.0) -> bool:
        """Request a stop. Returns False if nothing was running."""
        with self._lock:
            if self.state != SimState.RUNNING:
                return False
            self._stop.set()
            thread = self._thread
        if thread and thread is not threading.current_thread():
            thread.join(timeout)
        return True

    def reset(self) -> None:
        """Stop (if needed) and discard all virtual state."""
        self.stop()
        with self._lock:
            self._reset_world()
            self.state = SimState.IDLE
            self.phase = None
        self.bus.clear()
        self.bus.publish(SimEvent("reset", kind="reset"))
        self._publish_state()

    def snapshot(self) -> Dict[str, Any]:
        """Thread-safe copy of the current virtual world."""
        with self._lock:
            return {
                "state": self.state,
                "phase": self.phase,
                "legit": self.legit.copy() if self.legit else None,
                "rogue": self.rogue.copy() if self.rogue else None,
                "clients": [c.copy() for c in self.clients],
                "history": {k: list(v) for k, v in self.history.items()},
                "trusted": self.trusted,
                "report": self.report,
            }

    # -------------------------------------------------------------- internals
    def _reset_world(self) -> None:
        self.legit: Optional[AccessPoint] = None
        self.rogue: Optional[AccessPoint] = None
        self.clients: List[Client] = []
        self.history: Dict[str, List[float]] = {}
        self.trusted: Optional[TrustedProfile] = None
        self.report: Optional[DetectionReport] = None
        self._base: Dict[str, tuple] = {}
        self._rng = random.Random(self.config.seed)

    def _begin(self) -> None:
        with self._lock:
            if self.state == SimState.RUNNING:
                raise SimulationError("The simulation is already running.")
            self._reset_world()
            self._stop.clear()
            self.state = SimState.RUNNING
            self.phase = None
        self.bus.publish(SimEvent("reset", kind="reset"))
        self._publish_state()

    def _run(self) -> None:
        completed = True
        try:
            for step in self._steps():
                if self._stop.is_set():
                    completed = False
                    break
                step()
                if self._stop.wait(self.config.step_delay):
                    completed = False
                    break
        except Exception as exc:  # keep the GUI alive whatever happens
            completed = False
            self._log(f"Simulation aborted by an internal error: {exc!r}", Level.ERROR, "system")
        finally:
            with self._lock:
                self.state = SimState.COMPLETED if completed else SimState.STOPPED
            self._log("Simulation finished." if completed else "Simulation stopped.",
                      Level.INFO, "system")
            self._publish_state()

    def _steps(self) -> List[Callable[[], None]]:
        return [self._s_intro, self._s_legit_ap, self._s_baseline, self._s_clone,
                self._s_rogue_broadcast, self._s_associate, self._s_exposure,
                self._s_detect, self._s_mitigate]

    # -------------------------------------------------------------- publishing
    def _log(self, message: str, level: Level = Level.INFO, category: str = "sim") -> None:
        self.bus.publish(SimEvent(message, level, category))

    def _emit(self, kind: str, **data: Any) -> None:
        self.bus.publish(SimEvent(kind, kind=kind, data=data))

    def _publish_state(self) -> None:
        self._emit("state", state=self.state.value)

    def _set_phase(self, phase: Phase) -> None:
        with self._lock:
            self.phase = phase
        self._emit("phase", phase=int(phase), name=PHASE_INFO[phase])
        self._log(f"Lifecycle stage {int(phase) + 1}/7: {PHASE_INFO[phase]}", Level.INFO, "lifecycle")

    # ------------------------------------------------------------------ steps
    def _s_intro(self) -> None:
        self._log("Everything in this lab is virtual: no radio, no real network, no real traffic.", Level.INFO, "safety")
        self._log("A LEGITIMATE access point is deployed and managed by the network owner: a known BSSID, "
                  "enforced encryption and an approved configuration.", Level.EDU, "lesson")
        self._log("A FRAUDULENT (rogue / evil-twin) access point is controlled by someone else and only "
                  "copies the visible name (SSID). It cannot copy the owner's BSSID hardware identity "
                  "or credentials by itself.", Level.EDU, "lesson")

    def _s_legit_ap(self) -> None:
        self._set_phase(Phase.LEGIT_AP)
        ap = AccessPoint(self.config.ssid, validate_bssid(LEGIT_BSSID), 6, Security.WPA2, -58.0,
                         vendor_for(LEGIT_BSSID))
        with self._lock:
            self.legit = ap
            self._base[ap.bssid] = (-58.0, 1.5)
        self.history[ap.bssid] = []
        self._emit("ap", role="legit")
        self._log(f"Virtual legitimate AP created: SSID='{ap.ssid}' BSSID={ap.bssid} ch{ap.channel} "
                  f"{ap.security.value}", Level.INFO, "network")

    def _s_baseline(self) -> None:
        self._sample_burst(4)
        with self._lock:
            ap = self.legit
            baseline = round(statistics.fmean(self.history[ap.bssid]), 1)
            self.trusted = TrustedProfile(ap.ssid, ap.bssid, ap.channel, ap.security, baseline)
        self._log(f"Administrator recorded a trusted profile (baseline {baseline} dBm). Detection uses it later.",
                  Level.DEFENSE, "baseline")

    def _s_clone(self) -> None:
        self._set_phase(Phase.SSID_CLONING)
        self._log("An SSID is just a text label in beacon frames; anyone can advertise the same text. "
                  "The attacker (a lab actor) therefore reuses the SSID, but must use its own BSSID.",
                  Level.EDU, "lesson")
        sec = self.config.rogue_security
        self._log(f"Attacker profile: SSID copied, BSSID differs, security = {sec.value}.", Level.ATTACK, "attacker")

    def _s_rogue_broadcast(self) -> None:
        self._set_phase(Phase.ROGUE_BROADCAST)
        sec = self.config.rogue_security
        ap = AccessPoint(self.config.ssid, validate_bssid(ROGUE_BSSID), 11, sec, -40.0, vendor_for(ROGUE_BSSID))
        with self._lock:
            self.rogue = ap
            self._base[ap.bssid] = (-40.0, 4.0)
        self.history[ap.bssid] = []
        self._emit("ap", role="rogue")
        self._log(f"Virtual ROGUE AP broadcasting: SSID='{ap.ssid}' BSSID={ap.bssid} ch{ap.channel} {sec.value}",
                  Level.ATTACK, "attacker")
        self._sample_burst(4)

    def _s_associate(self) -> None:
        self._set_phase(Phase.CLIENT_ASSOCIATION)
        ssid = self.config.ssid
        with self._lock:
            self.clients = [
                Client("Laptop-Alice", "0A:00:00:00:00:01", ssid, Security.WPA2, auto_connect=True),
                Client("IoT-Sensor", "0A:00:00:00:00:02", ssid, Security.WPA2, auto_connect=True,
                       accepts_open_downgrade=True),
                Client("Phone-Bob", "0A:00:00:00:00:03", ssid, Security.WPA2, auto_connect=True,
                       pinned_bssid=LEGIT_BSSID),
                Client("Laptop-Carol", "0A:00:00:00:00:04", ssid, Security.WPA2, auto_connect=False),
            ]
        for client in self.clients:
            chosen, reason = self._client_decision(client)
            with self._lock:
                client.connected_bssid = chosen.bssid if chosen else None
            self._emit("client", name=client.name)
            if chosen is None:
                self._log(f"{client.name}: no acceptable network ({reason}).", Level.INFO, "client")
            elif chosen.bssid == ROGUE_BSSID:
                self._log(f"[SIMULATED] {client.name} associated with the ROGUE AP ({reason}).", Level.ATTACK, "client")
            else:
                self._log(f"{client.name} associated with the legitimate AP ({reason}).", Level.INFO, "client")

    def _client_decision(self, client: Client):
        """Model of a client's join logic. Returns (AccessPoint | None, reason)."""
        with self._lock:
            visible = [ap for ap in (self.legit, self.rogue) if ap and ap.ssid == client.saved_ssid]
        if client.pinned_bssid:
            pinned = [ap for ap in visible if ap.bssid == client.pinned_bssid]
            return (pinned[0], "BSSID pinned, ignores look-alikes") if pinned else (None, "pinned AP not visible")
        acceptable = [ap for ap in visible if ap.security == client.saved_security
                      or (ap.security == Security.OPEN and client.accepts_open_downgrade)]
        if not acceptable:
            return None, "no AP matches saved security"
        if not client.auto_connect:
            legit = [ap for ap in acceptable if ap.bssid == LEGIT_BSSID]
            return (legit[0], "manual selection, user checked the BSSID") if legit else (None, "manual, no trusted AP")
        best = max(acceptable, key=lambda ap: ap.signal_dbm)
        reason = f"auto-connect picked strongest signal {best.signal_dbm:.0f} dBm"
        if best.bssid == ROGUE_BSSID and client.accepts_open_downgrade and best.security == Security.OPEN:
            reason += "; legacy profile tolerates an Open network"
        return best, reason

    def _s_exposure(self) -> None:
        self._set_phase(Phase.EXPOSURE_RISK)
        victims = [c.name for c in self.clients if c.connected_bssid == ROGUE_BSSID]
        if victims:
            self._log(f"Auto-connect risk: {', '.join(victims)} would now route traffic via an attacker-run AP.",
                      Level.WARNING, "risk")
            self._log("In a real incident the attacker could observe unencrypted traffic, redirect users to "
                      "fake login pages or downgrade connections. No traffic is generated or captured here.",
                      Level.EDU, "lesson")
        else:
            self._log("No client joined the rogue AP in this scenario.", Level.INFO, "risk")
        self._log("Why automatic connection is risky: clients match on the SSID text and usually prefer "
                  "the strongest signal, so a nearby look-alike can win.", Level.EDU, "lesson")
        self._log("Modern WPA2/WPA3 clients normally refuse an Open network for a saved secured SSID; "
                  "legacy or misconfigured devices may not.", Level.EDU, "lesson")

    def _s_detect(self) -> None:
        self._set_phase(Phase.DETECTION)
        self.run_detection(use_trusted=True)

    def run_detection(self, use_trusted: bool = True) -> DetectionReport:
        """Run the defensive detector against the current virtual scan."""
        with self._lock:
            scan = [ap.copy() for ap in (self.legit, self.rogue) if ap]
            trusted = self.trusted if use_trusted else None
            history = {k: list(v) for k, v in self.history.items()}
        if not scan:
            raise SimulationError("No access points exist yet. Start the simulation first.")
        report = self.detector.analyze(scan, trusted, history)
        with self._lock:
            self.report = report
        self._log(f"Detection scan ({'with' if use_trusted else 'without'} trusted profile): "
                  f"{len(scan)} AP(s) in range.", Level.DEFENSE, "detector")
        for finding in report.findings:
            lvl = Level.WARNING if finding.severity < 4 else Level.DEFENSE
            self._log(f"{finding.title} [{finding.severity.name}] {finding.bssid}: {finding.detail}", lvl, "detector")
        self._log(f"Verdict: {report.verdict} (max risk score {report.overall_score}/100).", Level.DEFENSE, "detector")
        self._emit("detection", report=report)
        return report

    def _s_mitigate(self) -> None:
        self._set_phase(Phase.MITIGATION)
        report = self.report
        for rec in (report.recommendations[:4] if report else []):
            self._log(f"Recommendation: {rec}", Level.DEFENSE, "mitigation")
        for client in self.clients:
            if client.connected_bssid == ROGUE_BSSID:
                with self._lock:
                    client.connected_bssid = LEGIT_BSSID
                    client.pinned_bssid = LEGIT_BSSID
                    client.auto_connect = False
                self._emit("client", name=client.name)
                self._log(f"{client.name}: user verified the BSSID, reconnected to the trusted AP, disabled "
                          "auto-connect and pinned the BSSID (simulated user action).", Level.DEFENSE, "mitigation")
        self._emit("phase", phase=len(Phase), name="Complete")

    # ---------------------------------------------------------------- signals
    def _sample_burst(self, count: int) -> None:
        """Take ``count`` simulated RSSI readings for every existing AP."""
        for _ in range(count):
            with self._lock:
                readings: Dict[str, float] = {}
                for ap in (self.legit, self.rogue):
                    if ap is None:
                        continue
                    base, sigma = self._base[ap.bssid]
                    value = round(max(-95.0, min(-20.0, base + self._rng.gauss(0, sigma))), 1)
                    ap.signal_dbm = value
                    self.history.setdefault(ap.bssid, []).append(value)
                    del self.history[ap.bssid][:-120]
                    readings[ap.bssid] = value
            self._emit("signal", readings=readings)
            if self._stop.wait(self.config.step_delay * 0.25):
                return
