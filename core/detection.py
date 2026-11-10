"""Defensive detection module.

Works ONLY on observable fields of virtual access points (SSID, BSSID,
channel, security, signal samples). It never sees the simulation's ground
truth, so it behaves like a real wireless-IDS heuristic would.
"""
from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Sequence

from .models import AccessPoint, Security, TrustedProfile


class Severity(IntEnum):
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass(frozen=True)
class Finding:
    code: str
    severity: Severity
    title: str
    detail: str
    bssid: str


@dataclass
class APAssessment:
    ap: AccessPoint
    trusted: bool
    score: int
    verdict: str
    findings: List[Finding] = field(default_factory=list)


@dataclass
class DetectionReport:
    assessments: List[APAssessment]
    overall_score: int
    verdict: str
    recommendations: List[str]
    used_trusted_profile: bool
    generated_at: float = field(default_factory=time.time)

    @property
    def findings(self) -> List[Finding]:
        return [f for a in self.assessments for f in a.findings]

    @property
    def alert_count(self) -> int:
        """Number of HIGH / CRITICAL findings."""
        return sum(1 for f in self.findings if f.severity >= Severity.HIGH)


# Simulated OUI table. 00:00:5E is IANA's documentation range (RFC 7042), so no
# real vendor is impersonated.
OUI_TABLE: Dict[str, str] = {"00:00:5E": "LabRouter Inc. (simulated)"}


def vendor_for(bssid: str) -> str:
    return OUI_TABLE.get(bssid.upper()[:8], "Unknown")


def is_locally_administered(bssid: str) -> bool:
    """Bit 1 of the first octet marks a software-assigned (not factory) MAC."""
    return bool(int(bssid.split(":")[0], 16) & 0b10)


# Risk weights per finding code (sum is capped at 100).
WEIGHTS: Dict[str, int] = {
    "DUPLICATE_SSID": 20,
    "BSSID_MISMATCH": 30,
    "SECURITY_MISMATCH": 30,
    "CHANNEL_MISMATCH": 5,
    "UNKNOWN_VENDOR": 6,
    "LOCAL_ADMIN_MAC": 6,
    "SIGNAL_ANOMALY": 15,
    "SIGNAL_VARIANCE": 4,
    "SIGNAL_DRIFT": 5,
}

LIKELY_ROGUE_THRESHOLD = 60
SUSPICIOUS_THRESHOLD = 25


class DetectionEngine:
    """Heuristic evil-twin detector."""

    STRONG_DELTA_DB = 12.0      # peer much stronger than the trusted baseline
    ERRATIC_STDEV_DB = 3.5      # unusually unstable signal
    MIN_SAMPLES = 3

    def analyze(
        self,
        scan: Sequence[AccessPoint],
        trusted: Optional[TrustedProfile] = None,
        history: Optional[Dict[str, List[float]]] = None,
    ) -> DetectionReport:
        history = history or {}
        groups: Dict[str, List[AccessPoint]] = {}
        for ap in scan:
            groups.setdefault(ap.ssid.casefold(), []).append(ap)

        assessments: List[APAssessment] = []
        for ap in scan:
            peers = [p for p in groups[ap.ssid.casefold()] if p.bssid.upper() != ap.bssid.upper()]
            is_trusted = bool(
                trusted and ap.bssid.upper() == trusted.bssid.upper() and ap.ssid == trusted.ssid
            )
            findings = [] if is_trusted else self._check_ap(ap, peers, trusted, history)
            if is_trusted:
                findings = self._check_trusted_drift(ap, trusted, history)
            score = min(100, sum(WEIGHTS.get(f.code, 0) for f in findings))
            assessments.append(APAssessment(ap.copy(), is_trusted, score, self._verdict(score, is_trusted), findings))

        overall = max((a.score for a in assessments), default=0)
        if overall >= LIKELY_ROGUE_THRESHOLD:
            verdict = "ALERT: probable Evil Twin detected"
        elif overall >= SUSPICIOUS_THRESHOLD:
            verdict = "WARNING: suspicious access point(s) found"
        else:
            verdict = "No evil-twin indicators found"
        return DetectionReport(assessments, overall, verdict,
                               self._recommendations(assessments), trusted is not None)

    # ------------------------------------------------------------------ checks
    def _check_ap(self, ap, peers, trusted, history) -> List[Finding]:
        out: List[Finding] = []
        samples = history.get(ap.bssid, [])
        impersonates_trusted = bool(trusted and ap.ssid == trusted.ssid)

        if peers:
            others = ", ".join(p.bssid for p in peers)
            out.append(Finding("DUPLICATE_SSID", Severity.MEDIUM, "Duplicate SSID",
                               f"'{ap.ssid}' is also advertised by BSSID {others}. Legitimate multi-AP "
                               "networks do this too, so the BSSID/security must be verified.", ap.bssid))

        if impersonates_trusted:
            out.append(Finding("BSSID_MISMATCH", Severity.HIGH, "BSSID not in trusted profile",
                               f"Trusted BSSID is {trusted.bssid} but this AP uses {ap.bssid}.", ap.bssid))
            if ap.security != trusted.security:
                sev = Severity.CRITICAL if ap.security == Security.OPEN else Severity.HIGH
                out.append(Finding("SECURITY_MISMATCH", sev, "Security mode differs from trusted AP",
                                   f"Trusted AP uses {trusted.security.value}; this AP uses {ap.security.value}.",
                                   ap.bssid))
            if ap.channel != trusted.channel:
                out.append(Finding("CHANNEL_MISMATCH", Severity.LOW, "Different channel",
                                   f"Trusted AP is on channel {trusted.channel}; this AP is on {ap.channel}.",
                                   ap.bssid))
        else:
            for p in peers:  # no admin baseline: compare against peers only
                if p.security != ap.security:
                    out.append(Finding("SECURITY_MISMATCH", Severity.MEDIUM, "Security differs between same-SSID APs",
                                       f"{ap.bssid} uses {ap.security.value} while {p.bssid} uses {p.security.value}.",
                                       ap.bssid))
                    break

        if peers or impersonates_trusted:
            if vendor_for(ap.bssid) == "Unknown":
                out.append(Finding("UNKNOWN_VENDOR", Severity.LOW, "Unknown hardware vendor",
                                   f"OUI {ap.bssid[:8]} is not in the known-vendor table.", ap.bssid))
            if is_locally_administered(ap.bssid):
                out.append(Finding("LOCAL_ADMIN_MAC", Severity.LOW, "Locally administered MAC",
                                   "The BSSID has the locally-administered bit set, which is typical for "
                                   "software-defined access points rather than factory hardware.", ap.bssid))

        if len(samples) >= self.MIN_SAMPLES:
            mean = statistics.fmean(samples)
            reference = trusted.baseline_dbm if impersonates_trusted else self._peer_reference(peers, history)
            if reference is not None and mean - reference >= self.STRONG_DELTA_DB:
                out.append(Finding("SIGNAL_ANOMALY", Severity.MEDIUM, "Signal-strength anomaly",
                                   f"Average {mean:.1f} dBm is {mean - reference:.1f} dB stronger than the "
                                   f"reference {reference:.1f} dBm. Rogue APs are often placed close to victims.",
                                   ap.bssid))
            if statistics.pstdev(samples) >= self.ERRATIC_STDEV_DB:
                out.append(Finding("SIGNAL_VARIANCE", Severity.LOW, "Unstable signal",
                                   f"Signal std-dev {statistics.pstdev(samples):.1f} dB is higher than a "
                                   "fixed, wall-mounted AP normally shows.", ap.bssid))
        return out

    def _check_trusted_drift(self, ap, trusted, history) -> List[Finding]:
        samples = history.get(ap.bssid, [])
        if trusted and len(samples) >= self.MIN_SAMPLES:
            mean = statistics.fmean(samples)
            if abs(mean - trusted.baseline_dbm) >= self.STRONG_DELTA_DB:
                return [Finding("SIGNAL_DRIFT", Severity.LOW, "Trusted AP signal drifted",
                                f"Average {mean:.1f} dBm vs baseline {trusted.baseline_dbm:.1f} dBm.", ap.bssid)]
        return []

    def _peer_reference(self, peers, history) -> Optional[float]:
        means = [statistics.fmean(history[p.bssid]) for p in peers if len(history.get(p.bssid, [])) >= self.MIN_SAMPLES]
        return statistics.median(means) if means else None

    @staticmethod
    def _verdict(score: int, trusted: bool) -> str:
        if trusted and score == 0:
            return "Trusted"
        if score >= LIKELY_ROGUE_THRESHOLD:
            return "Likely rogue"
        if score >= SUSPICIOUS_THRESHOLD:
            return "Suspicious"
        return "Low concern"

    @staticmethod
    def _recommendations(assessments: List[APAssessment]) -> List[str]:
        codes = {f.code for a in assessments for f in a.findings}
        recs = [
            "Verify the BSSID (not just the SSID) against your network inventory before trusting an AP.",
            "Prefer WPA3-SAE or WPA2/WPA3-Enterprise (802.1X) with server-certificate validation.",
            "Enable Protected Management Frames (802.11w) on managed access points.",
            "Disable auto-connect for public or unmanaged networks and 'forget' old profiles.",
            "Use a VPN and rely on HTTPS/HSTS so a hostile AP only sees encrypted traffic.",
            "Run a wireless IDS/WIPS that keeps a baseline of authorised BSSIDs, channels and security modes.",
            "Train users to treat sudden captive portals or certificate warnings as red flags.",
        ]
        if "SECURITY_MISMATCH" in codes:
            recs.insert(0, "Security downgrade seen: alert when a known SSID appears with weaker or no encryption.")
        if "SIGNAL_ANOMALY" in codes:
            recs.append("Investigate the physical location of unusually strong same-SSID transmitters.")
        recs.append("Respond via authorised physical/administrative means; do not 'fight back' by "
                    "deauthenticating or jamming (illegal in many jurisdictions).")
        return recs
