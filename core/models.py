"""Plain data models shared by the simulation, detection engine and GUI."""
from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Dict, Optional


class Security(str, Enum):
    """Wi-Fi security modes used by the virtual access points."""
    OPEN = "Open"
    WPA2 = "WPA2-PSK"
    WPA3 = "WPA3-SAE"


class Level(str, Enum):
    """Log levels / event categories (each has its own colour in the GUI)."""
    INFO = "INFO"
    EDU = "EDU"
    ATTACK = "ATTACK"
    WARNING = "WARNING"
    DEFENSE = "DEFENSE"
    ERROR = "ERROR"


@dataclass
class AccessPoint:
    """A *virtual* access point. Only observable (beacon-like) fields live here.

    The ground truth "is this the rogue?" is deliberately NOT stored, so the
    defensive detector can only use what a real scanner could observe.
    """
    ssid: str
    bssid: str
    channel: int
    security: Security
    signal_dbm: float
    vendor: str = "Unknown"

    def copy(self) -> "AccessPoint":
        return replace(self)


@dataclass
class Client:
    """A virtual Wi-Fi client with a saved profile and a connection policy."""
    name: str
    mac: str
    saved_ssid: str
    saved_security: Security = Security.WPA2
    auto_connect: bool = True                 # joins the "best" known network automatically
    pinned_bssid: Optional[str] = None        # only trusts this exact BSSID
    accepts_open_downgrade: bool = False      # legacy device: joins Open network with a known SSID
    connected_bssid: Optional[str] = None

    def copy(self) -> "Client":
        return replace(self)


@dataclass(frozen=True)
class TrustedProfile:
    """Administrator-approved baseline of the legitimate access point."""
    ssid: str
    bssid: str
    channel: int
    security: Security
    baseline_dbm: float


@dataclass
class SimEvent:
    """An event travelling from the simulation thread to the GUI.

    kind == "log" events are shown in the log views; other kinds ("state",
    "phase", "ap", "client", "signal", "detection", "reset") update widgets.
    """
    message: str
    level: Level = Level.INFO
    category: str = "general"
    kind: str = "log"
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def formatted(self) -> str:
        stamp = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        return f"[{stamp}] [{self.level.value:<7}] [{self.category}] {self.message}"
