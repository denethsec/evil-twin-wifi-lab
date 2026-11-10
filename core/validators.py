"""Input validation helpers (SSID, BSSID, channel)."""
from __future__ import annotations

import re

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


class ValidationError(ValueError):
    """Raised when a user-supplied value is not acceptable."""


def validate_ssid(value: str) -> str:
    """SSIDs are 1-32 bytes (UTF-8), without control characters."""
    if not isinstance(value, str) or value == "":
        raise ValidationError("SSID must not be empty.")
    if len(value.encode("utf-8")) > 32:
        raise ValidationError("SSID must be at most 32 bytes long.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValidationError("SSID must not contain control characters.")
    if value.strip() == "":
        raise ValidationError("SSID must not consist only of whitespace.")
    return value


def validate_bssid(value: str) -> str:
    """Return an upper-case, colon-separated MAC address or raise."""
    if not isinstance(value, str) or not _MAC_RE.match(value):
        raise ValidationError("BSSID must look like AA:BB:CC:DD:EE:FF.")
    return value.upper()


def validate_channel(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 196:
        raise ValidationError("Channel must be an integer between 1 and 196.")
    return value


def validate_delay(value: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError("Step delay must be a number.") from exc
    if not 0.0 <= number <= 10.0:
        raise ValidationError("Step delay must be between 0 and 10 seconds.")
    return number
