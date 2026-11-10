"""Static educational text shown in the Learn tab."""

LESSONS = """\
WHAT IS AN EVIL TWIN?
An evil twin is a rogue access point that advertises the same network name (SSID) as a legitimate one.
Clients identify networks by SSID text, so a look-alike with a stronger signal can attract them.

LEGITIMATE vs FRAUDULENT ACCESS POINT
- Legitimate: owned and managed by the network operator, known BSSID (hardware MAC), enforced encryption,
  approved channel and vendor hardware.
- Fraudulent: controlled by a third party, same SSID but a different BSSID, often a different channel,
  frequently weaker or no encryption, often placed physically close to victims for a strong signal.

HOW SSID IMITATION WORKS (CONCEPT)
The SSID is an unauthenticated text field in beacon frames. Copying it requires no secret. What an
imitator cannot copy is the operator's infrastructure: the real BSSID inventory, 802.1X server
certificate or the pre-shared key (unless the key is known).

WHY AUTO-CONNECT IS RISKY
Devices remember networks by name and often join the strongest matching signal without asking.
Legacy and IoT devices may also accept an Open network for a saved secured name. Public networks that
share one password across all users give little protection against a twin that knows that password.

DEFENSIVE DETECTION TECHNIQUES (used in this lab)
1. Duplicate SSID detection - the same SSID served by several BSSIDs.
2. BSSID comparison - compare against an administrator-approved inventory.
3. Security-mode comparison - a known SSID appearing as Open or weaker WPA is a downgrade red flag.
4. Channel / vendor (OUI) / locally-administered-MAC checks.
5. Signal-strength anomalies - a same-SSID AP far stronger or less stable than the baseline.

NOTE ON FALSE POSITIVES
Enterprise networks legitimately use many BSSIDs per SSID. Duplicate SSIDs alone are only a hint; the
trusted-profile comparison is what makes detection reliable. Toggle "Use admin trusted profile" in the
Detection Lab to see the difference.

DEFENCES
WPA3-SAE or WPA2/3-Enterprise with certificate validation, Protected Management Frames (802.11w), a VPN,
HTTPS + HSTS, disabling auto-connect on public networks, forgetting old profiles and running a wireless
IDS/WIPS. Never respond to a rogue AP by jamming or deauthenticating - that is illegal in many places.

SCOPE OF THIS LAB
Pure simulation: no radio access, no scanning of real networks, no deauthentication, no traffic
interception and no credential collection.
"""
