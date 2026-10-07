#!/usr/bin/env python3
"""Scan nearby Wi-Fi networks, print a details table, and append results to CSV.

The script asks for a location label, triggers a fresh scan with the platform
tool, prints every visible access point (one row per BSSID) as a table, and
appends the records to a CSV history file (header written once).

Backends
  Windows  WLAN API: WlanScan forces a real scan (waits for the scan-complete
           notification) and WlanGetNetworkBssList supplies the true RSSI in
           dBm and the exact center frequency; netsh is only a fallback, since
           `netsh wlan show networks` merely prints the WLAN service cache
  Linux    NetworkManager nmcli device wifi list --rescan yes
           (falls back to netsh.exe when running under WSL)
  macOS    airport -s (utility Apple deprecated in macOS 14)

Usage
  python wifi_scanner.py
  python wifi_scanner.py --location "Office 3F" --csv scans/office.csv
  python wifi_scanner.py -c 1,6,11              # channel filter (alias --channel)
  python wifi_scanner.py -b 5                   # band filter: 2.4 / 5 / 6
  python wifi_scanner.py -s "Home*" -s Office   # SSID filter (alias --ssid)
  python wifi_scanner.py --update-oui           # fetch the full IEEE OUI registry

-s/--ssid, -b/--band and -c/--channel restrict which results are kept (and
written to CSV); they combine with AND.  Filter values tolerate surrounding
quotes ('pg*' or "pg*") so they work the same from cmd.exe and POSIX shells.
The platform scan itself always sweeps all channels; no public API exposes a
channel-limited scan.

Vendors: every BSSID is resolved to the registered owner of its OUI prefix
(access point make/brand); locally administered addresses are labelled
"Randomized MAC".  The IEEE registry is cached as oui.csv next to the script
(next to the .exe in frozen builds, seeded from the copy bundled into the
executable); fetch or refresh it with --update-oui, or point --oui-file at an
existing registry CSV.  Without a registry only randomized-MAC detection runs.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import fnmatch
import io
import locale
import os
import platform
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

DEFAULT_CSV = "wifi_networks.csv"

CSV_FIELDS: Sequence[str] = (
    "timestamp",
    "location",
    "ssid",
    "hidden",
    "bssid",
    "vendor",
    "signal_percent",
    "signal_dbm",
    "channel",
    "frequency_mhz",
    "band",
    "radio_type",
    "max_rate_mbps",
    "security",
    "encryption",
    "network_type",
    "interface",
)

# Older releases wrote these layouts; prepare_csv() migrates them in place.
LEGACY_CSV_HEADERS: Sequence[Sequence[str]] = (
    (
        "timestamp",
        "location",
        "ssid",
        "hidden",
        "bssid",
        "signal_percent",
        "signal_dbm",
        "channel",
        "frequency_mhz",
        "band",
        "radio_type",
        "max_rate_mbps",
        "security",
        "encryption",
        "network_type",
        "interface",
    ),
)
_LEGACY_CSV_HEADER_TUPLES = tuple(tuple(header) for header in LEGACY_CSV_HEADERS)

NMCLI_FIELDS = (
    "SSID,BSSID,CHAN,FREQ,RATE,SIGNAL,BARS,SECURITY,WPA-FLAGS,RSN-FLAGS,DEVICE"
)

AIRPORT_PATH = (
    "/System/Library/PrivateFrameworks/Apple80211.framework/"
    "Versions/Current/Resources/airport"
)

# (record key, table header, alignment, display width cap; None = uncapped)
TABLE_COLUMNS: Sequence[tuple] = (
    ("ssid", "SSID", "left", 28),
    ("bssid", "BSSID", "left", 17),
    ("vendor", "VENDOR", "left", 24),
    ("signal_percent", "SIG%", "right", 5),
    ("signal_dbm", "dBm", "right", 5),
    ("channel", "CH", "right", 4),
    ("frequency_mhz", "MHz", "right", 6),
    ("band", "BAND", "left", 8),
    ("security", "SECURITY", "left", 20),
    ("encryption", "CIPHER", "left", 12),
    ("radio_type", "RADIO", "left", 10),
    ("max_rate_mbps", "RATE", "right", 6),
)


class ScanError(RuntimeError):
    """Raised when a scan cannot produce any records."""


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


def _run(cmd: Sequence[str], timeout: float = 45.0) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            list(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout
        )
    except subprocess.TimeoutExpired as exc:
        raise ScanError(f"{cmd[0]} timed out after {timeout:.0f}s") from exc
    except OSError as exc:
        raise ScanError(f"cannot run {cmd[0]}: {exc}") from exc


def _decode(raw: bytes) -> str:
    if not raw:
        return ""
    for enc in ("utf-8", locale.getpreferredencoding(False), "cp437"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1", errors="replace")


def _first_int(text: Optional[str]) -> Optional[int]:
    m = re.search(r"-?\d+", text or "")
    return int(m.group()) if m else None


def _first_float(text: Optional[str]) -> Optional[float]:
    m = re.search(r"-?\d+(?:\.\d+)?", text or "")
    return float(m.group()) if m else None


def _band_from_channel(channel: int) -> str:
    if channel < 1:
        return ""
    if channel <= 14:
        return "2.4 GHz"
    if 32 <= channel <= 177:
        return "5 GHz"
    return "6 GHz"


def _band_from_freq(freq: int) -> str:
    if freq < 3000:
        return "2.4 GHz"
    if freq < 5925:
        return "5 GHz"
    if freq <= 7125:
        return "6 GHz"
    return ""


def _freq_from_channel(channel: int, band: str) -> Optional[int]:
    if band == "2.4 GHz":
        return 2484 if channel == 14 else 2407 + 5 * channel
    if band == "5 GHz":
        return 5000 + 5 * channel
    if band == "6 GHz":
        return 5950 + 5 * channel
    return None


def _channel_from_freq(freq: int, band: str) -> Optional[int]:
    if band == "2.4 GHz":
        return 14 if freq == 2484 else round((freq - 2407) / 5)
    if band == "5 GHz":
        return round((freq - 5000) / 5)
    if band == "6 GHz":
        return round((freq - 5950) / 5)
    return None


def _dbm_to_percent(dbm: float) -> float:
    return max(0.0, min(100.0, 2 * (dbm + 100)))


def _cipher_from_flags(flags: str) -> str:
    ciphers: List[str] = []
    for m in re.finditer(r"pairwise:\s*([^;)]+)", flags or ""):
        for c in m.group(1).split():
            if c and c not in ciphers:
                ciphers.append(c)
    return ", ".join(ciphers)


# --------------------------------------------------------------------------
# Windows: WLAN API (wlanapi.dll) with netsh fallback
#
# `netsh wlan show networks` only prints what the WLAN service has cached -- on
# Windows 11 it does not trigger a scan, so the list stays stale until the
# network flyout refreshes it.  The primary backend calls WlanScan() and waits
# for the scan-complete notification, then reads WlanGetNetworkBssList(), which
# also carries the true RSSI in dBm (WLAN_BSS_ENTRY.lRssi) that netsh omits.
# --------------------------------------------------------------------------

_NETSH_IFACE_RE = re.compile(r"^Interface name\s*:\s*(.*)$")
_NETSH_SSID_RE = re.compile(r"^SSID\s+\d+\s*:\s*(.*)$")
_NETSH_BSSID_RE = re.compile(
    r"^\s*BSSID(?:\s+\d+)?\s*:\s*([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s*$"
)
_NETSH_KEY_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 ()\-/\.]*?)\s*:\s*(.*)$")


def parse_netsh_output(text: str) -> List[Dict[str, Any]]:
    """Parse English `netsh wlan show networks mode=bssid` output."""
    records: List[Dict[str, Any]] = []
    interface = ""
    ssid = ""
    ssid_level = {"network_type": "", "security": "", "encryption": ""}
    current: Optional[Dict[str, Any]] = None

    for line in text.splitlines():
        if not line.strip():
            continue

        m = _NETSH_IFACE_RE.match(line)
        if m:
            interface = m.group(1).strip()
            current = None
            continue

        m = _NETSH_SSID_RE.match(line)
        if m:
            ssid = m.group(1).strip()
            ssid_level = {"network_type": "", "security": "", "encryption": ""}
            current = None
            continue

        m = _NETSH_BSSID_RE.match(line)
        if m:
            bssid = m.group(1).lower()
            if bssid == "00:00:00:00:00:00":  # placeholder Windows emits without scan data
                current = None
                continue
            current = {
                "ssid": ssid,
                "hidden": 1 if not ssid else 0,
                "bssid": bssid,
                "signal_percent": None,
                "signal_dbm": None,
                "channel": None,
                "frequency_mhz": None,
                "band": "",
                "radio_type": "",
                "max_rate_mbps": None,
                "security": ssid_level["security"],
                "encryption": ssid_level["encryption"],
                "network_type": ssid_level["network_type"],
                "interface": interface,
            }
            records.append(current)
            continue

        m = _NETSH_KEY_RE.match(line)
        if not m:
            continue
        key = m.group(1).strip().lower()
        value = m.group(2).strip()

        if current is None:  # keys declared once per SSID, before its BSSIDs
            if key == "network type":
                ssid_level["network_type"] = value
            elif key == "authentication":
                ssid_level["security"] = value
            elif key == "encryption":
                ssid_level["encryption"] = value
            continue

        if key == "signal":
            current["signal_percent"] = _first_int(value)
        elif key == "radio type":
            current["radio_type"] = value
        elif key == "channel":
            current["channel"] = _first_int(value)
        elif key == "band":
            current["band"] = value
        elif key.endswith("rates (mbps)"):
            rates = [float(x) for x in re.findall(r"\d+(?:\.\d+)?", value)]
            if rates and (current["max_rate_mbps"] is None or max(rates) > current["max_rate_mbps"]):
                current["max_rate_mbps"] = max(rates)

    return records


WLAN_NOTIFICATION_SOURCE_ACM = 0x00000008
WLAN_NOTIFICATION_ACM_SCAN_COMPLETE = 7
WLAN_NOTIFICATION_ACM_SCAN_FAIL = 8
DOT11_BSS_TYPE_ANY = 3

_DOT11_BSS_TYPE_NAMES = {1: "Infrastructure", 2: "Ad-hoc", 3: "Any"}
_DOT11_PHY_NAMES = {
    0: "", 1: "FHSS", 2: "DSSS", 3: "IR", 4: "802.11a", 5: "802.11b",
    6: "802.11g", 7: "802.11n", 8: "802.11ac", 9: "802.11ad",
    10: "802.11ax", 11: "802.11be",
}
_DOT11_AUTH_NAMES = {
    1: "Open", 2: "Shared", 3: "WPA-Enterprise", 4: "WPA-Personal",
    5: "WPA-None", 6: "WPA2-Enterprise", 7: "WPA2-Personal",
    8: "WPA3-Enterprise-192", 9: "WPA3-Personal", 10: "WPA3-Enterprise", 11: "OWE",
}
_DOT11_CIPHER_NAMES = {
    0: "None", 1: "WEP40", 2: "TKIP", 4: "CCMP", 5: "WEP104", 6: "BIP",
    8: "GCMP", 9: "GCMP-256", 10: "CCMP-256", 11: "BIP-GMAC-128",
    12: "BIP-GMAC-256", 13: "BIP-CMAC-256", 0x100: "Group", 0x101: "WEP",
}


class WlanApiError(ScanError):
    """A WLAN API call failed."""


class WlanApiUnavailable(WlanApiError):
    """wlanapi.dll cannot be used here (non-Windows, or library missing)."""


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _DOT11_SSID(ctypes.Structure):
    _fields_ = [("uSSIDLength", ctypes.c_uint32), ("ucSSID", ctypes.c_ubyte * 32)]


class _WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [
        ("InterfaceGuid", _GUID),
        ("strInterfaceDescription", ctypes.c_wchar * 256),
        ("isState", ctypes.c_uint32),
    ]


class _WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    _fields_ = [
        ("dwNumberOfItems", ctypes.c_uint32),
        ("dwIndex", ctypes.c_uint32),
        ("InterfaceInfo", _WLAN_INTERFACE_INFO * 1),
    ]


class _WLAN_RATE_SET(ctypes.Structure):
    _fields_ = [
        ("uRateSetLength", ctypes.c_uint32),
        ("usRateSet", ctypes.c_uint16 * 126),
    ]


class _WLAN_BSS_ENTRY(ctypes.Structure):
    _fields_ = [
        ("dot11Ssid", _DOT11_SSID),
        ("uPhyId", ctypes.c_uint32),
        ("dot11Bssid", ctypes.c_ubyte * 6),
        ("dot11BssType", ctypes.c_uint32),
        ("dot11BssPhyType", ctypes.c_uint32),
        ("lRssi", ctypes.c_int32),
        ("uLinkQuality", ctypes.c_uint32),
        ("bInRegDomain", ctypes.c_ubyte),
        ("usBeaconPeriod", ctypes.c_uint16),
        ("ullTimestamp", ctypes.c_uint64),
        ("ullHostTimestamp", ctypes.c_uint64),
        ("usCapabilityInformation", ctypes.c_uint16),
        ("ulChCenterFrequency", ctypes.c_uint32),
        ("wlanRateSet", _WLAN_RATE_SET),
        ("ulIeOffset", ctypes.c_uint32),
        ("ulIeSize", ctypes.c_uint32),
    ]


class _WLAN_BSS_LIST(ctypes.Structure):
    _fields_ = [
        ("dwTotalSize", ctypes.c_uint32),
        ("dwNumberOfItems", ctypes.c_uint32),
        ("wlanBssEntries", _WLAN_BSS_ENTRY * 1),
    ]


class _WLAN_AVAILABLE_NETWORK(ctypes.Structure):
    _fields_ = [
        ("strProfileName", ctypes.c_wchar * 256),
        ("dot11Ssid", _DOT11_SSID),
        ("dot11BssType", ctypes.c_uint32),
        ("uNumberOfBssids", ctypes.c_uint32),
        ("bNetworkConnectable", ctypes.c_uint32),
        ("wlanNotConnectableReason", ctypes.c_uint32),
        ("uNumberOfPhyTypes", ctypes.c_uint32),
        ("dot11PhyTypes", ctypes.c_uint32 * 8),
        ("bMorePhyTypes", ctypes.c_uint32),
        ("wlanSignalQuality", ctypes.c_uint32),
        ("bSecurityEnabled", ctypes.c_uint32),
        ("dot11DefaultAuthAlgorithm", ctypes.c_uint32),
        ("dot11DefaultCipherAlgorithm", ctypes.c_uint32),
        ("dwFlags", ctypes.c_uint32),
        ("dwReserved", ctypes.c_uint32),
    ]


class _WLAN_AVAILABLE_NETWORK_LIST(ctypes.Structure):
    _fields_ = [
        ("dwNumberOfItems", ctypes.c_uint32),
        ("dwIndex", ctypes.c_uint32),
        ("Network", _WLAN_AVAILABLE_NETWORK * 1),
    ]


class _WLAN_NOTIFICATION_DATA(ctypes.Structure):
    _fields_ = [
        ("NotificationSource", ctypes.c_uint32),
        ("NotificationCode", ctypes.c_uint32),
        ("InterfaceGuid", _GUID),
        ("dwDataSize", ctypes.c_uint32),
        ("pData", ctypes.c_void_p),
    ]


class _WlanApi:
    """Thin ctypes wrapper around wlanapi.dll."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise WlanApiUnavailable("the WLAN API is Windows-only")
        try:
            self.lib = ctypes.WinDLL("wlanapi")
        except OSError as exc:
            raise WlanApiUnavailable(f"cannot load wlanapi.dll: {exc}") from exc

        self.callback_type = ctypes.WINFUNCTYPE(
            None, ctypes.POINTER(_WLAN_NOTIFICATION_DATA), ctypes.c_void_p
        )
        self.null_callback = self.callback_type()

        lib = self.lib
        lib.WlanOpenHandle.argtypes = [
            ctypes.c_uint32, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_void_p),
        ]
        lib.WlanOpenHandle.restype = ctypes.c_uint32
        lib.WlanCloseHandle.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        lib.WlanCloseHandle.restype = ctypes.c_uint32
        lib.WlanEnumInterfaces.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p,
            ctypes.POINTER(ctypes.POINTER(_WLAN_INTERFACE_INFO_LIST)),
        ]
        lib.WlanEnumInterfaces.restype = ctypes.c_uint32
        lib.WlanScan.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(_GUID),
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ]
        lib.WlanScan.restype = ctypes.c_uint32
        lib.WlanRegisterNotification.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, self.callback_type,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32),
        ]
        lib.WlanRegisterNotification.restype = ctypes.c_uint32
        lib.WlanGetAvailableNetworkList.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(_GUID), ctypes.c_uint32, ctypes.c_void_p,
            ctypes.POINTER(ctypes.POINTER(_WLAN_AVAILABLE_NETWORK_LIST)),
        ]
        lib.WlanGetAvailableNetworkList.restype = ctypes.c_uint32
        lib.WlanGetNetworkBssList.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(_GUID), ctypes.c_void_p, ctypes.c_uint32,
            ctypes.c_int, ctypes.c_void_p,
            ctypes.POINTER(ctypes.POINTER(_WLAN_BSS_LIST)),
        ]
        lib.WlanGetNetworkBssList.restype = ctypes.c_uint32
        lib.WlanFreeMemory.argtypes = [ctypes.c_void_p]
        lib.WlanFreeMemory.restype = None

    def make_scan_notification_callback(self, state):
        """Return a callback that records scan_complete/scan_fail for any interface."""
        def _on_notification(data_ptr, _context):
            try:
                data = data_ptr.contents
                if data.NotificationCode in (
                    WLAN_NOTIFICATION_ACM_SCAN_COMPLETE,
                    WLAN_NOTIFICATION_ACM_SCAN_FAIL,
                ):
                    guid = data.InterfaceGuid
                    key = (guid.Data1, guid.Data2, guid.Data3, bytes(guid.Data4))
                    with state["lock"]:
                        state["finished"].add(key)
                    state["event"].set()
            except Exception:
                pass  # never let a Python exception cross the C callback boundary
        return self.callback_type(_on_notification)


_WLAN_API: Optional[_WlanApi] = None


def _wlan_api() -> _WlanApi:
    global _WLAN_API
    if _WLAN_API is None:
        _WLAN_API = _WlanApi()
    return _WLAN_API


def _wlan_err(rc: int) -> str:
    hints = {
        5: "access denied - turn on Settings > Privacy & security > Location",
        1062: "WLAN AutoConfig service (WlanSvc) is not running",
    }
    detail = f"error {rc}"
    if rc in hints:
        detail += f" ({hints[rc]})"
    return detail


def _dot11_ssid_text(value: _DOT11_SSID) -> str:
    length = int(value.uSSIDLength)
    if not 0 <= length <= 32:
        return ""  # driver artifact: not a valid 802.11 SSID length
    text = bytes(value.ucSSID[:length]).decode("utf-8", errors="replace")
    return text.split("\x00", 1)[0]  # an SSID cannot contain NUL


def _struct_array(ptr, count_field: str, array_field, struct_type) -> List[Any]:
    """Copy the trailing `T x[1]` array of a WLAN API list structure."""
    count = int(getattr(ptr.contents, count_field))
    if not count:
        return []
    base = ctypes.addressof(ptr.contents) + array_field.offset
    return list(ctypes.cast(base, ctypes.POINTER(struct_type * count)).contents)


def _wlan_interfaces(lib, handle) -> List[_WLAN_INTERFACE_INFO]:
    ptr = ctypes.POINTER(_WLAN_INTERFACE_INFO_LIST)()
    rc = lib.WlanEnumInterfaces(handle, None, ctypes.byref(ptr))
    if rc != 0:
        raise WlanApiError(f"WlanEnumInterfaces failed with {_wlan_err(rc)}")
    try:
        return _struct_array(
            ptr, "dwNumberOfItems", _WLAN_INTERFACE_INFO_LIST.InterfaceInfo,
            _WLAN_INTERFACE_INFO,
        )
    finally:
        lib.WlanFreeMemory(ptr)


def _security_map(lib, handle, guid) -> Dict[str, Any]:
    """Per-SSID default authentication/cipher, from WlanGetAvailableNetworkList."""
    ptr = ctypes.POINTER(_WLAN_AVAILABLE_NETWORK_LIST)()
    rc = lib.WlanGetAvailableNetworkList(
        handle, ctypes.byref(guid), 0, None, ctypes.byref(ptr)
    )
    if rc != 0:
        raise WlanApiError(f"WlanGetAvailableNetworkList failed with {_wlan_err(rc)}")
    try:
        entries = _struct_array(
            ptr, "dwNumberOfItems", _WLAN_AVAILABLE_NETWORK_LIST.Network,
            _WLAN_AVAILABLE_NETWORK,
        )
    finally:
        lib.WlanFreeMemory(ptr)

    result: Dict[str, Any] = {}
    for net in entries:
        ssid = _dot11_ssid_text(net.dot11Ssid)
        auth = _DOT11_AUTH_NAMES.get(int(net.dot11DefaultAuthAlgorithm), "")
        cipher = _DOT11_CIPHER_NAMES.get(int(net.dot11DefaultCipherAlgorithm), "")
        result[ssid] = (auth, cipher)
    return result


def _bss_entry_record(
    entry: _WLAN_BSS_ENTRY, security, interface: str
) -> Optional[Dict[str, Any]]:
    bssid = ":".join(f"{byte:02x}" for byte in entry.dot11Bssid)
    if bssid == "00:00:00:00:00:00":
        return None
    ssid = _dot11_ssid_text(entry.dot11Ssid)
    frequency = int(entry.ulChCenterFrequency) // 1000 or None
    band = _band_from_freq(frequency) if frequency else ""
    rate_count = min(int(entry.wlanRateSet.uRateSetLength), 126)
    rates = [
        (value & 0x7FFF) * 0.5
        for value in entry.wlanRateSet.usRateSet[:rate_count]
        if value & 0x7FFF
    ]
    authentication, encryption = security.get(ssid, ("", ""))
    return {
        "ssid": ssid,
        "hidden": 1 if not ssid else 0,
        "bssid": bssid,
        "signal_percent": int(entry.uLinkQuality) or None,
        "signal_dbm": int(entry.lRssi) or None,  # true RSSI in dBm
        "channel": _channel_from_freq(frequency, band) if frequency else None,
        "frequency_mhz": frequency,
        "band": band,
        "radio_type": _DOT11_PHY_NAMES.get(int(entry.dot11BssPhyType), ""),
        "max_rate_mbps": max(rates) if rates else None,
        "security": authentication,
        "encryption": encryption,
        "network_type": _DOT11_BSS_TYPE_NAMES.get(int(entry.dot11BssType), ""),
        "interface": interface,
    }


def _bss_list(lib, handle, guid, security, interface: str) -> List[Dict[str, Any]]:
    ptr = ctypes.POINTER(_WLAN_BSS_LIST)()
    rc = lib.WlanGetNetworkBssList(
        handle, ctypes.byref(guid), None, DOT11_BSS_TYPE_ANY, False, None,
        ctypes.byref(ptr),
    )
    if rc != 0:
        raise WlanApiError(f"WlanGetNetworkBssList failed with {_wlan_err(rc)}")
    try:
        entries = _struct_array(
            ptr, "dwNumberOfItems", _WLAN_BSS_LIST.wlanBssEntries, _WLAN_BSS_ENTRY
        )
    finally:
        lib.WlanFreeMemory(ptr)
    records = []
    for entry in entries:
        record = _bss_entry_record(entry, security, interface)
        if record:
            records.append(record)
    return records


def scan_windows_wlanapi(rescan: bool = True):
    """Force a scan through the WLAN API; returns (records, warnings)."""
    api = _wlan_api()
    lib = api.lib
    handle = ctypes.c_void_p()
    negotiated = ctypes.c_uint32()
    rc = lib.WlanOpenHandle(2, None, ctypes.byref(negotiated), ctypes.byref(handle))
    if rc != 0:
        raise WlanApiError(f"WlanOpenHandle failed with {_wlan_err(rc)}")
    try:
        interfaces = _wlan_interfaces(lib, handle)
        if not interfaces:
            raise WlanApiError("no wireless interface found")
        targets = [
            (info.InterfaceGuid, info.strInterfaceDescription or "wireless adapter")
            for info in interfaces
        ]

        warnings: List[str] = []
        state = {"finished": set(), "lock": threading.Lock(), "event": threading.Event()}
        callback = api.make_scan_notification_callback(state)  # keep the reference alive
        previous = ctypes.c_uint32()
        registered = lib.WlanRegisterNotification(
            handle, WLAN_NOTIFICATION_SOURCE_ACM, True, callback, None, None,
            ctypes.byref(previous),
        ) == 0
        try:
            pending = 0
            if rescan:
                for guid, description in targets:
                    rc = lib.WlanScan(handle, ctypes.byref(guid), None, None, None)
                    if rc != 0:
                        warnings.append(f"{description}: WlanScan failed with {_wlan_err(rc)}")
                    else:
                        pending += 1
            if pending:
                if registered:
                    deadline = time.monotonic() + 10.0
                    while len(state["finished"]) < pending and time.monotonic() < deadline:
                        state["event"].clear()
                        state["event"].wait(0.25)
                else:
                    time.sleep(2.0)  # no notifications available; let the scan settle

            records: List[Dict[str, Any]] = []
            for guid, description in targets:
                try:
                    security = _security_map(lib, handle, guid)
                except WlanApiError as exc:
                    warnings.append(f"{description}: {exc}")
                    security = {}
                try:
                    records.extend(_bss_list(lib, handle, guid, security, description))
                except WlanApiError as exc:
                    warnings.append(f"{description}: {exc}")
            if not records:
                raise WlanApiError("the WLAN API returned no visible networks")
            return records, warnings
        finally:
            if registered:
                lib.WlanRegisterNotification(
                    handle, 0, False, api.null_callback, None, None, None
                )
    finally:
        lib.WlanCloseHandle(handle, None)


def scan_windows_netsh() -> List[Dict[str, Any]]:
    """Fallback: parse `netsh wlan show networks mode=bssid` (cached results)."""
    exe = shutil.which("netsh") or shutil.which("netsh.exe")
    if not exe:
        raise ScanError("netsh not found; run on Windows or pass --backend for another platform")
    proc = _run([exe, "wlan", "show", "networks", "mode=bssid"], timeout=25)
    out = _decode(proc.stdout)
    err = _decode(proc.stderr)
    records = parse_netsh_output(out)
    if not records:
        detail = (out.strip() or err.strip() or "no output")[:400]
        raise ScanError(
            "netsh reported no visible networks.\n"
            "Check: Wi-Fi adapter enabled, WLAN AutoConfig service running, and\n"
            "(on Windows 11) Settings > Privacy & security > Location turned on.\n"
            f"netsh said: {detail}"
        )
    return records


def scan_windows(rescan: bool = True) -> List[Dict[str, Any]]:
    problems: List[str] = []
    try:
        records, warnings = scan_windows_wlanapi(rescan=rescan)
        for warning in warnings:
            print(f"note: {warning}", file=sys.stderr)
        return records
    except WlanApiUnavailable as exc:
        problems.append(f"WLAN API unavailable: {exc}")
    except WlanApiError as exc:
        problems.append(f"WLAN API scan failed: {exc}")

    try:
        records = scan_windows_netsh()
    except ScanError as exc:
        problems.append(str(exc))
        records = []
    if records:
        print(
            "note: fell back to `netsh wlan show networks` (cached list; dBm "
            "estimated from signal %)",
            file=sys.stderr,
        )
        return records

    raise ScanError(
        "\n".join(problems)
        + "\nHints: Wi-Fi adapter enabled, WLAN AutoConfig service running, and\n"
        "(on Windows 11) Settings > Privacy & security > Location turned on."
    )


# --------------------------------------------------------------------------
# Linux: nmcli
# --------------------------------------------------------------------------


def _split_terse(line: str) -> List[str]:
    """Split nmcli --terse output on colons that are neither escaped nor inside
    brackets.  Escaping alone is not enough: WPA/RSN flag groups such as
    ``(pairwise: CCMP; group: CCMP)`` contain raw colons on some nmcli builds."""
    fields: List[str] = []
    buf: List[str] = []
    escaped = False
    depth = 0
    for ch in line:
        if escaped:
            buf.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch in "([{":
            depth += 1
            buf.append(ch)
        elif ch in ")]}":
            depth = max(0, depth - 1)
            buf.append(ch)
        elif ch == ":" and depth == 0:
            fields.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if escaped:
        buf.append("\\")
    fields.append("".join(buf))
    return fields


def parse_nmcli_output(text: str) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    nfields = len(NMCLI_FIELDS.split(","))
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = _split_terse(line)
        if len(fields) < nfields:
            continue
        ssid, bssid, chan, freq, rate, signal, _bars, security, wpa, rsn, device = fields[:11]
        if not bssid or bssid == "--":
            continue
        hidden = 0
        if not ssid or ssid == "--":
            ssid, hidden = "", 1
        records.append(
            {
                "ssid": ssid,
                "hidden": hidden,
                "bssid": bssid.lower(),
                "signal_percent": _first_int(signal),
                "signal_dbm": None,
                "channel": _first_int(chan),
                "frequency_mhz": _first_int(freq),
                "band": "",
                "radio_type": "",
                "max_rate_mbps": _first_float(rate),
                "security": "" if security in ("", "--") else security,
                "encryption": _cipher_from_flags(rsn) or _cipher_from_flags(wpa),
                "network_type": "Infrastructure",
                "interface": device,
            }
        )
    return records


def scan_linux(rescan: bool = True) -> List[Dict[str, Any]]:
    exe = shutil.which("nmcli")
    if exe is None:
        if shutil.which("netsh.exe"):  # WSL with a Windows Wi-Fi adapter
            return scan_windows()
        raise ScanError("nmcli not found (install NetworkManager); no netsh.exe fallback either")

    cmd = [exe, "-t", "-f", NMCLI_FIELDS, "device", "wifi", "list"]
    if rescan:
        cmd += ["--rescan", "yes"]
    proc = _run(cmd, timeout=60)
    out = _decode(proc.stdout)
    err = _decode(proc.stderr)
    records = parse_nmcli_output(out)
    if not records:
        detail = (err.strip() or out.strip() or "no output")[:400]
        raise ScanError(f"nmcli returned no visible networks.\nnmcli said: {detail}")
    return records


# --------------------------------------------------------------------------
# macOS: airport -s
# --------------------------------------------------------------------------

_AIRPORT_LINE_RE = re.compile(
    r"^(?P<ssid>.*?)\s+"
    r"(?P<bssid>[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s+"
    r"(?P<rssi>-?\d+)\s+"
    r"(?P<chan>\d+)(?:,[+-]\d+)?\s+"
    r"(?P<rest>.*)$"
)


def parse_airport_output(text: str) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for line in text.splitlines():
        m = _AIRPORT_LINE_RE.match(line.rstrip())
        if not m:
            continue
        ssid = m.group("ssid").strip()
        tokens = m.group("rest").split()
        if tokens and tokens[0] in ("Y", "N"):  # HT capability column
            tokens = tokens[1:]
        if tokens and re.fullmatch(r"[A-Za-z]{2}|--", tokens[0]):  # country code
            tokens = tokens[1:]
        security = " ".join(tokens)

        auth, encryption = security, ""
        sm = re.match(r"([A-Za-z0-9\-]+)\(([^)]*)\)", security)
        if sm:
            parts = [p.strip() for p in sm.group(2).split("/")]
            auth = sm.group(1)
            if "PSK" in parts:
                auth += "-Personal"
            elif "MGT" in parts or "802.1X" in parts:
                auth += "-Enterprise"
            if len(parts) > 1:
                encryption = parts[1]

        rssi = int(m.group("rssi"))
        records.append(
            {
                "ssid": ssid,
                "hidden": 1 if not ssid else 0,
                "bssid": m.group("bssid").lower(),
                "signal_percent": round(_dbm_to_percent(rssi)),
                "signal_dbm": rssi,
                "channel": int(m.group("chan")),
                "frequency_mhz": None,
                "band": "",
                "radio_type": "",
                "max_rate_mbps": None,
                "security": auth,
                "encryption": encryption,
                "network_type": "Infrastructure",
                "interface": "",
            }
        )
    return records


def scan_macos() -> List[Dict[str, Any]]:
    if not os.path.exists(AIRPORT_PATH):
        raise ScanError(
            "the airport utility is unavailable (Apple removed it in recent macOS);\n"
            "run this script on Windows/Linux or use a supported scan tool"
        )
    proc = _run([AIRPORT_PATH, "-s"], timeout=30)
    out = _decode(proc.stdout)
    records = parse_airport_output(out)
    if not records:
        raise ScanError(f"airport returned no visible networks.\nairport said: {out.strip()[:400]}")
    return records


# --------------------------------------------------------------------------
# dispatch, enrichment, output
# --------------------------------------------------------------------------


def select_backend(requested: str) -> str:
    if requested != "auto":
        return requested
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    if system == "darwin":
        return "macos"
    return "linux"


def scan(backend: str, rescan: bool = True) -> List[Dict[str, Any]]:
    if backend == "windows":
        return scan_windows(rescan=rescan)
    if backend == "macos":
        return scan_macos()
    return scan_linux(rescan=rescan)


def finalize(records: List[Dict[str, Any]], location: str) -> List[Dict[str, Any]]:
    """Stamp scan metadata and derive band/frequency/signal fields where missing."""
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    for rec in records:
        rec["timestamp"] = timestamp
        rec["location"] = location
        # drivers occasionally return control characters in SSIDs: keep the
        # table and CSV parseable
        ssid = rec.get("ssid")
        if ssid:
            rec["ssid"] = "".join(ch if ch.isprintable() else "?" for ch in ssid)

        channel, freq = rec.get("channel"), rec.get("frequency_mhz")
        if channel and not freq:
            if not rec.get("band"):
                # netsh has no band column: channels 32-177 map to 5 GHz,
                # everything above to 6 GHz (best effort; 6 GHz reuses
                # low channel numbers, so a 6 GHz AP on ch <= 177 shows as 5 GHz).
                rec["band"] = _band_from_channel(channel)
            estimated = _freq_from_channel(channel, rec.get("band") or "")
            if estimated:
                rec["frequency_mhz"] = estimated
        elif freq and not rec.get("band"):
            rec["band"] = _band_from_freq(freq)

        pct, dbm = rec.get("signal_percent"), rec.get("signal_dbm")
        if pct is not None and dbm is None:
            rec["signal_dbm"] = round(pct / 2 - 100)  # -50 dBm .. -100 dBm
        elif dbm is not None and pct is None:
            rec["signal_percent"] = round(_dbm_to_percent(dbm))
    return records


def filter_records(
    records: List[Dict[str, Any]],
    ssid_patterns: Optional[Sequence[str]] = None,
    channels: Optional[Set[int]] = None,
    bands: Optional[Set[str]] = None,
) -> List[Dict[str, Any]]:
    """Keep records matching every given filter.

    SSID patterns are case-insensitive and may use * and ? wildcards; a pattern
    without wildcards is an exact-name match.  Records without a known channel
    (or band) are dropped once that filter is set.  Hidden networks (empty
    SSID) only match wildcard patterns such as "*".
    """
    selected = []
    for rec in records:
        if ssid_patterns:
            ssid = str(rec.get("ssid") or "")
            if not any(
                fnmatch.fnmatchcase(ssid.casefold(), pattern.casefold())
                for pattern in ssid_patterns
            ):
                continue
        if channels and rec.get("channel") not in channels:
            continue
        if bands and rec.get("band") not in bands:
            continue
        selected.append(rec)
    return selected


# --------------------------------------------------------------------------
# OUI vendor identification (BSSID -> access point make/brand)
# --------------------------------------------------------------------------

OUI_REGISTRY_URL = "https://standards-oui.ieee.org/oui/oui.csv"


def _parse_oui_text(text: str) -> Dict[str, str]:
    """Parse an IEEE registry CSV (Registry, Assignment, Organization Name,...)."""
    entries: Dict[str, str] = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 3 or row[0] == "Registry":
            continue
        assignment = re.sub(r"[^0-9A-Fa-f]", "", row[1]).upper()
        name = row[2].strip()
        if assignment and name:
            entries[assignment] = name
    return entries


def lookup_vendor(bssid: str, entries: Dict[str, str]) -> str:
    """Map a BSSID to its vendor name; '' when the OUI is unknown."""
    hexmac = re.sub(r"[^0-9a-fA-F]", "", bssid or "").upper()
    if len(hexmac) < 12:
        return ""
    if int(hexmac[:2], 16) & 0x02:  # locally administered bit: randomized MAC
        return "Randomized MAC"
    for size in (9, 7, 6):  # MA-S (36-bit), MA-M (28-bit), MA-L (24-bit)
        name = entries.get(hexmac[:size])
        if name:
            return name
    return ""


def annotate_vendors(
    records: List[Dict[str, Any]], entries: Dict[str, str]
) -> List[Dict[str, Any]]:
    cache: Dict[str, str] = {}
    for rec in records:
        bssid = str(rec.get("bssid") or "")
        if bssid not in cache:
            cache[bssid] = lookup_vendor(bssid, entries)
        rec["vendor"] = cache[bssid]
    return records


def _app_dir() -> Path:
    """Directory that owns runtime data (the oui.csv cache).

    Frozen builds (PyInstaller onefile) run from a temporary extraction
    directory that disappears on exit, so data files belong next to the
    executable instead of next to the module.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def _bundled_oui() -> Optional[Path]:
    """oui.csv shipped inside the executable as a data file, if any."""
    base = getattr(sys, "_MEIPASS", None)
    if not base:
        return None
    candidate = Path(base) / "oui.csv"
    return candidate if candidate.is_file() else None


def _seed_bundled_oui(cache: Path) -> Path:
    """Materialise the bundled OUI registry next to the executable.

    Returns the path to read from: the cache when it exists or was just
    seeded, otherwise the bundled copy (read-only install directory), and
    finally the plain cache path so the caller reports 'unavailable'.
    """
    if cache.exists() and cache.stat().st_size:
        return cache
    bundled = _bundled_oui()
    if bundled is None:
        return cache
    try:
        temp = cache.with_name(cache.name + ".part")
        temp.write_bytes(bundled.read_bytes())
        os.replace(temp, cache)
    except OSError:
        return bundled
    return cache


def _download_oui(url: str, destination: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "wifi-scanner/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read()
    except (urllib.error.URLError, OSError) as exc:
        raise ScanError(f"cannot download OUI registry from {url}: {exc}") from exc
    if not data:
        raise ScanError(f"OUI registry download from {url} returned no data")
    temp = destination.with_name(destination.name + ".part")
    try:
        temp.write_bytes(data)
        os.replace(temp, destination)
    except OSError as exc:
        raise ScanError(f"cannot write OUI registry to {destination}: {exc}") from exc


def load_oui_database(
    path_override: Optional[str], url: str, update: bool
) -> Tuple[Dict[str, str], Optional[str]]:
    """Return (entries, note): --oui-file, else the oui.csv cache next to the
    script (or executable), else the built-in subset.  --update-oui
    re-downloads first."""
    cache = (
        Path(path_override).expanduser()
        if path_override
        else _seed_bundled_oui(_app_dir() / "oui.csv")
    )
    if path_override and not update and not cache.exists():
        raise ScanError(f"OUI database not found: {cache}")
    note = None
    if update:
        _download_oui(url, cache)
        note = f"OUI registry updated: {cache}"
    elif not (cache.exists() and cache.stat().st_size):
        return {}, (
            "vendors unavailable: no OUI registry cached "
            "(run --update-oui to fetch the IEEE registry); "
            "randomized MACs are still labelled"
        )
    try:
        text = cache.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ScanError(f"cannot read OUI registry {cache}: {exc}") from exc
    entries = _parse_oui_text(text)
    if not entries:
        if path_override:
            raise ScanError(f"no OUI entries found in {cache}")
        return {}, f"{cache} contained no OUI entries; vendor lookup disabled"
    return entries, note


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def render_table(records: List[Dict[str, Any]]) -> str:
    headers = [header for _, header, _, _ in TABLE_COLUMNS]
    rows: List[List[str]] = []
    for rec in records:
        row = []
        for key, _, _, cap in TABLE_COLUMNS:
            text = _cell(rec.get(key))
            if key == "ssid" and not text and rec.get("hidden"):
                text = "<hidden>"
            if cap and len(text) > cap:
                text = text[: cap - 2] + ".."
            row.append(text)
        rows.append(row)

    widths = [
        max(len(headers[i]), *(len(row[i]) for row in rows)) if rows else len(headers[i])
        for i in range(len(headers))
    ]
    lines = [
        "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)),
        "  ".join("-" * w for w in widths),
    ]
    for row in rows:
        lines.append(
            "  ".join(
                cell.rjust(widths[i]) if TABLE_COLUMNS[i][2] == "right" else cell.ljust(widths[i])
                for i, cell in enumerate(row)
            )
        )
    return "\n".join(lines)


def prepare_csv(path: Path) -> Optional[str]:
    """Validate the CSV header, migrating known older layouts in place.

    Returns a note describing the migration, or None when nothing changed.
    """
    if not path.exists() or path.stat().st_size == 0:
        return None
    try:
        with path.open("r", newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            header = reader.fieldnames
            rows = (
                list(reader)
                if header is not None and tuple(header) in _LEGACY_CSV_HEADER_TUPLES
                else None
            )
    except OSError as exc:
        raise ScanError(f"cannot read {path}: {exc}") from exc
    if header == list(CSV_FIELDS):
        return None
    if header is not None and rows is not None:
        try:
            with path.open("w", newline="", encoding="utf-8-sig") as handle:
                writer = csv.DictWriter(
                    handle, fieldnames=CSV_FIELDS, extrasaction="ignore"
                )
                writer.writeheader()
                writer.writerows(rows)
        except OSError as exc:
            raise ScanError(f"cannot migrate {path}: {exc}") from exc
        return f"migrated {path} to the current column layout (added 'vendor')"
    raise ScanError(
        f"{path} has an incompatible header; use a different --csv file or rename it"
    )


def append_csv(path: Path, records: List[Dict[str, Any]]) -> bool:
    """Append records; returns True when the header (and file) was created."""
    is_new = not path.exists() or path.stat().st_size == 0
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    encoding = "utf-8-sig" if is_new else "utf-8"
    with path.open("a", newline="", encoding=encoding) as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, extrasaction="ignore")
        if is_new:
            writer.writeheader()
        writer.writerows(records)
    return is_new


def prompt_location() -> str:
    try:
        while True:
            location = input("Enter scan location (e.g. Home, Office-3F): ").strip()
            if location:
                return location
            print("Location cannot be empty.")
    except (EOFError, KeyboardInterrupt):
        print("\nNo location provided; rerun with --location.", file=sys.stderr)
        raise SystemExit(2)


def _strip_quotes(value: str) -> str:
    """Tolerate quotes that cmd.exe/PowerShell pass through literally."""
    value = value.strip()
    while len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        value = value[1:-1].strip()
    return value


def _ssid_filter(value: str) -> str:
    """argparse type for --ssid: strips shell-literal quotes."""
    return _strip_quotes(value)


_BAND_ALIASES = {
    "2.4": "2.4 GHz", "2.4ghz": "2.4 GHz", "2.4g": "2.4 GHz", "2ghz": "2.4 GHz",
    "5": "5 GHz", "5ghz": "5 GHz", "5g": "5 GHz",
    "6": "6 GHz", "6ghz": "6 GHz", "6g": "6 GHz",
}


def _band_filter(value: str) -> Set[str]:
    """argparse type for --band: '2.4', '5 GHz', '6', comma-separated allowed."""
    bands: Set[str] = set()
    for part in _strip_quotes(value).split(","):
        key = part.strip().lower().replace(" ", "")
        if not key:
            continue
        if key not in _BAND_ALIASES:
            raise argparse.ArgumentTypeError(
                f"invalid band: {part.strip()!r} (use 2.4, 5 or 6)"
            )
        bands.add(_BAND_ALIASES[key])
    if not bands:
        raise argparse.ArgumentTypeError("no bands given")
    return bands


def _channel_filter(value: str) -> Set[int]:
    """argparse type for --channel: '6', '1,6,11', '1-14' or combinations."""
    channels: Set[int] = set()
    for part in _strip_quotes(value).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            low, _, high = part.partition("-")
            if not (low.strip().isdigit() and high.strip().isdigit()):
                raise argparse.ArgumentTypeError(f"invalid channel range: {part!r}")
            low_number, high_number = int(low), int(high)
            if low_number < 1 or high_number < low_number:
                raise argparse.ArgumentTypeError(f"invalid channel range: {part!r}")
            channels.update(range(low_number, high_number + 1))
        elif part.isdigit() and int(part) > 0:
            channels.add(int(part))
        else:
            raise argparse.ArgumentTypeError(f"invalid channel: {part!r}")
    if not channels:
        raise argparse.ArgumentTypeError("no channels given")
    return channels


def _describe_filters(
    ssid_patterns: Optional[Sequence[str]],
    channels: Optional[Set[int]],
    bands: Optional[Set[str]],
) -> str:
    parts = []
    if ssid_patterns:
        parts.append("ssid=" + ",".join(ssid_patterns))
    if bands:
        parts.append("band=" + ",".join(sorted(bands)))
    if channels:
        parts.append("channels=" + ",".join(str(c) for c in sorted(channels)))
    return "; ".join(parts)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan Wi-Fi networks, print a table, and append results to a CSV file."
    )
    parser.add_argument(
        "-l", "--location", help="scan location label; skips the interactive prompt"
    )
    parser.add_argument(
        "--csv",
        default=DEFAULT_CSV,
        help=f"CSV file to append to (default: {DEFAULT_CSV})",
    )
    parser.add_argument(
        "--backend",
        choices=("auto", "windows", "linux", "macos"),
        default="auto",
        help="force a specific scan backend (default: auto-detect)",
    )
    parser.add_argument(
        "--oui-file",
        metavar="PATH",
        help="OUI registry CSV to use instead of the cached oui.csv",
    )
    parser.add_argument(
        "--oui-url",
        metavar="URL",
        default=OUI_REGISTRY_URL,
        help=f"OUI registry URL used by --update-oui (default: {OUI_REGISTRY_URL})",
    )
    parser.add_argument(
        "--update-oui",
        action="store_true",
        help="download the full IEEE OUI registry to oui.csv next to the "
        "script/executable",
    )
    parser.add_argument(
        "-s",
        "--ssid",
        action="append",
        type=_ssid_filter,
        metavar="NAME",
        help="only include networks whose SSID matches NAME (case-insensitive; "
        "* and ? wildcards allowed; repeat for multiple patterns; surrounding "
        "quotes are tolerated)",
    )
    parser.add_argument(
        "-b",
        "--band",
        action="append",
        type=_band_filter,
        metavar="BAND",
        help="only include networks on these bands: 2.4, 5 or 6 (GHz suffix "
        "optional; repeatable, comma-separated allowed)",
    )
    parser.add_argument(
        "-c",
        "--channel",
        action="append",
        type=_channel_filter,
        metavar="LIST",
        help="only include networks on these channels, e.g. 6 / 1,6,11 / 1-14 "
        "(repeatable)",
    )
    parser.add_argument(
        "--no-rescan",
        action="store_true",
        help="use cached results instead of triggering a fresh scan "
        "(Windows WLAN API and Linux/nmcli)",
    )
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    location = args.location if args.location is not None else prompt_location()
    csv_path = Path(args.csv).expanduser()
    channels = set().union(*args.channel) if args.channel else None
    bands = set().union(*args.band) if args.band else None

    try:
        migration = prepare_csv(csv_path)
        if migration:
            print(f"note: {migration}", file=sys.stderr)
        oui_entries, oui_note = load_oui_database(
            args.oui_file, args.oui_url, args.update_oui
        )
        if oui_note:
            print(f"note: {oui_note}", file=sys.stderr)
        backend = select_backend(args.backend)
        print(f"Scanning wireless networks ({backend})...")
        records = scan(backend, rescan=not args.no_rescan)
        if not records:
            print("No wireless networks found.", file=sys.stderr)
            return 1
        scanned = len(records)
        records = filter_records(records, args.ssid, channels, bands)
        if not records:
            print(
                "No networks matched the filter "
                f"({_describe_filters(args.ssid, channels, bands)}); "
                f"scanned {scanned} BSSID(s).",
                file=sys.stderr,
            )
            return 1
        finalize(records, location)
        annotate_vendors(records, oui_entries)
        records.sort(key=lambda r: r.get("signal_percent") or -1, reverse=True)
        created = append_csv(csv_path, records)
    except ScanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    if scanned != len(records):
        print(
            f"Filter ({_describe_filters(args.ssid, channels, bands)}) "
            f"kept {len(records)} of {scanned} BSSID(s)."
        )

    visible_ssids = {r["ssid"] for r in records if r["ssid"]}
    print(
        f"\nFound {len(records)} BSSID(s) across {len(visible_ssids)} SSID(s) "
        f"at location '{location}':\n"
    )
    print(render_table(records))
    print(
        f"\n{'Created' if created else 'Appended to'} {csv_path.resolve()} "
        f"({len(records)} row(s), header {'written' if created else 'already present'})."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
