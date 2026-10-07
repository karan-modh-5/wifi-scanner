# wifi-scanner

Scan nearby Wi-Fi networks, print a readable details table, and append every
visible access point (one row per BSSID) to a CSV history file.

Runs as a **standalone Windows executable** (no Python needed) or from source
on Windows, Linux and macOS.

## Features

- **Real scans, not the OS cache.** On Windows the scanner calls the WLAN API
  (`WlanScan` + scan-complete notification, then `WlanGetNetworkBssList`), so
  results are fresh and carry the true RSSI in dBm; `netsh wlan show networks`
  is only a fallback. Linux uses `nmcli device wifi list --rescan yes`,
  macOS uses `airport -s`.
- **CSV history.** Header written once, then one row per BSSID per scan, with
  timestamp, location label, band, channel, frequency, signal, security
  details, radio type and interface. Older column layouts are migrated in
  place.
- **Vendor identification.** Every BSSID is resolved against the IEEE OUI
  registry (`oui.csv`), including MA-M/MA-S (28/36-bit) prefixes and
  "Randomized MAC" detection for locally administered addresses.
- **Filters.** Narrow the table and the CSV rows by SSID pattern, band or
  channel.

## Quick start (Windows executable)

1. Download `wifi-scanner.exe` from the [latest release](../../releases/latest).
2. Run it — double-click, or from a terminal:

   ```
   wifi-scanner.exe --location "Office 3F"
   ```

   Without `--location` the scanner asks for a location label interactively.

The executable writes `wifi_networks.csv` in the working directory and seeds
`oui.csv` (bundled inside the release build) next to itself on first run, so
vendor names work offline.

## Run from source

Only the Python standard library is required (Python 3.8+; developed on 3.14).

```
python wifi_scanner.py
python wifi_scanner.py --location "Office 3F" --csv scans/office.csv
python wifi_scanner.py -c 1,6,11            # channel filter
python wifi_scanner.py -b 5                 # band filter: 2.4 / 5 / 6
python wifi_scanner.py -s "Home*" -s Office # SSID filter, repeatable
python wifi_scanner.py --update-oui         # refresh the IEEE OUI registry
```

The first run without a cached `oui.csv` downloads the IEEE registry once
(see [OUI vendor data](#oui-vendor-data)); add `--no-oui-download` to skip it.

`-s/--ssid`, `-b/--band` and `-c/--channel` combine with AND and apply to both
the printed table and the appended CSV rows; the platform scan itself always
sweeps all channels, since no public API exposes a channel-limited scan.
Surrounding quotes in filter values are stripped, so `-s "Home*"` behaves the
same from `cmd.exe`, PowerShell and POSIX shells.

## Options

| Option | Description |
| --- | --- |
| `-l`, `--location LABEL` | Scan location label; skips the interactive prompt. |
| `--csv PATH` | CSV file to append to (default: `wifi_networks.csv`). |
| `--backend {auto,windows,linux,macos}` | Force a scan backend (default: auto-detect). |
| `-s`, `--ssid PATTERN` | Keep networks whose SSID matches (case-insensitive, `*`/`?` wildcards, repeatable). |
| `-b`, `--band BAND` | Keep networks on 2.4, 5 or 6 GHz (repeatable, comma-separated). |
| `-c`, `--channel LIST` | Keep networks on these channels, e.g. `6`, `1,6,11`, `1-14` (repeatable). |
| `--no-rescan` | Use cached results instead of triggering a fresh scan (Windows WLAN API and Linux/nmcli). |
| `--oui-file PATH` | Use a specific IEEE OUI registry CSV. |
| `--oui-url URL` | Registry URL used for the first-run download and `--update-oui` (default: the IEEE registry). |
| `--update-oui` | Download the full IEEE OUI registry to `oui.csv`. |
| `--no-oui-download` | Never download the registry (offline machines; vendor names stay empty). |

Exit codes: `0` success, `1` no networks found / nothing matched the filter,
`2` no location provided, `3` scan error.

## Printed table

```
SSID                          BSSID              VENDOR                    SIG%  dBm   CH    MHz  BAND     SECURITY             CIPHER        RADIO        RATE
----------------------------  -----------------  ------------------------  ----  ---  ---  -----  -------  -------------------  ------------  ----------  -----
HomeNet                       aa:bb:cc:dd:ee:01  TP-Link                  78   -61    6   2437  2.4 GHz  WPA2-Personal        CCMP         802.11n        144
HomeNet                       aa:bb:cc:dd:ee:02  TP-Link                  54   -73   44   5220  5 GHz    WPA2-Personal        CCMP         802.11ac       866
```

When a backend reports only one of the two signal fields, the other is
derived: `percent = 2 * (dBm + 100)` clamped to 0–100, and
`dBm = percent / 2 - 100`. Hidden networks are shown as `<hidden>` when the
backend reports an empty SSID.

## CSV columns

| Column | Description |
| --- | --- |
| `timestamp` | Local scan time, ISO 8601 with UTC offset, e.g. `2026-10-07T09:30:44+05:30`. |
| `location` | Location label given on the command line or at the prompt. |
| `ssid` | Network name (empty for hidden networks). |
| `hidden` | `1` when the SSID is not broadcast, else `0`. |
| `bssid` | Access point MAC address. |
| `vendor` | OUI owner (make/brand) or `Randomized MAC`. |
| `signal_percent` | Signal quality, 0–100. |
| `signal_dbm` | Raw RSSI in dBm (Windows WLAN API and Linux). |
| `channel` | Wi-Fi channel. |
| `frequency_mhz` | Center frequency in MHz. |
| `band` | `2.4 GHz`, `5 GHz` or `6 GHz`. |
| `radio_type` | PHY, e.g. `802.11n`, `802.11ac`, `802.11ax`. |
| `max_rate_mbps` | Max PHY rate in Mbps. |
| `security` | Authentication, e.g. `WPA2-Personal`, `Open`. |
| `encryption` | Cipher, e.g. `CCMP`, `TKIP`. |
| `network_type` | `Infrastructure` or `Ad-hoc`. |
| `interface` | Wireless interface that saw the network. |

## Backends

| Platform | Backend | Notes |
| --- | --- | --- |
| Windows | WLAN API via `ctypes` | Real scan, true dBm RSSI, exact frequency. |
| Windows | `netsh wlan show networks mode=bssid` | Fallback; returns the WLAN service cache only. Also used under WSL. |
| Linux | `nmcli device wifi list --rescan yes` | Requires NetworkManager. |
| macOS | `airport -s` | Apple deprecated the `airport` utility in macOS 14. |

## OUI vendor data

Vendor names come from the IEEE registry CSV (`Registry, Assignment,
Organization Name, ...`), cached as `oui.csv` next to the script (next to the
`.exe` in frozen builds). The scanner fetches it automatically the first time
it runs without a cache (~4 MB, one request to the IEEE registry URL), and
prints which file it wrote:

```
note: OUI registry downloaded: /path/to/oui.csv
```

- `--no-oui-download` skips that fetch for offline machines: `vendor` stays
  empty for normal OUIs, randomized addresses are still labelled.
- `--update-oui` re-downloads the registry on demand (annual refresh).
- `--oui-url URL` points the download at a mirror.
- `--oui-file PATH` uses an existing registry CSV instead of the cache.
- If the download fails the scan still runs and prints a note saying vendor
  names are unavailable.

The Windows release build has `oui.csv` bundled inside the executable: it is
unpacked next to the `.exe` on first run, so release users never trigger the
download (a read-only install directory falls back to reading the bundled
copy). `oui.csv` is deliberately not committed to this repository — it is
regenerated from the upstream URL.

This tool is for auditing your own networks and for passive site surveys;
use it only where you are authorized to do so.

## Building the executable

```
python -m pip install -r requirements-build.txt
python build.py                 # extra flags are forwarded to PyInstaller
```

Result: `dist/wifi-scanner.exe` (Windows) or `dist/wifi-scanner`
(Linux/macOS). Put `oui.csv` next to `wifi_scanner.py` beforehand to bundle
the vendor registry; `build.py` warns when it is missing.

Build inputs: `wifi_scanner.spec` (PyInstaller description) and
`version_info.txt` (Windows version resource).

### Releases via GitHub Actions

`.github/workflows/build.yml` builds the Windows executable on every push and
pull request, uploads it as the `wifi-scanner-windows-x64` artifact, and
attaches it to a GitHub Release when a `v*` tag is pushed:

```
git tag v1.0.0
git push origin v1.0.0
```

## Project layout

```
wifi_scanner.py       scanner: backends, parsing, filters, CSV and table output
build.py              builds the standalone executable
wifi_scanner.spec     PyInstaller build description
version_info.txt      Windows version resource for the executable
requirements-build.txt build-time dependency (PyInstaller)
.github/workflows/    CI: build + release the Windows executable
```

## License

[MIT](LICENSE)
