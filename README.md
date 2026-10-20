# PowerScan

A network scanner that runs from one line of PowerShell. No install, no modules, no admin rights.

```powershell
& ([scriptblock]::Create((irm "https://raw.githubusercontent.com/kevinmcgillicuddy/PowerScan/main/PowerScan.ps1")))
```

That opens a window, detects the subnet you're on, and starts scanning. For a table in the console instead:

```powershell
& ([scriptblock]::Create((irm "https://raw.githubusercontent.com/kevinmcgillicuddy/PowerScan/main/PowerScan.ps1"))) --nogui
```

## What it finds

For every host that answers: IP address, reverse-DNS hostname, MAC address, hardware vendor, ping latency, and optionally which TCP ports are open.

```
IP Address      Hostname                  MAC                 Vendor           ms  Open Ports
----------      --------                  ---                 ------           --  ----------
192.168.1.1     router.lan                34:60:F9:1C:2E:08   TP-Link           1  80, 443
192.168.1.14    NAS01.lan                 00:11:32:5A:7B:C1   Synology          2  22, 80, 445
192.168.1.52    DESKTOP-K4F2.lan          B8:CA:3A:19:04:7E   Dell              3  135, 445, 3389
192.168.1.88    pi-hole.lan               B8:27:EB:3D:91:AA   Raspberry Pi      4  22, 80
```

## Options

**Every option is optional.** Run PowerScan with no arguments at all and it opens the GUI, works out which subnet you're on, and scans it.

| Option | Default | What it does |
|---|---|---|
| `-Range`, `-r` | the subnet of whichever adapter holds your default gateway | What to scan. CIDR (`192.168.1.0/24`), a dashed range (`192.168.1.10-50`, `10.0.0.250-10.0.1.20`), a single IP, or a comma-separated mix. |
| `-Ports`, `-p` | none tested | TCP ports to test on each live host: `22,80,443,3389`. Ranges work too: `8000-8010`. |
| `--nogui`, `-NoGui` | off — GUI opens | Print a table to the console instead of opening the window. |
| `-TimeoutMs` | `400` | Per-host ICMP timeout. Raise it on slow links, lower it on a fast LAN. |
| `-Concurrency` | `64` | How many hosts are pinged at once. |
| `-NoDns` | off | Skip reverse DNS. Noticeably faster on subnets with no local DNS server. |
| `-NoMac` | off | Skip MAC and vendor resolution. |
| `-ExportCsv` | off | Also write the results to a CSV path. |
| `-Help`, `-h` | — | Usage. |

Two conveniences worth knowing:

- **Range and ports are positional**, in that order, so `PowerScan.ps1 192.168.1.0/24 22,443` does what it looks like.
- **Both `--nogui` and `-NoGui` work**, so muscle memory from other CLI tools doesn't bite. The same goes for `--range`, `--ports`, `--nodns`, `--nomac`, `--csv` and `--help`, including the `--range=10.0.0.0/24` form.

### Examples

```powershell
# Console table for a specific subnet, checking the usual remote-access ports
.\PowerScan.ps1 --nogui -Range 10.0.0.0/24 -Ports 22,80,443,3389

# Same thing, positionally
.\PowerScan.ps1 10.0.0.0/24 22,80,443,3389 --nogui

# Fast sweep, no name resolution, straight to CSV
.\PowerScan.ps1 --nogui -Range 192.168.1.1-254 -NoDns -ExportCsv .\site-audit.csv

# GUI, pre-pointed at a range you don't live on
.\PowerScan.ps1 -Range 172.16.4.0/22
```

Passing arguments through the one-liner works the same way — they bind to the downloaded script's `param()` block:

```powershell
& ([scriptblock]::Create((irm "https://raw.githubusercontent.com/kevinmcgillicuddy/PowerScan/main/PowerScan.ps1"))) --nogui -Range 10.0.0.0/24 -Ports 445
```

## The GUI

Follows your Windows light/dark setting. Columns are click-to-sort, rows are multi-select, and **Copy** puts a tab-separated block on the clipboard that pastes straight into a ticket or a spreadsheet. **Export CSV** writes a file. Results stream in as hosts answer rather than appearing all at once, and **Stop** aborts a sweep mid-run.

## Requirements

- Windows PowerShell 5.1 (ships with Windows) or PowerShell 7+
- Nothing else — no modules, no admin rights

The GUI needs WPF on an STA thread, which is the default under `powershell.exe`. If you're in PowerShell 7 and the window won't open, use `pwsh -STA` or just run with `--nogui`. On Server Core, where WPF isn't present, the script detects it and falls back to console output on its own.

If `irm` fails on an older build, TLS 1.2 isn't the default there:

```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; & ([scriptblock]::Create((irm "https://raw.githubusercontent.com/kevinmcgillicuddy/PowerScan/main/PowerScan.ps1")))
```

## How it works

Everything lives in one file so the one-liner stays a one-liner.

- **The one-liner.** `iex` can't accept parameters, so the script is compiled with `[scriptblock]::Create()` and invoked with `&`. Arguments then bind to its `param()` block like any other script. (Same trick [Win11Debloat](https://github.com/Raphire/Win11Debloat) uses.)
- **Discovery.** Async `Ping.SendPingAsync` — a whole batch is launched before any reply is awaited, so a /24 sweeps in a couple of seconds rather than a couple of minutes.
- **Enrichment.** Once a batch answers, reverse DNS and TCP connects fire concurrently for the whole batch, and the MAC comes out of the Windows neighbor cache (`Get-NetNeighbor`, falling back to `arp.exe`) while the entries are still warm from the ping.
- **Vendors.** An OUI prefix table is built into the script, so there's no API call and no rate limit. Locally administered addresses are labelled as such rather than guessed at.
- **The window.** WPF built from XAML held as a string and parsed with `XamlReader.Load()`, with `shell:WindowChrome` for the custom title bar.
- **Responsiveness.** The scan runs in a background runspace and pushes results onto a `ConcurrentQueue`. A `DispatcherTimer` on the UI thread drains that queue into the bound collection, so the window never blocks and every control touch stays on the dispatcher thread.

## A note on use

This is a diagnostic tool for networks you're responsible for. Ping sweeps and port probes look like reconnaissance to an IDS — scan your own estate, or one you've been engaged to assess.

## License

MIT
