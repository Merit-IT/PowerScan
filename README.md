# PowerScan

A network scanner that runs from one line of PowerShell. No install, no modules, no admin rights.

```powershell
& ([scriptblock]::Create((irm "https://github.com/kevinmcgillicuddy/PowerScan/releases/latest/download/PowerScan.ps1")))
```

That opens a window, detects the subnet you're on, and starts scanning. For a table in the console instead:

```powershell
& ([scriptblock]::Create((irm "https://github.com/kevinmcgillicuddy/PowerScan/releases/latest/download/PowerScan.ps1"))) -NoGui
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
| `-NoGui`, `-c` | off — GUI opens | Print a table to the console instead of opening the window. |
| `-TimeoutMs` | `400` | Per-host ICMP timeout. Raise it on slow links, lower it on a fast LAN. |
| `-Concurrency` | `64` | How many hosts are pinged at once. |
| `-NoDns` | off | Skip reverse DNS. Noticeably faster on subnets with no local DNS server. |
| `-NoMac` | off | Skip MAC and vendor resolution. |
| `-OfflineVendors`, `-Offline` | off | Never call the vendor API; use the built-in OUI table only. |
| `-ExportCsv` | off | Also write the results to a CSV path. |
| `-Help`, `-h` | — | Usage. |
| `-Version`, `-v` | — | Print the version and exit. |

**Range and ports are positional**, in that order, so `PowerScan.ps1 192.168.1.0/24 22,443` does what it looks like. Everything else is a normal PowerShell switch, with the usual short aliases (`-r`, `-p`, `-c`, `-h`) and prefix matching, so `-NoG` and `-Off` work too.

### Examples

```powershell
# Console table for a specific subnet, checking the usual remote-access ports
.\PowerScan.ps1 -NoGui -Range 10.0.0.0/24 -Ports 22,80,443,3389

# Same thing, positionally
.\PowerScan.ps1 10.0.0.0/24 22,80,443,3389 -NoGui

# Fast sweep, no name resolution, straight to CSV
.\PowerScan.ps1 -NoGui -Range 192.168.1.1-254 -NoDns -ExportCsv .\site-audit.csv

# GUI, pre-pointed at a range you don't live on
.\PowerScan.ps1 -Range 172.16.4.0/22
```

Passing arguments through the one-liner works the same way — they bind to the downloaded script's `param()` block:

```powershell
& ([scriptblock]::Create((irm "https://github.com/kevinmcgillicuddy/PowerScan/releases/latest/download/PowerScan.ps1"))) -NoGui -Range 10.0.0.0/24 -Ports 445
```

## The GUI

Follows your Windows light/dark setting. Columns are click-to-sort, rows are multi-select, and **Copy** puts a tab-separated block on the clipboard that pastes straight into a ticket or a spreadsheet. **Export CSV** writes a file. Results stream in as hosts answer rather than appearing all at once, and **Stop** aborts a sweep mid-run.

## Requirements

- Windows PowerShell 5.1 (ships with Windows) or PowerShell 7+
- Nothing else — no modules, no admin rights

The GUI needs WPF on an STA thread, which is the default under `powershell.exe`. If you're in PowerShell 7 and the window won't open, use `pwsh -STA` or just run with `-NoGui`. On Server Core, where WPF isn't present, the script detects it and falls back to console output on its own.

If `irm` fails on an older build, TLS 1.2 isn't the default there:

```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; & ([scriptblock]::Create((irm "https://github.com/kevinmcgillicuddy/PowerScan/releases/latest/download/PowerScan.ps1")))
```

## How it works

Everything lives in one file so the one-liner stays a one-liner.

- **The one-liner.** `iex` can't accept parameters, so the script is compiled with `[scriptblock]::Create()` and invoked with `&`. Arguments then bind to its `param()` block like any other script. (Same trick [Win11Debloat](https://github.com/Raphire/Win11Debloat) uses.)
- **Discovery.** Async `Ping.SendPingAsync` — a whole batch is launched before any reply is awaited, so a /24 sweeps in a couple of seconds rather than a couple of minutes.
- **Enrichment.** Once a batch answers, reverse DNS and TCP connects fire concurrently for the whole batch, and the MAC comes out of the Windows neighbor cache (`Get-NetNeighbor`, falling back to `arp.exe`) while the entries are still warm from the ping.
- **Vendors.** Looked up against [api.macadress.com](https://macadress.com/free-mac-address-api), which needs no key, with a built-in OUI table as the fallback. See below.
- **The window.** WPF built from XAML held as a string and parsed with `XamlReader.Load()`, with `shell:WindowChrome` for the custom title bar.
- **Responsiveness.** The scan runs in a background runspace and pushes results onto a `ConcurrentQueue`. A `DispatcherTimer` on the UI thread drains that queue into the bound collection, so the window never blocks and every control touch stays on the dispatcher thread.

## Vendor lookup

Vendor names come from [api.macadress.com](https://macadress.com/free-mac-address-api) — no key, no signup. If it can't be reached, PowerScan silently falls back to an OUI table built into the script and carries on.

Details that matter in practice:

- **Only the OUI is sent.** PowerScan transmits the 6-hex manufacturer prefix (`B827EB`), never a full MAC address. The prefix identifies Raspberry Pi; it doesn't identify a device. Nothing that could fingerprint a specific machine leaves the network you're scanning.
- **One call per vendor, not per host.** Results are cached by OUI for the duration of a scan, so a /24 full of Dell desktops costs a single request.
- **First failure is the last.** DNS failure, no route, a proxy block, a timeout, or a `429` trips a circuit breaker, and the rest of the scan uses the table without touching the network again. An air-gapped scan of six unique vendors costs one failed request and about 0.16s, not six timeouts.
- **Rate limits** are 60 requests/minute and 1,000/day per IP without a key. With per-OUI caching you are very unlikely to reach either.
- **`-OfflineVendors`** skips the API entirely, for sites that would rather make no outbound calls at all.

The built-in table carries ~150 common prefixes and is deliberately kept, so the tool stays useful on an isolated network. The API gives fuller names where it's reachable — `Apple, Inc.` and `Raspberry Pi Foundation` rather than the table's `Apple` and `Raspberry Pi`.

## Releases and the short URL

The one-liner points at **`/releases/latest/download/PowerScan.ps1`**, not at `main`. That matters: with a raw-`main` link, every push lands in a technician's elevated prompt the moment it's committed. With a release, you tag deliberately, and rolling back is moving a tag.

Cutting a release is pushing a tag:

```powershell
git tag v1.0.1
git push origin v1.0.1
```

[`release.yml`](.github/workflows/release.yml) then checks the script parses, checks `$PowerScanVersion` agrees with the tag, smoke-tests both the console path and the `scriptblock` path a technician actually uses, and only then publishes. A tag that disagrees with the version in the script fails the build rather than shipping a file that misreports itself.

To put it behind your own hostname, a 301 is all it takes — this is exactly what Win11Debloat's `debloat.raphi.re` does:

```
https://scanner.example.com/  →  301  →
https://github.com/kevinmcgillicuddy/PowerScan/releases/latest/download/PowerScan.ps1
```

`irm` follows the redirect, and release assets come back as `application/octet-stream` but still arrive as a `String`, so `[scriptblock]::Create()` is happy. On Cloudflare that's a proxied DNS record plus one Redirect Rule, no Worker required.

Worth knowing before you point a domain at this: that DNS record becomes a path to elevated code execution on every machine that runs the one-liner. Whoever can edit it can run anything as administrator. Lock the account down accordingly.

## A note on use

This is a diagnostic tool for networks you're responsible for. Ping sweeps and port probes look like reconnaissance to an IDS — scan your own estate, or one you've been engaged to assess.

## License

MIT
