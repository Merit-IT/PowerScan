<#
.SYNOPSIS
    PowerScan - a single-file PowerShell IP scanner with a WPF GUI.

    No installs, no dependencies, no modules

.DESCRIPTION
    Scans a subnet with ICMP pings, then checks each live host with
    reverse DNS, MAC address and vendor, plus an optional TCP port check. 
    Results render in a WPF grid, or as a plain table when run with -NoGui.

    No modules, no installs, no dependencies beyond Windows PowerShell 5.1.

.PARAMETER Range
    What to scan. Accepts CIDR (192.168.1.0/24), a dashed range
    (192.168.1.10-50 or 192.168.1.10-192.168.2.20), a single IP, or a
    comma-separated mix. Defaults to the subnet of the adapter holding the
    default gateway.

.PARAMETER NoGui
    Skip the window and print results to the console as a table.

.PARAMETER Ports
    Comma-separated TCP ports to test on every live host, e.g. '22,80,443,3389'.

.PARAMETER TimeoutMs
    Per-host ICMP timeout in milliseconds. Default 400.

.PARAMETER Concurrency
    How many hosts are pinged at once. Default 64.

.PARAMETER NoDns
    Skip reverse DNS lookups (noticeably faster on subnets without a local DNS server).

.PARAMETER NoMac
    Skip MAC address / vendor resolution.

.PARAMETER OfflineVendors
    Never call api.macadress.com; resolve vendors from the built-in OUI table
    only. The script falls back to that table on its own if the API cannot be
    reached, so this is for air-gapped networks and for sites that would rather
    make no outbound calls at all.

.PARAMETER ExportCsv
    Write results to this path as CSV. Works in both modes.

.EXAMPLE
    .\PowerScan.ps1
    Opens the GUI, pre-filled with the local subnet.

.EXAMPLE
    .\PowerScan.ps1 -NoGui -Range 10.0.0.0/24 -Ports 22,80,443,3389
    Prints a table of live hosts and which of those ports are open.

.LINK
    https://github.com/Merit-IT/PowerScan
#>
[CmdletBinding()]
param(

    [Parameter(Position = 0)]
    [Alias('r', 'Subnet', 'Target')]
    [string]$Range,

    [Alias('c', 'Console', 'Cli')]
    [switch]$NoGui,

    [Parameter(Position = 1)]
    [Alias('p')]
    [string]$Ports,

    [int]$TimeoutMs = 400,

    [int]$Concurrency = 64,

    [switch]$NoDns,

    [switch]$NoMac,

    # Vendor names come from the API by default; this forces the built-in table.
    [Alias('NoVendorApi', 'Offline')]
    [switch]$OfflineVendors,

    [Alias('Csv')]
    [string]$ExportCsv,

    [Alias('h', '?')]
    [switch]$Help,

    [Alias('v')]
    [switch]$Version
)

$ErrorActionPreference = 'Stop'

# Single source of truth for the version. The release workflow refuses to
# publish a tag whose name disagrees with this, so a released file can never
# misreport which build it is.
$PowerScanVersion = '1.0.0'

if ($Version) {
    Write-Host $PowerScanVersion
    return
}

# A positional value that looks like a switch is a mistyped parameter.
#
# This matters most through the one-liner. `powershell.exe -File x.ps1 --nogui`
# rewrites --nogui to -nogui and binds the switch, but
# `& ([scriptblock]::Create(...)) --nogui` uses expression-mode binding, which
# does no such rewriting -- so "--nogui" lands in -Range as a positional
# string. Without this check the window opens with a nonsense range and the
# mistake looks like the switch being ignored.
foreach ($positional in @(
        @{ Name = 'Range'; Value = $Range },
        @{ Name = 'Ports'; Value = $Ports })) {

    if ($positional.Value -like '-*') {
        Write-Host ''
        Write-Host "'$($positional.Value)' was taken as the -$($positional.Name) value, not as a switch." -ForegroundColor Red
        Write-Host 'PowerScan uses ordinary PowerShell switches, single dash:' -ForegroundColor DarkGray
        Write-Host '  -NoGui  -NoDns  -NoMac  -OfflineVendors  -Help' -ForegroundColor DarkGray
        Write-Host ''
        return
    }
}

if ($Help) {
    Write-Host ''
    Write-Host "PowerScan $PowerScanVersion - PowerShell IP scanner with a WPF GUI"
    Write-Host @'

USAGE
  PowerScan.ps1 [[-Range] <range>] [[-Ports] <list>] [-NoGui] [-TimeoutMs <n>]
                [-Concurrency <n>] [-NoDns] [-NoMac] [-ExportCsv <path>]

  Every option is optional. With no arguments at all, PowerScan opens the
  GUI and scans the subnet you are on.

  Range and ports may also be given positionally, in that order:
      PowerScan.ps1 192.168.1.0/24 22,443

OPTIONS                                                      (all optional)
  -Range, -r        Positional 1. CIDR (192.168.1.0/24), dashed range
                    (192.168.1.10-50), a single IP, or a comma-separated
                    mix. Default: the subnet holding your default gateway.
  -Ports, -p        Positional 2. TCP ports to test on live hosts,
                    e.g. 22,80,443,3389. Default: none tested.
  -NoGui, -c        Print a table to the console instead of opening the window.
  -TimeoutMs        Per-host ICMP timeout. Default 400.
  -Concurrency      Hosts pinged at once. Default 64.
  -NoDns / -NoMac   Skip reverse DNS / MAC+vendor resolution.
  -OfflineVendors   Never call the vendor API; use the built-in OUI table.
  -ExportCsv        Also write the results to this CSV path.
  -Version, -v      Print the version and exit.

EXAMPLES
  PowerScan.ps1
  PowerScan.ps1 -NoGui
  PowerScan.ps1 -NoGui -Range 10.0.0.0/24 -Ports 22,80,443,3389
  PowerScan.ps1 10.0.0.0/24 22,80,443,3389 -NoGui
  PowerScan.ps1 -Range 192.168.1.1-254 -ExportCsv .\scan.csv

'@
    return
}

# ===========================================================================
# Scanner library
#
# Kept as a string so the exact same code can be dot-sourced into this
# session (CLI mode) and into the background runspace that drives the GUI.
# ===========================================================================
$ScannerLib = @'
function ConvertTo-IpUInt32 {
    param([string]$IpAddress)
    $bytes = ([System.Net.IPAddress]::Parse($IpAddress)).GetAddressBytes()
    [Array]::Reverse($bytes)
    [System.BitConverter]::ToUInt32($bytes, 0)
}

function ConvertFrom-IpUInt32 {
    param([uint32]$Value)
    $bytes = [System.BitConverter]::GetBytes($Value)
    [Array]::Reverse($bytes)
    (New-Object System.Net.IPAddress(, $bytes)).IPAddressToString
}

<#
    Returns the CIDR of the adapter that owns the default gateway, so the GUI
    and the CLI both open on something sensible without being told.
#>
function Get-DefaultScanRange {
    $best = $null

    foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($nic.OperationalStatus -ne 'Up') { continue }
        if ($nic.NetworkInterfaceType -eq 'Loopback') { continue }
        if ($nic.NetworkInterfaceType -eq 'Tunnel') { continue }

        $props = $nic.GetIPProperties()
        $hasGateway = @($props.GatewayAddresses | Where-Object {
            $_.Address.AddressFamily -eq 'InterNetwork' -and $_.Address.IPAddressToString -ne '0.0.0.0'
        }).Count -gt 0

        foreach ($unicast in $props.UnicastAddresses) {
            if ($unicast.Address.AddressFamily -ne 'InterNetwork') { continue }

            $ip = $unicast.Address.IPAddressToString
            if ($ip -match '^(127\.|169\.254\.)') { continue }

            $mask = $null
            try { $mask = $unicast.IPv4Mask } catch { }
            if (-not $mask -or $mask.IPAddressToString -eq '0.0.0.0') { continue }

            $maskValue = ConvertTo-IpUInt32 $mask.IPAddressToString
            $prefix = 0
            for ($bit = 31; $bit -ge 0; $bit--) {
                if (($maskValue -shr $bit) -band 1) { $prefix++ } else { break }
            }
            if ($prefix -lt 16 -or $prefix -gt 30) { continue }

            $network = (ConvertTo-IpUInt32 $ip) -band $maskValue
            $candidate = [pscustomobject]@{
                Cidr       = "$(ConvertFrom-IpUInt32 $network)/$prefix"
                HasGateway = $hasGateway
            }

            # An adapter with a default gateway always wins.
            if ($hasGateway) { return $candidate.Cidr }
            if (-not $best) { $best = $candidate }
        }
    }

    if ($best) { return $best.Cidr }
    return '192.168.1.0/24'
}

<#
    Expands CIDR / dashed-range / single-IP notation into a flat list of
    addresses. Comma-separated inputs are expanded and de-duplicated.
#>
function Expand-ScanRange {
    param([string]$Range)

    if ([string]::IsNullOrWhiteSpace($Range)) { throw 'No scan range supplied.' }

    $addresses = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'

    foreach ($part in ($Range -split '[,;]')) {
        $piece = $part.Trim()
        if (-not $piece) { continue }

        $first = $null
        $last = $null

        if ($piece -match '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') {
            $base = ConvertTo-IpUInt32 $matches[1]
            $prefix = [int]$matches[2]
            if ($prefix -lt 8 -or $prefix -gt 32) { throw "Prefix /$prefix is out of range (expected /8 to /32)." }

            $mask = if ($prefix -eq 0) { [uint32]0 } else { [uint32](([uint64]0xFFFFFFFFL -shl (32 - $prefix)) -band 0xFFFFFFFFL) }
            $network = $base -band $mask
            $broadcast = $network -bor (-bnot $mask -band 0xFFFFFFFFL)

            # Skip network and broadcast addresses on anything wider than a /31.
            $first = if ($prefix -le 30) { $network + 1 } else { $network }
            $last  = if ($prefix -le 30) { $broadcast - 1 } else { $broadcast }
        }
        elseif ($piece -match '^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})$') {
            $first = ConvertTo-IpUInt32 $matches[1]
            $last  = ConvertTo-IpUInt32 $matches[2]
        }
        elseif ($piece -match '^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})\s*-\s*(\d{1,3})$') {
            $first = ConvertTo-IpUInt32 "$($matches[1]).$($matches[2])"
            $last  = ConvertTo-IpUInt32 "$($matches[1]).$($matches[3])"
        }
        elseif ($piece -match '^\d{1,3}(?:\.\d{1,3}){3}$') {
            $first = ConvertTo-IpUInt32 $piece
            $last  = $first
        }
        else {
            throw "Could not parse '$piece'. Use 192.168.1.0/24, 192.168.1.10-50 or a single IP."
        }

        if ($last -lt $first) { $first, $last = $last, $first }
        if (($last - $first) -gt 65535) { throw "'$piece' covers more than 65536 addresses; narrow it down." }

        for ($value = $first; $value -le $last; $value++) {
            $ip = ConvertFrom-IpUInt32 $value
            if ($seen.Add($ip)) { $addresses.Add($ip) }
            if ($value -eq [uint32]::MaxValue) { break }
        }
    }

    , $addresses.ToArray()
}

<#
    IP -> MAC map from the Windows neighbor cache. Called right after a ping
    batch, while the entries are still fresh.
#>
function Get-ArpMap {
    $map = @{}

    try {
        foreach ($entry in (Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop)) {
            if ($entry.State -in @('Unreachable', 'Incomplete', 'Permanent')) { continue }
            if (-not $entry.LinkLayerAddress) { continue }
            if ($entry.LinkLayerAddress -eq '00-00-00-00-00-00') { continue }
            $map[[string]$entry.IPAddress] = ($entry.LinkLayerAddress -replace '[-:]', '').ToUpperInvariant()
        }
    }
    catch {
        # Get-NetNeighbor is unavailable on older builds and in some restricted
        # runspaces; arp.exe has been there since forever.
        foreach ($line in (& arp.exe -a 2>$null)) {
            if ($line -match '^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})') {
                $map[$matches[1]] = ($matches[2] -replace '[-:]', '').ToUpperInvariant()
            }
        }
    }

    $map
}

$global:PowerScanOui = @{
    '000569' = 'VMware';        '000C29' = 'VMware';        '001C14' = 'VMware'
    '005056' = 'VMware';        '000F4B' = 'Oracle';        '080027' = 'VirtualBox'
    '00155D' = 'Microsoft Hyper-V'; '00125A' = 'Microsoft'; '0017FA' = 'Microsoft'
    '001DD8' = 'Microsoft';     '28187C' = 'Microsoft';     '7C1E52' = 'Microsoft'
    '00037F' = 'Atheros';       '000D93' = 'Apple';         '001451' = 'Apple'
    '0017F2' = 'Apple';         '001EC2' = 'Apple';         '002608' = 'Apple'
    '3C0754' = 'Apple';         '40331A' = 'Apple';         '7CD1C3' = 'Apple'
    'A45E60' = 'Apple';         'F0189E' = 'Apple';         'DC2B2A' = 'Apple'
    '001018' = 'Broadcom';      '00102F' = 'Cisco';         '001120' = 'Cisco'
    '00000C' = 'Cisco';         '0050F0' = 'Cisco';         '00E0FC' = 'Huawei'
    '001882' = 'Huawei';        '48D539' = 'Huawei';        '001B63' = 'Apple'
    '000E08' = 'Cisco-Linksys'; '001217' = 'Cisco-Linksys'; '002369' = 'Cisco-Linksys'
    '00095B' = 'Netgear';       '000FB5' = 'Netgear';       '0024B2' = 'Netgear'
    '20E52A' = 'Netgear';       '001195' = 'D-Link';        '00179A' = 'D-Link'
    '1CBDB9' = 'D-Link';        '0015E9' = 'D-Link';        '001D7E' = 'Cisco-Linksys'
    '0005CD' = 'Denon';         '001E58' = 'D-Link';        '000502' = 'Apple'
    '00904C' = 'Epigram';       '001CF0' = 'D-Link';        '0026F2' = 'Netgear'
    '000FEA' = 'Giga-Byte';     '001A4D' = 'Giga-Byte';     '1C6F65' = 'Giga-Byte'
    '0019DB' = 'Micro-Star';    '00163E' = 'Xensource';     '525400' = 'QEMU/KVM'
    '001B21' = 'Intel';         '001E67' = 'Intel';         '0022FB' = 'Intel'
    '3C9772' = 'Intel';         '7085C2' = 'ASRock';        '94DE80' = 'Giga-Byte'
    '001517' = 'Intel';         '0CC47A' = 'Super Micro';   '003048' = 'Super Micro'
    'B827EB' = 'Raspberry Pi';  'DCA632' = 'Raspberry Pi';  'E45F01' = 'Raspberry Pi'
    '2CCF67' = 'Raspberry Pi';  '001132' = 'Synology';      '0011D8' = 'ASUSTek'
    '00248C' = 'ASUSTek';       '2C56DC' = 'ASUSTek';       '08BFB8' = 'ASUSTek'
    '001E8C' = 'ASUSTek';       '000423' = 'Intel';         '001377' = 'Samsung'
    '002454' = 'Samsung';       '78BDBC' = 'Samsung';       '001632' = 'Samsung'
    '0021CC' = 'Hon Hai';       '002564' = 'Dell';          '00188B' = 'Dell'
    '001E4F' = 'Dell';          'B8CA3A' = 'Dell';          'D067E5' = 'Dell'
    '0017A4' = 'Hewlett Packard'; '001871' = 'Hewlett Packard'; '002655' = 'Hewlett Packard'
    '3863BB' = 'Hewlett Packard'; '9457A5' = 'Hewlett Packard'; '00215A' = 'Hewlett Packard'
    '001B78' = 'Hewlett Packard'; '000D9D' = 'Hewlett Packard'; '001279' = 'Hewlett Packard'
    '0004F2' = 'Polycom';       '00096E' = 'Avaya';         '001B4F' = 'Avaya'
    '0060B9' = 'NEC';           '00037A' = 'Yamaha';        '001C73' = 'Arista'
    '000B86' = 'Aruba';         '6CF37F' = 'Aruba';         '186472' = 'Aruba'
    '245A4C' = 'Ubiquiti';      '788A20' = 'Ubiquiti';      '802AA8' = 'Ubiquiti'
    'FCECDA' = 'Ubiquiti';      '24A43C' = 'Ubiquiti';      '0418D6' = 'Ubiquiti'
    '74ACB9' = 'Ubiquiti';      '9C05D6' = 'Ubiquiti';      'E063DA' = 'Ubiquiti'
    'B4FBE4' = 'Ubiquiti';      '002722' = 'Ubiquiti';      '687251' = 'Ubiquiti'
    '0009B0' = 'Onkyo';         'EC0D9A' = 'Mellanox';      '0002C9' = 'Mellanox'
    '001CC4' = 'Hewlett Packard'; '001A1E' = 'Aruba';       '000BFD' = 'Cisco'
    '001CB3' = 'Apple';         '000A27' = 'Apple';         'ACDE48' = 'Private'
    '001D0F' = 'TP-Link';       '14CC20' = 'TP-Link';       '50C7BF' = 'TP-Link'
    'A42BB0' = 'TP-Link';       'C46E1F' = 'TP-Link';       '98DED0' = 'TP-Link'
    'E8DE27' = 'TP-Link';       '0C8063' = 'TP-Link';       '647002' = 'TP-Link'
    '00E04C' = 'Realtek';       '52540C' = 'QEMU/KVM';      '001A11' = 'Google'
    '3C5AB4' = 'Google';        '94EB2C' = 'Google';        'F4F5D8' = 'Google'
    '001AA0' = 'Dell';          'F8BC12' = 'Dell';          '18DBF2' = 'Dell'
    '00224D' = 'Dell';          '0014BF' = 'Cisco-Linksys'; '002129' = 'Cisco-Linksys'
    '001AEF' = 'Loxley';        '0C9D92' = 'ASUSTek';       '1458D0' = 'Hewlett Packard'
}

# Resolved OUIs for this scan, so a subnet full of one vendor costs one call.
$global:PowerScanVendorCache = @{}

# Trips on the first transport failure or 429, after which the scan stops
# reaching for the network and rides the table above for the rest of the run.
$global:PowerScanApiDown = $false

<#
    Looks an OUI up against api.macadress.com.

    Returns a vendor string when the API answers definitively (including an
    empty string for an unregistered prefix), or $null when the API could not
    be reached, which is the caller's signal to fall back to the table.

    Only the 6-hex manufacturer prefix is ever sent - never a full MAC - so no
    device identifier leaves the network being scanned.
#>
function Get-MacVendorFromApi {
    param([string]$Oui)

    if ($global:PowerScanApiDown) { return $null }

    try {
        # Windows PowerShell 5.1 still defaults to TLS 1.0 on some builds.
        if ([Net.ServicePointManager]::SecurityProtocol -notmatch 'Tls12') {
            [Net.ServicePointManager]::SecurityProtocol =
                [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        }
    }
    catch { }

    try {
        $response = Invoke-WebRequest -Uri "https://api.macadress.com/v1/vendor/$Oui" `
            -TimeoutSec 4 -UseBasicParsing -UserAgent 'PowerScan' -ErrorAction Stop
        return ([string]$response.Content).Trim()
    }
    catch {
        $status = 0
        try { $status = [int]$_.Exception.Response.StatusCode } catch { }

        # The error body is on ErrorDetails in PS7 and on the response stream in 5.1.
        $body = ''
        try {
            $body = [string]$_.ErrorDetails.Message
            if (-not $body -and $_.Exception.Response) {
                $stream = $_.Exception.Response.GetResponseStream()
                $body = (New-Object System.IO.StreamReader($stream)).ReadToEnd()
            }
        }
        catch { }

        switch ($status) {
            400 { return '' }                                 # malformed - nothing to find
            404 {
                if ($body -match 'locally administered') { return 'Locally administered' }
                return ''                                      # valid, simply not registered
            }
            default {
                # 429, DNS failure, no route, proxy block, timeout: stop trying.
                $global:PowerScanApiDown = $true
                return $null
            }
        }
    }
}

function Get-MacVendor {
    param(
        [string]$Mac,
        [bool]$UseApi = $true
    )

    if ([string]::IsNullOrWhiteSpace($Mac) -or $Mac.Length -lt 6) { return '' }

    $oui = $Mac.Substring(0, 6).ToUpperInvariant()
    if ($global:PowerScanVendorCache.ContainsKey($oui)) { return $global:PowerScanVendorCache[$oui] }

    $vendor = $null
    if ($UseApi) { $vendor = Get-MacVendorFromApi $oui }

    if ($null -eq $vendor) {
        # Offline: the built-in table, then the locally-administered bit (the
        # second-least-significant of the first octet), which is worth flagging
        # because the OUI carries no meaning on those addresses.
        if ($global:PowerScanOui.ContainsKey($oui)) {
            $vendor = $global:PowerScanOui[$oui]
        }
        elseif ([Convert]::ToInt32($Mac.Substring(0, 2), 16) -band 2) {
            $vendor = 'Locally administered'
        }
        else {
            $vendor = ''
        }
    }

    $global:PowerScanVendorCache[$oui] = $vendor
    return $vendor
}

function Format-MacAddress {
    param([string]$Mac)
    if ([string]::IsNullOrWhiteSpace($Mac)) { return '' }
    (($Mac -split '(.{2})' | Where-Object { $_ }) -join ':')
}

<#
    Scans every address in -Targets and pushes a result object onto
    $State.Queue as soon as a host answers, so a caller can render live.

    $State is a synchronized hashtable with: Queue (ConcurrentQueue), Total,
    Done, Found, Cancel, Running, Error.
#>
function Invoke-IpScan {
    param(
        [string[]]$Targets,
        [int]$TimeoutMs = 400,
        [int]$Concurrency = 64,
        [int[]]$PortList = @(),
        [bool]$ResolveDns = $true,
        [bool]$ResolveMac = $true,
        [bool]$UseVendorApi = $true,
        $State
    )

    $State.Total = $Targets.Count
    $State.Done = 0
    $State.Found = 0

    $dnsTimeoutMs = [Math]::Max(500, $TimeoutMs)
    $portTimeoutMs = [Math]::Max(600, $TimeoutMs)

    for ($offset = 0; $offset -lt $Targets.Count; $offset += $Concurrency) {
        if ($State.Cancel) { break }

        $end = [Math]::Min($offset + $Concurrency - 1, $Targets.Count - 1)
        $batch = $Targets[$offset..$end]

        # --- Fire every ping in the batch before awaiting any of them ---
        $pings = foreach ($ip in $batch) {
            $pinger = New-Object System.Net.NetworkInformation.Ping
            [pscustomobject]@{
                Ip     = $ip
                Pinger = $pinger
                Task   = $pinger.SendPingAsync($ip, $TimeoutMs)
            }
        }

        $alive = New-Object System.Collections.Generic.List[object]
        foreach ($ping in $pings) {
            try {
                $reply = $ping.Task.GetAwaiter().GetResult()
                if ($reply.Status -eq 'Success') {
                    $alive.Add([pscustomobject]@{ Ip = $ping.Ip; Latency = [int]$reply.RoundtripTime })
                }
            }
            catch { }
            finally { $ping.Pinger.Dispose() }

            $State.Done = $State.Done + 1
        }

        if ($alive.Count -eq 0) { continue }

        $arp = if ($ResolveMac) { Get-ArpMap } else { @{} }

        # --- Start every enrichment task, then collect ---
        $dnsTasks = @{}
        if ($ResolveDns) {
            foreach ($node in $alive) {
                try { $dnsTasks[$node.Ip] = [System.Net.Dns]::GetHostEntryAsync($node.Ip) } catch { }
            }
        }

        $portTasks = @{}
        if ($PortList.Count -gt 0) {
            foreach ($node in $alive) {
                $perHost = foreach ($port in $PortList) {
                    $client = New-Object System.Net.Sockets.TcpClient
                    [pscustomobject]@{
                        Port   = $port
                        Client = $client
                        Task   = $client.ConnectAsync($node.Ip, $port)
                    }
                }
                $portTasks[$node.Ip] = @($perHost)
            }
        }

        foreach ($node in $alive) {
            $hostname = ''
            if ($dnsTasks.ContainsKey($node.Ip)) {
                try {
                    if ($dnsTasks[$node.Ip].Wait($dnsTimeoutMs)) {
                        $hostname = $dnsTasks[$node.Ip].Result.HostName
                    }
                }
                catch { }
            }

            $openPorts = @()
            if ($portTasks.ContainsKey($node.Ip)) {
                foreach ($attempt in $portTasks[$node.Ip]) {
                    try {
                        if ($attempt.Task.Wait($portTimeoutMs) -and $attempt.Client.Connected) {
                            $openPorts += $attempt.Port
                        }
                    }
                    catch { }
                    finally { try { $attempt.Client.Close() } catch { } }
                }
            }

            $mac = if ($arp.ContainsKey($node.Ip)) { $arp[$node.Ip] } else { '' }

            $State.Found = $State.Found + 1
            $State.Queue.Enqueue([pscustomobject]@{
                IPAddress = $node.Ip
                Hostname  = $hostname
                MAC       = Format-MacAddress $mac
                Vendor    = Get-MacVendor -Mac $mac -UseApi $UseVendorApi
                LatencyMs = $node.Latency
                OpenPorts = (($openPorts | Sort-Object) -join ', ')
                SortKey   = ConvertTo-IpUInt32 $node.Ip
            })
        }
    }
}
'@

. ([scriptblock]::Create($ScannerLib))

function New-ScanState {
    $state = [hashtable]::Synchronized(@{})
    $state.Queue   = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
    $state.Total   = 0
    $state.Done    = 0
    $state.Found   = 0
    $state.Cancel  = $false
    $state.Running = $true
    $state.Error   = $null
    $state
}

function ConvertTo-PortList {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return @() }

    $ports = foreach ($token in ($Value -split '[,;\s]+')) {
        if (-not $token) { continue }
        if ($token -match '^(\d+)\s*-\s*(\d+)$') {
            [int]$matches[1]..[int]$matches[2]
        }
        else {
            [int]$token
        }
    }

    @($ports | Where-Object { $_ -ge 1 -and $_ -le 65535 } | Sort-Object -Unique)
}

# ===========================================================================
# Console mode
# ===========================================================================
function Invoke-ConsoleScan {
    param([string]$Range, [int[]]$PortList)

    $targets = Expand-ScanRange $Range
    $state = New-ScanState

    Write-Host ''
    Write-Host "PowerScan $PowerScanVersion" -ForegroundColor DarkGray
    Write-Host "Scanning $Range " -NoNewline
    Write-Host "($($targets.Count) addresses)" -ForegroundColor DarkGray

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        Invoke-IpScan -Targets $targets -TimeoutMs $TimeoutMs -Concurrency $Concurrency `
            -PortList $PortList -ResolveDns (-not $NoDns) -ResolveMac (-not $NoMac) `
            -UseVendorApi (-not $OfflineVendors) -State $state
    }
    finally {
        $stopwatch.Stop()
        Write-Progress -Activity 'Scanning' -Completed
    }

    $results = @()
    $item = $null
    while ($state.Queue.TryDequeue([ref]$item)) { $results += $item }
    $results = @($results | Sort-Object SortKey)

    Write-Host ''
    if ($results.Count -eq 0) {
        Write-Host 'No hosts responded.' -ForegroundColor Yellow
    }
    else {
        $columns = @(
            @{ Name = 'IP Address'; Expression = 'IPAddress' }
            @{ Name = 'Hostname';   Expression = 'Hostname' }
            @{ Name = 'MAC';        Expression = 'MAC' }
            @{ Name = 'Vendor';     Expression = 'Vendor' }
            @{ Name = 'ms';         Expression = 'LatencyMs'; Align = 'right' }
        )
        if ($PortList.Count -gt 0) {
            $columns += @{ Name = 'Open Ports'; Expression = 'OpenPorts' }
        }

        $results | Format-Table -Property $columns -AutoSize | Out-String -Width 200 | Write-Host
    }

    Write-Host ("{0} host(s) up of {1} scanned in {2:n1}s" -f `
        $results.Count, $targets.Count, $stopwatch.Elapsed.TotalSeconds) -ForegroundColor DarkGray
    Write-Host ''

    $results
}

# ===========================================================================
# GUI mode
# ===========================================================================
$WindowXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:shell="clr-namespace:System.Windows.Shell;assembly=PresentationFramework"
        Title="PowerScan"
        Width="1040" Height="660" MinWidth="720" MinHeight="420"
        WindowStartupLocation="CenterScreen"
        WindowStyle="None"
        SnapsToDevicePixels="True"
        UseLayoutRounding="True"
        TextOptions.TextFormattingMode="Display"
        FontFamily="Segoe UI" FontSize="13"
        Background="@BG@" Foreground="@FG@">

    <shell:WindowChrome.WindowChrome>
        <shell:WindowChrome ResizeBorderThickness="6" CaptionHeight="40"
                            CornerRadius="0" GlassFrameThickness="0"
                            UseAeroCaptionButtons="False"/>
    </shell:WindowChrome.WindowChrome>

    <Window.Resources>
        <SolidColorBrush x:Key="Bg"       Color="@BG@"/>
        <SolidColorBrush x:Key="Fg"       Color="@FG@"/>
        <SolidColorBrush x:Key="Card"     Color="@CARD@"/>
        <SolidColorBrush x:Key="Border"   Color="@BORDER@"/>
        <SolidColorBrush x:Key="Accent"   Color="@ACCENT@"/>
        <SolidColorBrush x:Key="Muted"    Color="@MUTED@"/>
        <SolidColorBrush x:Key="RowAlt"   Color="@ROWALT@"/>

        <Style x:Key="ChromeBtn" TargetType="Button">
            <Setter Property="Width" Value="44"/>
            <Setter Property="Height" Value="32"/>
            <Setter Property="Foreground" Value="{StaticResource Fg}"/>
            <Setter Property="FontFamily" Value="Segoe MDL2 Assets"/>
            <Setter Property="FontSize" Value="10"/>
            <Setter Property="shell:WindowChrome.IsHitTestVisibleInChrome" Value="True"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="b" Background="Transparent">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="b" Property="Background" Value="{StaticResource Border}"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="CloseBtn" TargetType="Button" BasedOn="{StaticResource ChromeBtn}">
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="b" Background="Transparent">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="b" Property="Background" Value="#C42B1C"/>
                                <Setter Property="Foreground" Value="White"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style TargetType="TextBox">
            <Setter Property="Background" Value="{StaticResource Card}"/>
            <Setter Property="Foreground" Value="{StaticResource Fg}"/>
            <Setter Property="BorderBrush" Value="{StaticResource Border}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="8,6"/>
            <Setter Property="VerticalContentAlignment" Value="Center"/>
            <Setter Property="CaretBrush" Value="{StaticResource Fg}"/>
            <Setter Property="SelectionBrush" Value="{StaticResource Accent}"/>
        </Style>

        <Style TargetType="CheckBox">
            <Setter Property="Foreground" Value="{StaticResource Fg}"/>
            <Setter Property="VerticalAlignment" Value="Center"/>
            <Setter Property="Margin" Value="0,0,14,0"/>
        </Style>

        <Style x:Key="Label" TargetType="TextBlock">
            <Setter Property="Foreground" Value="{StaticResource Muted}"/>
            <Setter Property="FontSize" Value="11"/>
            <Setter Property="Margin" Value="2,0,0,4"/>
        </Style>

        <Style x:Key="Btn" TargetType="Button">
            <Setter Property="Height" Value="32"/>
            <Setter Property="Padding" Value="16,0"/>
            <Setter Property="Foreground" Value="{StaticResource Fg}"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="b" CornerRadius="4"
                                Background="{StaticResource Card}"
                                BorderBrush="{StaticResource Border}" BorderThickness="1">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="b" Property="Background" Value="{StaticResource Border}"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Opacity" Value="0.4"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="PrimaryBtn" TargetType="Button" BasedOn="{StaticResource Btn}">
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="b" CornerRadius="4" Background="{StaticResource Accent}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="b" Property="Opacity" Value="0.85"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Opacity" Value="0.4"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>

    <Border BorderBrush="{StaticResource Border}" BorderThickness="1">
        <Grid>
            <Grid.RowDefinitions>
                <RowDefinition Height="40"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*"/>
                <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>

            <!-- Title bar -->
            <Grid Grid.Row="0" Background="{StaticResource Card}">
                <StackPanel Orientation="Horizontal" VerticalAlignment="Center" Margin="16,0,0,0">
                    <TextBlock Text="PowerScan" FontWeight="SemiBold"
                               Foreground="{StaticResource Fg}"/>
                    <TextBlock Text="@VERSION@" FontSize="11" Margin="8,1,0,0"
                               VerticalAlignment="Center" Foreground="{StaticResource Muted}"/>
                </StackPanel>
                <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" VerticalAlignment="Center">
                    <Button x:Name="MinBtn" Style="{StaticResource ChromeBtn}" Content="&#xE921;" ToolTip="Minimize"/>
                    <Button x:Name="CloseBtn" Style="{StaticResource CloseBtn}" Content="&#xE8BB;" ToolTip="Close"/>
                </StackPanel>
            </Grid>

            <!-- Controls -->
            <Grid Grid.Row="1" Margin="16,14,16,10">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="180"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>

                <StackPanel Grid.Row="0" Grid.Column="0" Margin="0,0,10,0">
                    <TextBlock Style="{StaticResource Label}" Text="RANGE  (CIDR, 192.168.1.10-50, or a single IP)"/>
                    <TextBox x:Name="RangeBox"/>
                </StackPanel>

                <StackPanel Grid.Row="0" Grid.Column="1" Margin="0,0,10,0">
                    <TextBlock Style="{StaticResource Label}" Text="TCP PORTS  (optional)"/>
                    <TextBox x:Name="PortsBox"/>
                </StackPanel>

                <Button Grid.Row="0" Grid.Column="2" x:Name="ScanBtn" Style="{StaticResource PrimaryBtn}"
                        Content="Scan" Width="110" VerticalAlignment="Bottom" Margin="0,0,8,0"/>
                <Button Grid.Row="0" Grid.Column="3" x:Name="StopBtn" Style="{StaticResource Btn}"
                        Content="Stop" Width="84" VerticalAlignment="Bottom" IsEnabled="False"/>

                <StackPanel Grid.Row="1" Grid.Column="0" Grid.ColumnSpan="4"
                            Orientation="Horizontal" Margin="0,12,0,0">
                    <CheckBox x:Name="DnsChk" Content="Resolve hostnames" IsChecked="True"/>
                    <CheckBox x:Name="MacChk" Content="Resolve MAC / vendor" IsChecked="True"/>
                    <TextBlock Text="Timeout" Foreground="{StaticResource Muted}"
                               VerticalAlignment="Center" Margin="6,0,6,0"/>
                    <TextBox x:Name="TimeoutBox" Width="60" Text="400"/>
                    <TextBlock Text="ms" Foreground="{StaticResource Muted}"
                               VerticalAlignment="Center" Margin="6,0,0,0"/>
                </StackPanel>
            </Grid>

            <!-- Results -->
            <DataGrid Grid.Row="2" x:Name="ResultGrid" Margin="16,4,16,8"
                      AutoGenerateColumns="False" IsReadOnly="True"
                      CanUserAddRows="False" CanUserDeleteRows="False"
                      HeadersVisibility="Column" GridLinesVisibility="None"
                      Background="{StaticResource Card}" Foreground="{StaticResource Fg}"
                      BorderBrush="{StaticResource Border}" BorderThickness="1"
                      RowBackground="{StaticResource Card}"
                      AlternatingRowBackground="{StaticResource RowAlt}"
                      SelectionMode="Extended" SelectionUnit="FullRow"
                      EnableRowVirtualization="True" RowHeight="26">
                <DataGrid.ColumnHeaderStyle>
                    <Style TargetType="DataGridColumnHeader">
                        <Setter Property="Background" Value="{StaticResource Border}"/>
                        <Setter Property="Foreground" Value="{StaticResource Fg}"/>
                        <Setter Property="FontWeight" Value="SemiBold"/>
                        <Setter Property="Padding" Value="10,7"/>
                        <Setter Property="BorderThickness" Value="0"/>
                        <Setter Property="HorizontalContentAlignment" Value="Left"/>
                    </Style>
                </DataGrid.ColumnHeaderStyle>
                <DataGrid.CellStyle>
                    <Style TargetType="DataGridCell">
                        <Setter Property="BorderThickness" Value="0"/>
                        <Setter Property="Padding" Value="10,0"/>
                        <Setter Property="VerticalAlignment" Value="Center"/>
                        <Setter Property="Template">
                            <Setter.Value>
                                <ControlTemplate TargetType="DataGridCell">
                                    <Border Background="{TemplateBinding Background}" Padding="10,0">
                                        <ContentPresenter VerticalAlignment="Center"/>
                                    </Border>
                                </ControlTemplate>
                            </Setter.Value>
                        </Setter>
                        <Style.Triggers>
                            <Trigger Property="IsSelected" Value="True">
                                <Setter Property="Background" Value="{StaticResource Accent}"/>
                                <Setter Property="Foreground" Value="White"/>
                            </Trigger>
                        </Style.Triggers>
                    </Style>
                </DataGrid.CellStyle>
                <DataGrid.Columns>
                    <DataGridTextColumn Header="IP Address" Binding="{Binding IPAddress}" Width="140"
                                        SortMemberPath="SortKey"/>
                    <DataGridTextColumn Header="Hostname"   Binding="{Binding Hostname}"  Width="*"/>
                    <DataGridTextColumn Header="MAC"        Binding="{Binding MAC}"       Width="170"/>
                    <DataGridTextColumn Header="Vendor"     Binding="{Binding Vendor}"    Width="170"/>
                    <DataGridTextColumn Header="ms"         Binding="{Binding LatencyMs}" Width="60"/>
                    <DataGridTextColumn Header="Open Ports" Binding="{Binding OpenPorts}" Width="160"/>
                </DataGrid.Columns>
            </DataGrid>

            <!-- Status bar -->
            <Grid Grid.Row="3" Background="{StaticResource Card}" Height="44">
                <ProgressBar x:Name="Progress" Height="2" VerticalAlignment="Top"
                             Background="Transparent" BorderThickness="0"
                             Foreground="{StaticResource Accent}" Minimum="0" Maximum="100"/>
                <TextBlock x:Name="StatusText" Margin="16,0,0,0" VerticalAlignment="Center"
                           Foreground="{StaticResource Muted}" Text="Ready."/>
                <StackPanel Orientation="Horizontal" HorizontalAlignment="Right"
                            VerticalAlignment="Center" Margin="0,0,16,0">
                    <Button x:Name="CopyBtn"   Style="{StaticResource Btn}" Content="Copy"       Margin="0,0,8,0"/>
                    <Button x:Name="ExportBtn" Style="{StaticResource Btn}" Content="Export CSV"/>
                </StackPanel>
            </Grid>
        </Grid>
    </Border>
</Window>
'@

function Show-ScannerWindow {
    param([string]$InitialRange, [string]$InitialPorts)

    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase | Out-Null
    $useDark = $true
    try {
        $useDark = (Get-ItemPropertyValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' 'AppsUseLightTheme') -eq 0
    }
    catch { }

    $theme = if ($useDark) {
        @{ BG = '#FF1B1B1F'; FG = '#FFF2F2F2'; CARD = '#FF26262B'; BORDER = '#FF3A3A41'
           ACCENT = '#FF0F7AE5'; MUTED = '#FF9A9AA5'; ROWALT = '#FF2C2C32' }
    }
    else {
        @{ BG = '#FFF5F5F7'; FG = '#FF1A1A1A'; CARD = '#FFFFFFFF'; BORDER = '#FFD8D8DE'
           ACCENT = '#FF0F6CBD'; MUTED = '#FF606068'; ROWALT = '#FFF7F7F9' }
    }

    $xaml = $WindowXaml
    foreach ($key in $theme.Keys) { $xaml = $xaml.Replace("@$key@", $theme[$key]) }
    $xaml = $xaml.Replace('@VERSION@', $PowerScanVersion)

    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
    try { $window = [System.Windows.Markup.XamlReader]::Load($reader) }
    finally { $reader.Close() }

    $rangeBox   = $window.FindName('RangeBox')
    $portsBox   = $window.FindName('PortsBox')
    $timeoutBox = $window.FindName('TimeoutBox')
    $dnsChk     = $window.FindName('DnsChk')
    $macChk     = $window.FindName('MacChk')
    $scanBtn    = $window.FindName('ScanBtn')
    $stopBtn    = $window.FindName('StopBtn')
    $grid       = $window.FindName('ResultGrid')
    $progress   = $window.FindName('Progress')
    $statusText = $window.FindName('StatusText')
    $copyBtn    = $window.FindName('CopyBtn')
    $exportBtn  = $window.FindName('ExportBtn')

    $rangeBox.Text   = $InitialRange
    $portsBox.Text   = $InitialPorts
    $timeoutBox.Text = [string]$TimeoutMs
    $dnsChk.IsChecked = -not $NoDns
    $macChk.IsChecked = -not $NoMac

    $rows = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
    $grid.ItemsSource = $rows

    # Mutable state shared between the event handlers below.
    $ctx = [pscustomobject]@{
        State     = $null
        Shell     = $null
        Runspace  = $null
        Handle    = $null
        Timer     = $null
        Stopwatch = $null
    }

    $window.FindName('MinBtn').Add_Click({ $window.WindowState = 'Minimized' })
    $window.FindName('CloseBtn').Add_Click({ $window.Close() })

    $finishScan = {
        if ($ctx.Timer) { $ctx.Timer.Stop() }

        if ($ctx.Shell) {
            try { if ($ctx.Handle) { $ctx.Shell.EndInvoke($ctx.Handle) } } catch { }
            try { $ctx.Shell.Dispose() } catch { }
            $ctx.Shell = $null
        }
        if ($ctx.Runspace) {
            try { $ctx.Runspace.Close(); $ctx.Runspace.Dispose() } catch { }
            $ctx.Runspace = $null
        }

        $scanBtn.IsEnabled = $true
        $stopBtn.IsEnabled = $false
        $progress.Value = 100

        $elapsed = if ($ctx.Stopwatch) { $ctx.Stopwatch.Elapsed.TotalSeconds } else { 0 }
        $verb = if ($ctx.State -and $ctx.State.Cancel) { 'Stopped' } else { 'Done' }

        if ($ctx.State -and $ctx.State.Error) {
            $statusText.Text = "Error: $($ctx.State.Error)"
        }
        else {
            $statusText.Text = '{0}. {1} host(s) up of {2} scanned in {3:n1}s.' -f `
                $verb, $rows.Count, $(if ($ctx.State) { $ctx.State.Done } else { 0 }), $elapsed
        }
    }

    $startScan = {
        if ($ctx.Shell) { return }

        $rangeText = $rangeBox.Text.Trim()
        try {
            $targets = Expand-ScanRange $rangeText
            $portList = ConvertTo-PortList $portsBox.Text
            $timeout = [int]$timeoutBox.Text
            if ($timeout -lt 50) { $timeout = 50 }
        }
        catch {
            $statusText.Text = $_.Exception.Message
            return
        }

        $rows.Clear()
        $progress.Value = 0
        $scanBtn.IsEnabled = $false
        $stopBtn.IsEnabled = $true
        $statusText.Text = "Scanning $rangeText ..."

        $ctx.State = New-ScanState
        $ctx.Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        $ctx.Runspace = [runspacefactory]::CreateRunspace()
        $ctx.Runspace.ApartmentState = 'STA'
        $ctx.Runspace.ThreadOptions = 'ReuseThread'
        $ctx.Runspace.Open()

        $ctx.Shell = [powershell]::Create()
        $ctx.Shell.Runspace = $ctx.Runspace
        [void]$ctx.Shell.AddScript({
            param($Lib, $Targets, $TimeoutMs, $Concurrency, $PortList, $ResolveDns, $ResolveMac, $UseVendorApi, $State)
            try {
                . ([scriptblock]::Create($Lib))
                Invoke-IpScan -Targets $Targets -TimeoutMs $TimeoutMs -Concurrency $Concurrency `
                    -PortList $PortList -ResolveDns $ResolveDns -ResolveMac $ResolveMac `
                    -UseVendorApi $UseVendorApi -State $State
            }
            catch { $State.Error = $_.Exception.Message }
            finally { $State.Running = $false }
        })
        [void]$ctx.Shell.AddArgument($ScannerLib)
        [void]$ctx.Shell.AddArgument($targets)
        [void]$ctx.Shell.AddArgument($timeout)
        [void]$ctx.Shell.AddArgument($Concurrency)
        [void]$ctx.Shell.AddArgument([int[]]$portList)
        [void]$ctx.Shell.AddArgument([bool]$dnsChk.IsChecked)
        [void]$ctx.Shell.AddArgument([bool]$macChk.IsChecked)
        [void]$ctx.Shell.AddArgument([bool](-not $OfflineVendors))
        [void]$ctx.Shell.AddArgument($ctx.State)

        $ctx.Handle = $ctx.Shell.BeginInvoke()
        $ctx.Timer.Start()
    }

    # The worker runs on its own runspace; this timer is the only thing that
    # touches the UI, so every control mutation stays on the dispatcher thread.
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(120)
    $timer.Add_Tick({
        $state = $ctx.State
        if (-not $state) { return }

        $item = $null
        while ($state.Queue.TryDequeue([ref]$item)) { $rows.Add($item) }

        if ($state.Total -gt 0) {
            $progress.Value = [Math]::Min(100, ($state.Done / $state.Total) * 100)
            $statusText.Text = '{0} / {1} scanned - {2} up' -f $state.Done, $state.Total, $rows.Count
        }

        if (-not $state.Running) { & $finishScan }
    })
    $ctx.Timer = $timer

    $scanBtn.Add_Click($startScan)
    $stopBtn.Add_Click({
        if ($ctx.State) { $ctx.State.Cancel = $true }
        $stopBtn.IsEnabled = $false
        $statusText.Text = 'Stopping...'
    })

    $rangeBox.Add_KeyDown({
        if ($_.Key -eq 'Return') { & $startScan }
    })

    $copyBtn.Add_Click({
        if ($rows.Count -eq 0) { return }
        $text = $rows | Select-Object IPAddress, Hostname, MAC, Vendor, LatencyMs, OpenPorts |
            ConvertTo-Csv -NoTypeInformation -Delimiter "`t" | Out-String
        [System.Windows.Clipboard]::SetText($text)
        $statusText.Text = "Copied $($rows.Count) row(s) to the clipboard."
    })

    $exportBtn.Add_Click({
        if ($rows.Count -eq 0) { return }
        $dialog = New-Object Microsoft.Win32.SaveFileDialog
        $dialog.Filter = 'CSV file (*.csv)|*.csv'
        $dialog.FileName = "powerscan-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
        if ($dialog.ShowDialog()) {
            $rows | Select-Object IPAddress, Hostname, MAC, Vendor, LatencyMs, OpenPorts |
                Export-Csv -Path $dialog.FileName -NoTypeInformation -Encoding UTF8
            $statusText.Text = "Exported to $($dialog.FileName)"
        }
    })

    $window.Add_Closing({
        if ($ctx.State) { $ctx.State.Cancel = $true }
        if ($ctx.Timer) { $ctx.Timer.Stop() }
        if ($ctx.Shell) { try { $ctx.Shell.Stop(); $ctx.Shell.Dispose() } catch { } }
        if ($ctx.Runspace) { try { $ctx.Runspace.Dispose() } catch { } }
    })

    $window.Add_ContentRendered({
        $rangeBox.Focus() | Out-Null
        $rangeBox.SelectAll()
        & $startScan
    })

    [void]$window.ShowDialog()

    , @($rows)
}

# ===========================================================================
# Entry point
# ===========================================================================
if (-not $Range) {
    try { $Range = Get-DefaultScanRange }
    catch { $Range = '192.168.1.0/24' }
}

$portList = ConvertTo-PortList $Ports

# WPF is Windows-only, absent from Server Core, and needs an STA thread.
# Fall back to the console rather than failing outright.
if (-not $NoGui) {
    try { Add-Type -AssemblyName PresentationFramework -ErrorAction Stop | Out-Null }
    catch {
        Write-Warning 'WPF is unavailable here; falling back to console output.'
        $NoGui = $true
    }
}

if (-not $NoGui -and [System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    Write-Warning 'This host is running MTA, which cannot show a WPF window. Re-run under powershell.exe (or pwsh -STA) for the GUI. Falling back to console output.'
    $NoGui = $true
}

$results = if ($NoGui) {
    try {
        Invoke-ConsoleScan -Range $Range -PortList $portList
    }
    catch {
        Write-Host ''
        Write-Host $_.Exception.Message -ForegroundColor Red
        Write-Host "Run with -Help for usage." -ForegroundColor DarkGray
        Write-Host ''
        # return, not exit: through the one-liner this runs inside the
        # technician's own shell, and exit would close their window.
        return
    }
}
else {
    Show-ScannerWindow -InitialRange $Range -InitialPorts $Ports
}

if ($ExportCsv -and $results) {
    $results | Select-Object IPAddress, Hostname, MAC, Vendor, LatencyMs, OpenPorts |
        Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Host "Exported $(@($results).Count) row(s) to $ExportCsv"
}
