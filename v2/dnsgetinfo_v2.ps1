<#
dnsgetinfo_v2.ps1

SCCM-friendly single-file script (no parameters required).
Behavior:
 - Runs on the local machine and collects DNS zone summary information from the local DNS Server service.
 - Server name used in CSV = local hostname.
 - ServerIP used in CSV = semicolon-separated list of the machine's IPv4 addresses (all interfaces).
 - Writes per-server CSV to $OutDir (local folder).
 - Attempts to copy the resulting CSV(s) to a remote network share: $RemoteShareBase\<COMPUTERNAME>\
 - Compatible with PowerShell 5.1 (uses Get-DnsServer* cmdlets when available).
 - Designed to run as an SCCM package / scheduled task without arguments.
 - All runtime variables are declared inside the script for easy deployment.

Customize the following variables at the top as needed for your environment:
 - $OutDir: local folder to store output before copying
 - $RemoteShareBase: UNC path of the destination server/share to copy results to
 - $UseNetRetry, $NetRetryDelaySeconds: network copy retry behavior
#>

# --- Configuration (edit as needed) ---
$OutDir = Join-Path -Path $env:ProgramData -ChildPath "WinDNSCollector\ib_export"
$RemoteShareBase = "//path/to/save"   

$UseNetRetry = 2
$NetRetryDelaySeconds = 2

# Logging
$LogFile = Join-Path -Path $OutDir -ChildPath ("{0}-dnsgetinfo_v2.log" -f $env:COMPUTERNAME)

$ErrorActionPreference = 'Continue'

function Log {
    param([string]$msg)
    $t = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "$t`t$msg"
    try { Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue } catch {}
    # also emit to host for immediate feedback
    Write-Host $line
}

function Sanitize-FileName {
    param([string]$name)
    if (-not $name) { return $null }
    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $out = $name
    foreach ($c in $invalid) { $out = $out -replace [regex]::Escape($c), '_' }
    return $out
}

function Get-LocalIPv4Addresses {
    # Return array of IPv4 addresses excluding loopback and link-local (169.254.*)
    $ips = @()
    try {
        if (Get-Command -Name Get-NetIPAddress -ErrorAction SilentlyContinue) {
            $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                   Where-Object { $_.IPAddress -and $_.IPAddress -ne '127.0.0.1' -and ($_.IPAddress -notmatch '^169\.254\.') -and ($_.IPAddress -notmatch '^0\.0\.0\.0') } |
                   Select-Object -ExpandProperty IPAddress -Unique
        }
    } catch {}
    if (-not $ips -or $ips.Count -eq 0) {
        try {
            $cfgs = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE" -ErrorAction SilentlyContinue
            foreach ($c in $cfgs) {
                if ($c.IPAddress) {
                    foreach ($ip in $c.IPAddress) {
                        if ($ip -and ($ip -notmatch ':') -and $ip -ne '127.0.0.1' -and ($ip -notmatch '^169\.254\.')) {
                            $ips += $ip
                        }
                    }
                }
            }
            $ips = $ips | Select-Object -Unique
        } catch {}
    }
    $ips = $ips | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ -and ($_ -ne '127.0.0.1') } | Select-Object -Unique
    return ,($ips)
}

function Try-CopyToRemote {
    param(
        [string]$localPath,
        [string]$remoteBase,
        [int]$retries = 3,
        [int]$delay = 5
    )
    if (-not (Test-Path -Path $localPath)) {
        Log "Local file not found for remote copy: $localPath"
        return $false
    }
    $remoteDir = Join-Path -Path $remoteBase -ChildPath $env:COMPUTERNAME
    $attempt = 0
    while ($attempt -lt $retries) {
        try {
            # create remote dir if possible
            New-Item -ItemType Directory -Path $remoteDir -Force -ErrorAction SilentlyContinue | Out-Null
            $dest = Join-Path -Path $remoteDir -ChildPath (Split-Path -Path $localPath -Leaf)
            Copy-Item -Path $localPath -Destination $dest -Force -ErrorAction Stop
            Log "Copied $localPath -> $dest"
            return $true
        } catch {
            $attempt++
            Log "Copy attempt $attempt failed: $($_.Exception.Message)"
            Start-Sleep -Seconds $delay
        }
    }
    Log "Failed to copy $localPath after $retries attempts."
    return $false
}

# --- Ensure output folder exists ---
try {
    if (-not (Test-Path -Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
} catch {
    Log "Could not create OutDir $OutDir : $($_.Exception.Message)"
}

# Determine local server and IPs
$LocalServer = $env:COMPUTERNAME
$LocalIPs = Get-LocalIPv4Addresses
if (-not $LocalIPs -or $LocalIPs.Count -eq 0) { $LocalIPs = @('127.0.0.1') }
$ServerIPField = ($LocalIPs -join ';')

Log "Starting dnsgetinfo_v2 on $LocalServer (IPs: $ServerIPField)"

# --- Main processing function (adapted from v1 implementation for local run) ---
function Process-LocalServer {
    param([string]$srv, [string]$serverIPs, [string]$OutDir)

    Log "Processing local server: $srv"

    $idForFile = if ($serverIPs -and ($serverIPs -ne '')) { ($serverIPs -split ';')[0] } else { $srv }
    $idForFile = Sanitize-FileName $idForFile
    $outPath = Join-Path -Path $OutDir -ChildPath ("server_{0}.csv" -f $idForFile)

    $rows = New-Object System.Collections.Generic.List[object]

    # Get zones
    try {
        $zones = @(Get-DnsServerZone -ComputerName $srv -ErrorAction Stop)
    } catch {
        Log ("Failed to query DNS zones for {0}: {1}" -f $srv, $_.Exception.Message)
        return
    }

    foreach ($z in $zones) {
        $zoneName = $z.ZoneName
        $zoneType = $z.ZoneType

        # flags
        $isDsIntegrated = $null
        if ($z.PSObject.Properties.Match('IsDsIntegrated')) { $isDsIntegrated = $z.IsDsIntegrated }
        $isReverse = $null
        if ($z.PSObject.Properties.Match('IsReverseLookupZone')) { $isReverse = $z.IsReverseLookupZone }
        $isPaused = $null
        if ($z.PSObject.Properties.Match('IsPaused')) { $isPaused = $z.IsPaused }
        $isAutoCreated = $null
        if ($z.PSObject.Properties.Match('IsAutoCreated')) { $isAutoCreated = $z.IsAutoCreated }

        $masterServers = $null
        $conditionalTargets = $null
        $soaMName = $null
        $soaSerial = $null
        $recordCount = $null
        $dynamicRecordCount = $null

        # master servers
        try {
            if ($z.PSObject.Properties.Match('MasterServers') -and $z.MasterServers) {
                $masterServers = ($z.MasterServers | ForEach-Object { $_.ToString() }) -join ';'
            } else {
                $zoneFull = Get-DnsServerZone -ComputerName $srv -Name $zoneName -ErrorAction SilentlyContinue
                if ($zoneFull -and $zoneFull.PSObject.Properties.Match('MasterServers') -and $zoneFull.MasterServers) {
                    $masterServers = ($zoneFull.MasterServers | ForEach-Object { $_.ToString() }) -join ';'
                }
            }
        } catch {}

        # conditional forwarders per zone (if forwarder zone)
        try {
            if ($zoneType -eq 'Forwarder') {
                $cfz = Get-DnsServerConditionalForwarderZone -ComputerName $srv -Name $zoneName -ErrorAction SilentlyContinue
                if ($cfz -and $cfz.MasterServers) {
                    $conditionalTargets = ($cfz.MasterServers | ForEach-Object { $_.ToString() }) -join ';'
                }
            }
        } catch {}

        # record counting (streaming)
        try {
            $recordCount = 0
            $dynamicRecordCount = 0
            Get-DnsServerResourceRecord -ComputerName $srv -ZoneName $zoneName -ErrorAction Stop | ForEach-Object {
                $recordCount++
                try { if ($_.PSObject.Properties.Match('Timestamp') -and $_.Timestamp) { $dynamicRecordCount++ } } catch {}
            }
        } catch {
            try {
                $recordCount = 0
                $dynamicRecordCount = 0
                Get-DnsServerResourceRecord -ComputerName $srv -ZoneName $zoneName -ErrorAction SilentlyContinue | ForEach-Object {
                    $recordCount++
                    try { if ($_.PSObject.Properties.Match('Timestamp') -and $_.Timestamp) { $dynamicRecordCount++ } } catch {}
                }
            } catch {
                $recordCount = $null
                $dynamicRecordCount = $null
            }
        }

        # SOA
        try {
            $soa = Get-DnsServerResourceRecord -ComputerName $srv -ZoneName $zoneName -RRType SOA -Name '@' -ErrorAction SilentlyContinue
            if ($soa) {
                if ($soa.RecordData -and $soa.RecordData.SerialNumber) { $soaSerial = $soa.RecordData.SerialNumber }
                if ($soa.RecordData -and $soa.RecordData.MName) { $soaMName = $soa.RecordData.MName }
            }
        } catch {}

        # decide forwardTargets field
        $forwardTargets = $null
        if ($conditionalTargets) { $forwardTargets = $conditionalTargets } elseif ($masterServers) { $forwardTargets = $masterServers }

        $rows.Add([pscustomobject]@{
            Server               = $srv
            ServerIP             = $serverIPs
            ZoneName             = $zoneName
            ZoneType             = $zoneType
            IsDsIntegrated       = $isDsIntegrated
            IsReverseZone        = $isReverse
            IsPaused             = $isPaused
            IsAutoCreated        = $isAutoCreated
            MasterServers        = $masterServers
            ForwardTargets       = $forwardTargets
            RecordCount          = $recordCount
            DynamicRecordCount   = $dynamicRecordCount
            SOA_MName            = $soaMName
            SOA_Serial           = $soaSerial
        }) | Out-Null
    }

    # server-level forwarders robust extraction
    try {
        $srvFwd = Get-DnsServerForwarder -ComputerName $srv -ErrorAction SilentlyContinue
        $ips = @()
        if ($srvFwd) {
            # multiple extraction strategies to handle different PS versions
            try {
                if ($srvFwd.PSObject.Properties.Match('IPAddress') -and $srvFwd.IPAddress -and $srvFwd.IPAddress.PSObject.Properties.Match('Value') -and $srvFwd.IPAddress.Value) {
                    foreach ($e in $srvFwd.IPAddress.Value) {
                        if ($null -eq $e) { continue }
                        if ($e.PSObject.Properties.Match('Address')) {
                            try {
                                $addrInt = [uint64]$e.Address
                                $a = ($addrInt -shr 24) -band 0xFF
                                $b = ($addrInt -shr 16) -band 0xFF
                                $c = ($addrInt -shr 8) -band 0xFF
                                $d = $addrInt -band 0xFF
                                $ips += ("{0}.{1}.{2}.{3}" -f $a,$b,$c,$d)
                            } catch {
                                try { $ips += $e.Address.ToString() } catch {}
                            }
                        } elseif ($e -is [System.Net.IPAddress]) {
                            $ips += $e.ToString()
                        } else {
                            $ips += $e.ToString()
                        }
                    }
                }
            } catch {}

            $items = if ($srvFwd -is [System.Array]) { $srvFwd } else { @($srvFwd) }

            try {
                if ($srvFwd.PSObject.Properties.Match('CimInstanceProperties') -and $srvFwd.CimInstanceProperties) {
                    foreach ($cip in $srvFwd.CimInstanceProperties) {
                        if ($cip.Name -eq 'IPAddress' -and $cip.Value) {
                            if ($cip.Value -is [System.Array]) {
                                foreach ($v in $cip.Value) { if ($v) { $ips += $v.ToString() } }
                            } else {
                                $ips += $cip.Value.ToString()
                            }
                        }
                    }
                }
            } catch {}

            foreach ($f in $items) {
                if ($f.PSObject.Properties.Match('IPAddress')) {
                    $addrProp = $f.IPAddress
                    if ($addrProp -and $addrProp.PSObject.Properties.Match('Value')) {
                        $entries = $addrProp.Value
                    } else {
                        $entries = $addrProp
                    }
                    if ($entries) {
                        foreach ($e in $entries) {
                            if ($null -ne $e) {
                                if ($e.PSObject.Properties.Match('Address')) {
                                    try {
                                        $addrInt = [uint64]$e.Address
                                        $a = ($addrInt -shr 24) -band 0xFF
                                        $b = ($addrInt -shr 16) -band 0xFF
                                        $c = ($addrInt -shr 8) -band 0xFF
                                        $d = $addrInt -band 0xFF
                                        $ips += ("{0}.{1}.{2}.{3}" -f $a,$b,$c,$d)
                                    } catch {
                                        try { $ips += $e.Address.ToString() } catch {}
                                    }
                                } elseif ($e -is [System.Net.IPAddress]) {
                                    $ips += $e.ToString()
                                } else {
                                    $ips += $e.ToString()
                                }
                            }
                        }
                    }
                } else {
                    foreach ($prop in $f.PSObject.Properties) {
                        if ($prop.Name -match 'IP' -and $prop.Value) {
                            $val = $prop.Value
                            if ($val -is [System.Array]) {
                                foreach ($v in $val) { if ($v) { $ips += $v.ToString() } }
                            } else {
                                $ips += $val.ToString()
                            }
                        }
                    }
                    if ($f -and ($f -is [string] -or $f -is [System.Net.IPAddress])) {
                        $ips += $f.ToString()
                    }
                }
            }
        }

        # normalize and dedupe
        $ips = $ips | Where-Object { $_ -and ($_.ToString().Trim() -ne '') } | ForEach-Object { $_.ToString().Trim() } | Select-Object -Unique

        # fallback: try alternative Get-DnsServerForwarder outputs
        if (($ips.Count -eq 0) -and $srvFwd) {
            try {
                $alt = @(Get-DnsServerForwarder -ComputerName $srv -ErrorAction SilentlyContinue | ForEach-Object {
                    if ($_.PSObject.Properties.Match('IPAddress') -and $_.IPAddress) { $_.IPAddress } else { $_ }
                })
                foreach ($a in $alt) {
                    if ($null -eq $a) { continue }
                    if ($a -is [System.Array]) {
                        foreach ($v in $a) {
                            if ($v -is [System.Net.IPAddress]) { $ips += $v.ToString() } else { $ips += $v.ToString() }
                        }
                    } else {
                        if ($a -is [System.Net.IPAddress]) { $ips += $a.ToString() } else { $ips += $a.ToString() }
                    }
                }
                $ips = $ips | Where-Object { $_ -and ($_.ToString().Trim() -ne '') } | ForEach-Object { $_.ToString().Trim() } | Select-Object -Unique
            } catch {}
        }

        if ($ips.Count -gt 0) {
            $ipsJoined = $ips -join ';'
            $rows.Add([pscustomobject]@{
                Server               = $srv
                ServerIP             = $serverIPs
                ZoneName             = '<ServerForwarders>'
                ZoneType             = 'Server'
                IsDsIntegrated       = $null
                IsReverseZone        = $null
                IsPaused             = $null
                IsAutoCreated        = $null
                MasterServers        = $null
                ForwardTargets       = $ipsJoined
                RecordCount          = $null
                DynamicRecordCount   = $null
                SOA_MName            = $null
                SOA_Serial           = $null
                RecordType           = 'Forwarders'
                RecordValue          = $ipsJoined
            }) | Out-Null
        }
    } catch {
        Log "Error while extracting server forwarders: $($_.Exception.Message)"
    }

    # recursion server-level indicator
    try {
        $recEnabled = $null
        $recObj = Get-DnsServerRecursion -ComputerName $srv -ErrorAction SilentlyContinue
        if ($recObj) {
            $names = $recObj.PSObject.Properties | ForEach-Object { $_.Name }
            $prop = $names | Where-Object { $_ -match '^(Enable|Enabled|IsEnabled)$' } | Select-Object -First 1
            if (-not $prop) {
                $prop = $names | Where-Object { $_ -match 'Recurs|Enable|Allow' } | Select-Object -First 1
            }
            if ($prop) {
                try { $val = $recObj.$prop } catch { $val = $null }
                if ($val -is [bool]) { $recEnabled = $val }
                elseif ($val -ne $null) { try { $recEnabled = [bool]([string]$val -match '(?i)^(true|1|yes)$') } catch { $recEnabled = $null } }
                else { $recEnabled = $null }
            } else {
                try {
                    $cip = $recObj.CimInstanceProperties | Where-Object { $_.Name -match 'Enable|Recurs|Allow' } | Select-Object -First 1
                    if ($cip -and $cip.Value -ne $null) { $recEnabled = [bool]$cip.Value }
                } catch { $recEnabled = $null }
            }
        }
        if ($recEnabled -eq $true) {
            $rows.Add([pscustomobject]@{
                Server               = $srv
                ServerIP             = $serverIPs
                ZoneName             = '<ServerRecursion>'
                ZoneType             = 'Server'
                IsDsIntegrated       = $null
                IsReverseZone        = $null
                IsPaused             = $null
                IsAutoCreated        = $null
                MasterServers        = $null
                ForwardTargets       = $null
                RecordCount          = $null
                DynamicRecordCount   = $null
                SOA_MName            = $null
                SOA_Serial           = $null
                RecordType           = 'Recursion'
                RecordValue          = 'True'
            }) | Out-Null
        }
    } catch {
        Log "Error while extracting recursion info: $($_.Exception.Message)"
    }

    # ensure output folder and export
    $outFolder = if ($OutDir) { $OutDir } else { "." }
    if ($outFolder -and -not (Test-Path $outFolder)) { New-Item -ItemType Directory -Path $outFolder | Out-Null }

    try {
        $rows | Sort-Object ZoneName |
            Export-Csv -NoTypeInformation -Encoding UTF8 -Path $outPath
        Log ("OK: {0} lines -> {1}" -f $rows.Count, $outPath)
    } catch {
        Log ("Failed to export CSV to {0}: {1}" -f $outPath, $_.Exception.Message)
    }

    return $outPath
}

# --- Run for local server and copy results ---
try {
    $csvPath = Process-LocalServer -srv $LocalServer -serverIPs $ServerIPField -OutDir $OutDir
    if ($csvPath) {
        # attempt to copy the generated CSV to remote share (per-machine folder)
        $copyOk = Try-CopyToRemote -localPath $csvPath -remoteBase $RemoteShareBase -retries $UseNetRetry -delay $NetRetryDelaySeconds
        if (-not $copyOk) {
            Log "Primary copy failed; will attempt to copy any other server_*.csv files found."
            # attempt to copy any server_*.csv files in outdir
            try {
                Get-ChildItem -Path $OutDir -Filter "server_*.csv" -File -ErrorAction SilentlyContinue | ForEach-Object {
                    Try-CopyToRemote -localPath $_.FullName -remoteBase $RemoteShareBase -retries $UseNetRetry -delay $NetRetryDelaySeconds | Out-Null
                }
            } catch { Log "Error while attempting additional copy: $($_.Exception.Message)" }
        }
    } else {
        Log "No CSV path returned from processing. Nothing to copy."
    }
} catch {
    Log "Fatal error running Process-LocalServer: $($_.Exception.Message)"
}

Log "dnsgetinfo_v2 finished on $LocalServer"
exit 0
