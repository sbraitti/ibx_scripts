<# 
Uso:
.\script.ps1 -Servers 'dns1','dns2'               # grava CSVs server_<IP_or_name>.csv no diretório atual
.\script.ps1 -Servers 'dns1','dns2' -OutDir 'C:\Temp'  # grava CSVs em C:\Temp

Descrição:
- Compatível com PowerShell 5.1 (usa cmdlets do módulo DNS Server).
- Para cada servidor informado, gera UM CSV separado contendo todas as zonas daquele servidor.
- Cada linha do CSV é um resumo por zona com as colunas:
    Server, ServerIP, ZoneName, ZoneType, IsDsIntegrated, IsReverseZone, IsPaused, IsAutoCreated,
    MasterServers, ForwardTargets, RecordCount, SOA_MName, SOA_Serial
- Adiciona linha especial ZoneName = '<ServerForwarders>' com RecordType 'Forwarders'/RecordValue contendo os forwarders de servidor.
- Não tenta extrair scavenge/aging; toda lógica experimental removida.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string[]] $Servers,
  
  [Parameter(Mandatory = $false)]
  [string] $OutDir = ".",
  
  [Parameter(Mandatory = $false)]
  [int] $MaxConcurrentServers = 1,
  
  [Parameter(Mandatory = $false)]
  [switch] $SingleServerMode
)

$ErrorActionPreference = 'Stop'

function Resolve-ServerIP {
  param([string]$Server)
  try {
    $addr = [System.Net.Dns]::GetHostAddresses($Server) |
      Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
      Select-Object -First 1
    if ($addr) { $addr.IPAddressToString } else { $null }
  } catch { $null }
}

function Format-Array {
  param([object]$arr)
  if (-not $arr) { return $null }
  try {
    if ($arr -is [string]) { return $arr }
    $list = @()
    foreach ($i in $arr) { $list += $i.ToString() }
    return ($list -join ';')
  } catch {
    return $null
  }
}

function Sanitize-FileName {
  param([string]$name)
  if (-not $name) { return $null }
  # substituir caracteres inválidos por underscore
  $invalid = [System.IO.Path]::GetInvalidFileNameChars()
  $out = $name
  foreach ($c in $invalid) { $out = $out -replace [regex]::Escape($c), '_' }
  return $out
}

# garantir pasta de saída
if ($OutDir -and -not (Test-Path $OutDir)) {
  try { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null } catch {}
}

function Process-Server {
  param([string]$srv, [string]$OutDir)

  Write-Host "Consultando servidor: $srv"
  $serverIP = Resolve-ServerIP $srv
  $idForFile = if ($serverIP) { $serverIP } else { $srv }
  $idForFile = Sanitize-FileName $idForFile
  $outPath = Join-Path -Path $OutDir -ChildPath ("server_{0}.csv" -f $idForFile)

  $rows = New-Object System.Collections.Generic.List[object]

  # obter zonas
  try {
    $zones = @(Get-DnsServerZone -ComputerName $srv -ErrorAction Stop)
  } catch {
    Write-Warning ("Falha ao consultar zonas do servidor {0}: {1}" -f $srv, $_.Exception.Message)
    return
  }

  foreach ($z in $zones) {
    $zoneName = $z.ZoneName
    $zoneType = $z.ZoneType

    # flags (nem todas as propriedades existem em todas as versões)
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

    # master servers (Secondary/Stub)
    try {
      if ($z.PSObject.Properties.Match('MasterServers') -and $z.MasterServers) {
        $masterServers = Format-Array $z.MasterServers
      } else {
        $zoneFull = Get-DnsServerZone -ComputerName $srv -Name $zoneName -ErrorAction SilentlyContinue
        if ($zoneFull -and $zoneFull.PSObject.Properties.Match('MasterServers') -and $zoneFull.MasterServers) {
          $masterServers = Format-Array $zoneFull.MasterServers
        }
      }
    } catch { $masterServers = $null }

    # conditional forwarders por zona
    try {
      if ($zoneType -eq 'Forwarder') {
        $cfz = Get-DnsServerConditionalForwarderZone -ComputerName $srv -Name $zoneName -ErrorAction SilentlyContinue
        if ($cfz -and $cfz.MasterServers) {
          $conditionalTargets = Format-Array $cfz.MasterServers
        }
      }
    } catch { $conditionalTargets = $null }

    # contar registros (apenas Count) - streaming (não armazenar todos os RRs)
    # agora também conta quantos são dinâmicos (possuem Timestamp)
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
      } catch { $recordCount = $null; $dynamicRecordCount = $null }
    }

    # SOA
    try {
      $soa = Get-DnsServerResourceRecord -ComputerName $srv -ZoneName $zoneName -RRType SOA -Name '@' -ErrorAction SilentlyContinue
      if ($soa) {
        if ($soa.RecordData -and $soa.RecordData.SerialNumber) { $soaSerial = $soa.RecordData.SerialNumber }
        if ($soa.RecordData -and $soa.RecordData.MName) { $soaMName = $soa.RecordData.MName }
      }
    } catch { }

    # escolher o campo ForwardTargets (conditional forwarders ou master servers)
    $forwardTargets = $null
    if ($conditionalTargets) { $forwardTargets = $conditionalTargets }
    elseif ($masterServers) { $forwardTargets = $masterServers }

    $rows.Add([pscustomobject]@{
      Server               = $srv
      ServerIP             = $serverIP
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

  # linha especial: forwarders configurados no servidor (robust extraction)
  try {
    $srvFwd = Get-DnsServerForwarder -ComputerName $srv -ErrorAction SilentlyContinue

    $ips = @()
    if ($srvFwd) {

      # 0) extração direta do .IPAddress.value quando presente (CIM-style) - trata o caso mostrado por você
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

      # normalizar para array de objetos para as outras tentativas
      $items = if ($srvFwd -is [System.Array]) { $srvFwd } else { @($srvFwd) }

      # 1) algumas versões expõem os IPs dentro de CimInstanceProperties (Name='IPAddress') como strings.
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
        # 2) propriedade IPAddress comum no objeto CIM: pode ter .Value array de entradas com .Address (integers)
        if ($f.PSObject.Properties.Match('IPAddress')) {
          $addrProp = $f.IPAddress
          # se for um objeto com 'Value' (CIM output), usar esse array
          if ($addrProp -and $addrProp.PSObject.Properties.Match('Value')) {
            $entries = $addrProp.Value
          } else {
            $entries = $addrProp
          }

          if ($entries) {
            foreach ($e in $entries) {
              if ($null -ne $e) {
                # e pode ser um objeto com .Address numeric (CIM), ou um string, ou IPAddress
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
          # 3) fallback: inspecionar todas props que contenham 'IP' e extrair valores
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

          # 4) se o próprio objeto for string/ip, usar direto
          if ($f -and ($f -is [string] -or $f -is [System.Net.IPAddress])) {
            $ips += $f.ToString()
          }
        }
      }
    }

    # normalizar e juntar, removendo vazios e duplicados
    $ips = $ips | Where-Object { $_ -and ($_.ToString().Trim() -ne '') } | ForEach-Object { $_.ToString().Trim() } | Select-Object -Unique

    # Fallback adicional: se não encontramos IPs, tentar extrair diretamente do cmdlet (variações de retorno entre versões)
    if (($ips.Count -eq 0) -and $srvFwd) {
      try {
        $alt = @(Get-DnsServerForwarder -ComputerName $srv -ErrorAction SilentlyContinue | ForEach-Object {
          if ($_.PSObject.Properties.Match('IPAddress') -and $_.IPAddress) { $_.IPAddress } else { $_ }
        })

        foreach ($a in $alt) {
          if ($null -eq $a) { continue }
          if ($a -is [System.Array]) {
            foreach ($v in $a) {
              if ($v -is [System.Net.IPAddress]) { $ips += $v.ToString() }
              else { $ips += $v.ToString() }
            }
          } else {
            if ($a -is [System.Net.IPAddress]) { $ips += $a.ToString() }
            else { $ips += $a.ToString() }
          }
        }

        # normalizar novamente e remover duplicados
        $ips = $ips | Where-Object { $_ -and ($_.ToString().Trim() -ne '') } | ForEach-Object { $_.ToString().Trim() } | Select-Object -Unique
      } catch { }
    }

    if ($ips.Count -gt 0) {
      $ipsJoined = $ips -join ';'
      # criar objeto com o mesmo conjunto de propriedades das linhas de zona para garantir colunas consistentes no CSV
      $rows.Add([pscustomobject]@{
        Server               = $srv
        ServerIP             = $serverIP
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
  } catch { }

  # linha especial: Recursion habilitado/desabilitado no servidor (Server-level)
  try {
    $recEnabled = $null
    $recObj = Get-DnsServerRecursion -ComputerName $srv -ErrorAction SilentlyContinue
    if ($recObj) {
      # procurar por propriedades explícitas (Enable/Enabled/IsEnabled) com prioridade
      $names = $recObj.PSObject.Properties | ForEach-Object { $_.Name }
      $prop = $names | Where-Object { $_ -match '^(Enable|Enabled|IsEnabled)$' } | Select-Object -First 1
      if (-not $prop) {
        $prop = $names | Where-Object { $_ -match 'Recurs|Enable|Allow' } | Select-Object -First 1
      }

      if ($prop) {
        try {
          $val = $recObj.$prop
        } catch {
          $val = $null
        }
        if ($val -is [bool]) {
          $recEnabled = $val
        } elseif ($val -ne $null) {
          # tentar interpretar valores textuais/numericos
          try { $recEnabled = [bool]([string]$val -match '(?i)^(true|1|yes)$') } catch { $recEnabled = $null }
        } else {
          $recEnabled = $null
        }
      } else {
        # fallback: checar CimInstanceProperties por nome
        try {
          $cip = $recObj.CimInstanceProperties | Where-Object { $_.Name -match 'Enable|Recurs|Allow' } | Select-Object -First 1
          if ($cip -and $cip.Value -ne $null) {
            $recEnabled = [bool]$cip.Value
          }
        } catch { $recEnabled = $null }
      }
    }

    # somente criar a linha se recursão estiver habilitada (true)
    if ($recEnabled -eq $true) {
      $rows.Add([pscustomobject]@{
        Server               = $srv
        ServerIP             = $serverIP
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
  } catch { }

  # garantir pasta e exportar por servidor
  $outFolder = if ($OutDir) { $OutDir } else { "." }
  if ($outFolder -and -not (Test-Path $outFolder)) { New-Item -ItemType Directory -Path $outFolder | Out-Null }

  try {
    $rows | Sort-Object ZoneName |
      Export-Csv -NoTypeInformation -Encoding UTF8 -Path $outPath
    Write-Host ("OK: $($rows.Count) linhas -> {0}" -f $outPath)
  } catch {
    Write-Warning ("Falha ao exportar CSV para {0}: {1}" -f $outPath, $_.Exception.Message)
  }
}

# controlar concorrência por servidores usando Start-Job que reinvoca este script em modo SingleServerMode
# Teste prévio: validar conectividade e permissão aos servidores DNS antes de iniciar o processamento em lote.
# Usamos Get-DnsServerRecursion como verificação leve; se não existir/der erro, tentamos Get-DnsServerForwarder como fallback.
# Se ambos falharem, marcamos o servidor como com problema.
$failed = New-Object System.Collections.Generic.List[object]
foreach ($srv in $Servers) {
  try {
    # verificação leve: Get-DnsServerRecursion (não baixa todas as zonas)
    Get-DnsServerRecursion -ComputerName $srv -ErrorAction Stop | Out-Null
  } catch {
    # se Recursion não funcionar, tentar um cmdlet alternativo mais leve
    $errMsg = $null
    try {
      Get-DnsServerForwarder -ComputerName $srv -ErrorAction Stop | Out-Null
      # se chegar aqui, consideramos que os cmdlets funcionam e o servidor está acessível
      continue
    } catch {
      $errMsg = $_.Exception.Message
    }

    # registrar falha (resolver IP para melhor relatório)
    try { $serverIP = Resolve-ServerIP $srv } catch { $serverIP = $null }
    if (-not $serverIP) { $serverIP = $srv }
    $failed.Add([pscustomobject]@{ Server = $srv; ServerIP = $serverIP; Error = $errMsg }) | Out-Null
  }
}

if ($failed.Count -gt 0) {
  Write-Host ("Falha ao conectar/autorizar em {0} servidor(es) DNS." -f $failed.Count) -ForegroundColor Red
  foreach ($f in $failed) {
    Write-Host ("  Servidor: {0}    IP: {1}    Erro: {2}" -f $f.Server, $f.ServerIP, $f.Error) -ForegroundColor Red
  }
  # sair com código de erro para automações
  exit 2
}
if ($MaxConcurrentServers -gt 1 -and -not $SingleServerMode) {
  $scriptPath = $MyInvocation.MyCommand.Path
  $pwsh = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $jobs = @()

  foreach ($srv in $Servers) {
    # limitar número de jobs em execução
    while (($jobs | Where-Object { $_.State -eq 'Running' }).Count -ge $MaxConcurrentServers) {
      Start-Sleep -Milliseconds 500
      # cleanup finished jobs
      $finished = $jobs | Where-Object { $_.State -ne 'Running' }
      foreach ($fj in $finished) {
        try { Receive-Job $fj -ErrorAction SilentlyContinue } catch {}
        try { Remove-Job $fj -ErrorAction SilentlyContinue } catch {}
        $jobs = $jobs | Where-Object { $_.Id -ne $fj.Id }
      }
    }

    $jobs += Start-Job -ScriptBlock {
      param($pwshPath, $scriptPath, $srv, $outDir)
      & $pwshPath -NoProfile -ExecutionPolicy Bypass -File $scriptPath -Servers $srv -OutDir $outDir -SingleServerMode
    } -ArgumentList $pwsh, $scriptPath, $srv, $OutDir
  }

  # aguardar todos terminarem e coletar saída
  while ($jobs.Count -gt 0) {
    Start-Sleep -Milliseconds 500
    $finished = $jobs | Where-Object { $_.State -ne 'Running' }
    foreach ($fj in $finished) {
      try { Receive-Job $fj -ErrorAction SilentlyContinue } catch {}
      try { Remove-Job $fj -ErrorAction SilentlyContinue } catch {}
      $jobs = $jobs | Where-Object { $_.Id -ne $fj.Id }
    }
  }

} else {
  foreach ($srv in $Servers) {
    Process-Server -srv $srv -OutDir $OutDir
  }
}
