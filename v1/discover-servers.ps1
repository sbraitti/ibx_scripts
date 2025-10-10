<#
.SYNOPSIS
    Lista todos os servidores DNS (Domain Controllers) encontrados via Active Directory.

.DESCRIPTION
    Script simples, extraído da lógica de DiscoverServers presente em extract-ms-dns.ps1,
    que percorre a floresta Active Directory atual, lista os Domain Controllers e resolve
    seus endereços IPv4 (quando disponível). O resultado é emitido como objetos PowerShell
    para que você possa redirecionar/filtrar ou salvar em CSV facilmente.

.EXAMPLE
    .\discover-servers.ps1
    Lista os servidores e seus endereços IP.

.EXAMPLE
    .\discover-servers.ps1 | Export-Csv -Path dns-servers.csv -NoTypeInformation

.PARAMETER DiscoverServers
    Quando definido como $true (padrão), executa a descoberta. Se definido como $false,
    o script não fará nada.

.NOTES
    Requer execução em uma máquina membro de domínio com acesso ao Active Directory.
    Se não estiver em um ambiente AD, o script vai reportar o erro correspondente.
#>

param (
    [bool]$DiscoverServers = $true
)

function Resolve-IPv4 {
    param (
        [string]$HostName
    )

    $ip = ''
    try {
        $addrs = [System.Net.Dns]::GetHostAddresses($HostName)
        foreach ($a in $addrs) {
            if ($a.AddressFamily -eq 'InterNetwork') {
                $ip = $a.IPAddressToString
                break
            }
        }
    }
    catch {
        # Falha ao resolver; retornará string vazia
        $ip = ''
    }
    return $ip
}

if (-not $DiscoverServers) {
    Write-Output "DiscoverServers está definido como false. Nada a fazer."
    return
}

try {
    $forest = [DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
}
catch {
    Write-Error "Não foi possível recuperar a floresta Active Directory atual. Assegure que a máquina está ingressada no domínio e que você tem acesso ao AD API. Detalhe: $_"
    exit 1
}

$dnsServers = @()

foreach ($domain in $forest.domains) {
    if (-not $domain.DomainControllers) {
        Write-Warning "Domínio '$($domain.Name)' retornou lista vazia de Domain Controllers."
        continue
    }

    foreach ($dc in $domain.DomainControllers) {
        $name = $dc.Name
        $ip = Resolve-IPv4 -HostName $name

        $obj = [PSCustomObject]@{
            Domain    = $domain.Name
            DnsName   = $name
            IPAddress = $ip
        }

        $dnsServers += $obj
    }
}

if ($dnsServers.Count -eq 0) {
    Write-Output "Nenhum servidor DNS (Domain Controller) encontrado."
}
else {
    # Ordena e exibe em formato tabular; como objetos também podem ser exportados
    $dnsServers | Sort-Object Domain, DnsName | Format-Table -AutoSize
}
