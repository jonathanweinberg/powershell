<#
.SYNOPSIS
    Enumerates and correlates DNS records across forward and reverse zones on a Microsoft DNS server.

.DESCRIPTION
    Find-DnsReferences performs a comprehensive analysis of DNS records within a specified DNS server,
    enabling deep inspection of relationships between hostnames, IP addresses, and record dependencies.

    The function supports:
        • Forward and reverse DNS enumeration (A, AAAA, CNAME, PTR, SRV, MX, NS, TXT, SOA)
        • Flexible name matching (exact, suffix, substring)
        • Detection of dangling CNAME records (including multi-hop chains)
        • Correlation between A/AAAA and PTR records
        • Identification of mismatches between forward and reverse DNS
        • Reverse lookup inclusion based on matched forward-record IPs
        • CSV export for reporting and offline analysis

    Internally, the function:
        • Caches all zone records to minimize repeated DNS queries
        • Builds lookup maps for A, AAAA, CNAME, and PTR relationships
        • Resolves CNAME chains recursively with loop detection
        • Normalizes all FQDNs for consistent comparison
        • Reconstructs IPv4 addresses from reverse zones with validation

.PARAMETER DnsServer
    The DNS server to query. Defaults to the local machine.

.PARAMETER Name
    A single DNS name to search for. Accepts pipeline input and common property names.

.PARAMETER Names
    One or more DNS names to search for.

.PARAMETER InputFile
    Path to a file containing one DNS name per line.

.PARAMETER Zone
    Limits the search to specific DNS zones (forward or reverse).

.PARAMETER ExactFqdn
    Forces exact FQDN matching (after normalization).

.PARAMETER MatchMode
    Controls non-exact matching behavior:
        Contains → substring match (broadest, most permissive)
        Suffix   → matches domain suffixes (recommended for most use cases)
        Exact    → exact match (same as -ExactFqdn without switch)

.PARAMETER Types
    Filters output by DNS record type.
    Default: ALL

.PARAMETER CheckDanglingCname
    Identifies CNAME records that do not ultimately resolve to an A or AAAA record.
    Handles multi-level CNAME chains and detects loops.

.PARAMETER CheckPtr
    Correlates A/AAAA records with PTR records and reports:
        Match
        NoPTR
        PTRExists->OtherName
        TargetMissingA
        SkippedIPv6

.PARAMETER OnlyIssues
    Outputs only problematic records:
        • Dangling CNAMEs
        • PTR mismatches or missing PTRs

.PARAMETER IncludeReverseForInputIPs
    Includes PTR records for IPs discovered via matched A/AAAA records,
    even if the PTR target does not match input names.

.PARAMETER OutputCsv
    Writes results to a CSV file.
    Accepts:
        • Full file path
        • Directory (auto-generates filename)

.PARAMETER NoClobber
    Prevents overwriting an existing CSV file.

.PARAMETER Strict
    Enables strict error handling:
        • Zone read failures throw terminating errors
        • DNS RPC issues are surfaced instead of silently ignored

.OUTPUTS
    PSCustomObject with the following fields:
        MatchedName     → Input name that triggered the match
        Direction       → Forward or Reverse
        Zone            → DNS zone name
        Name            → Record owner name
        FQDN            → Fully qualified domain name
        Type            → DNS record type
        Details         → Record-specific metadata
        TTL             → Time-to-live
        Address         → IP address (A/AAAA/PTR)
        CnameTarget     → Target of CNAME
        IsDanglingCname → Boolean flag
        PtrTargets      → PTR targets (if applicable)
        PtrStatus       → PTR correlation result

.NOTES
    • Requires the DnsServer PowerShell module (RSAT DNS tools)
    • Optimized for large enterprise DNS environments
    • Designed for security analysis, DNS hygiene audits, and incident response

    Recommended usage pattern:
        Use -MatchMode Suffix for most environments
        Use -Strict when accuracy is critical

.EXAMPLE
    Find-DnsReferences -Name "server01.contoso.com"

.EXAMPLE
    "server01" | Find-DnsReferences -MatchMode Suffix

.EXAMPLE
    Find-DnsReferences -InputFile .\hosts.txt -CheckPtr -CheckDanglingCname

.EXAMPLE
    Find-DnsReferences -Names "app.contoso.com" -OnlyIssues -Verbose

.LINK
    https://learn.microsoft.com/en-us/powershell/module/dnsserver/
#>

function Find-DnsReferences {
    [CmdletBinding()]
    param(
        [string]$DnsServer = $env:COMPUTERNAME,

        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('CN','ComputerName','HostName')]
        [string]$Name,

        [string[]]$Names,
        [string]$InputFile,
        [string[]]$Zone,

        [switch]$ExactFqdn,

        [ValidateSet('Contains','Suffix','Exact')]
        [string]$MatchMode = 'Contains',

        [string]$OutputCsv,
        [switch]$NoClobber,

        [ValidateSet('ALL','A','AAAA','CNAME','SRV','PTR','TXT','MX','NS','SOA')]
        [string[]]$Types = @('ALL'),

        [switch]$CheckDanglingCname,
        [switch]$CheckPtr,
        [switch]$OnlyIssues,
        [switch]$IncludeReverseForInputIPs,

        [switch]$Strict
    )

    begin {
        $collectedNames = @()
    }

    process {
        if ($PSBoundParameters.ContainsKey('Name') -and -not [string]::IsNullOrWhiteSpace($Name)) {
            $collectedNames += $Name
        }
    }

    end {
        function Normalize-Fqdn {
            param([string]$Value)

            if ([string]::IsNullOrWhiteSpace($Value)) {
                return $null
            }

            $n = $Value.Trim().ToLowerInvariant()
            $n = $n.TrimEnd('.')
            return $n
        }

        function Get-FqdnFromOwner {
            param(
                [string]$HostName,
                [string]$ZoneName
            )

            if ([string]::IsNullOrWhiteSpace($HostName) -or $HostName -eq '@') {
                return (Normalize-Fqdn $ZoneName)
            }

            return (Normalize-Fqdn "$HostName.$ZoneName")
        }

        function Test-IPv4 {
            param([string]$Ip)

            return ($Ip -match '^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$')
        }

        function Convert-ReverseZoneRecordToIPv4 {
            param(
                [string]$ZoneName,
                [string]$HostName
            )

            if ([string]::IsNullOrWhiteSpace($ZoneName) -or $ZoneName -notmatch '\.in-addr\.arpa$') {
                return $null
            }

            $ownerFqdn = if ([string]::IsNullOrWhiteSpace($HostName) -or $HostName -eq '@') {
                $ZoneName
            } else {
                "$HostName.$ZoneName"
            }

            $trimmed = $ownerFqdn -replace '\.in-addr\.arpa\.?$', ''
            $labels  = $trimmed -split '\.'

            if (-not $labels -or $labels.Count -ne 4) {
                return $null
            }

            foreach ($label in $labels) {
                if ($label -notmatch '^\d{1,3}$') {
                    return $null
                }
            }

            [array]::Reverse($labels)
            $ip = $labels -join '.'

            if (Test-IPv4 $ip) {
                return $ip
            }

            return $null
        }

        function Resolve-CnameTerminal {
            param(
                [string]$Name,
                [hashtable]$CnameOwners
            )

            $current = Normalize-Fqdn $Name
            if (-not $current) {
                return $null
            }

            $visited = New-Object 'System.Collections.Generic.HashSet[string]'

            while ($CnameOwners.ContainsKey($current)) {
                if (-not $visited.Add($current)) {
                    return [pscustomobject]@{
                        Terminal = $current
                        Loop     = $true
                    }
                }

                $current = $CnameOwners[$current]
            }

            return [pscustomobject]@{
                Terminal = $current
                Loop     = $false
            }
        }

        function Test-CnameResolvable {
            param(
                [string]$Name,
                [hashtable]$CnameOwners,
                [hashtable]$AByFqdn,
                [hashtable]$AAAAByFqdn
            )

            $resolved = Resolve-CnameTerminal -Name $Name -CnameOwners $CnameOwners
            if (-not $resolved -or $resolved.Loop -or -not $resolved.Terminal) {
                return $false
            }

            $terminal = $resolved.Terminal

            $hasA = $AByFqdn.ContainsKey($terminal) -and $AByFqdn[$terminal].Count -gt 0
            $hasAAAA = $AAAAByFqdn.ContainsKey($terminal) -and $AAAAByFqdn[$terminal].Count -gt 0

            return ($hasA -or $hasAAAA)
        }

        function Test-Match {
            param(
                [string]$Text,
                [object[]]$Matchers,
                [string]$LocalMatchMode,
                [switch]$LocalExactFqdn
            )

            if ([string]::IsNullOrWhiteSpace($Text)) {
                return $null
            }

            $textNorm = Normalize-Fqdn $Text
            if (-not $textNorm) {
                return $null
            }

            foreach ($m in $Matchers) {
                if ($LocalExactFqdn) {
                    if ($textNorm -eq $m.Fqdn) {
                        return $m.Raw
                    }
                    continue
                }

                switch ($LocalMatchMode) {
                    'Exact' {
                        if ($textNorm -eq $m.Fqdn) {
                            return $m.Raw
                        }
                    }
                    'Suffix' {
                        if ($textNorm -eq $m.Fqdn -or $textNorm.EndsWith(".$($m.Fqdn)")) {
                            return $m.Raw
                        }
                    }
                    'Contains' {
                        if ($textNorm -like "*$($m.Fqdn)*") {
                            return $m.Raw
                        }
                    }
                }
            }

            return $null
        }

        function New-ResultRow {
            param(
                [string]$MatchedName,
                [string]$Direction,
                [string]$Zone,
                [string]$Name,
                [string]$FQDN,
                [string]$Type,
                [string]$Details,
                $TTL,
                [string]$Address,
                [string]$CnameTarget,
                [Nullable[bool]]$IsDanglingCname,
                [string]$PtrTargets,
                [string]$PtrStatus
            )

            [pscustomobject]@{
                MatchedName     = $MatchedName
                Direction       = $Direction
                Zone            = $Zone
                Name            = $Name
                FQDN            = $FQDN
                Type            = $Type
                Details         = $Details
                TTL             = $TTL
                Address         = $Address
                CnameTarget     = $CnameTarget
                IsDanglingCname = $IsDanglingCname
                PtrTargets      = $PtrTargets
                PtrStatus       = $PtrStatus
            }
        }

        if (-not (Get-Module -ListAvailable -Name DnsServer)) {
            throw "The DnsServer module is not available. Install RSAT DNS tools or run on a DNS server."
        }

        $allNames = @()

        if ($collectedNames) {
            $allNames += $collectedNames
        }

        if ($Names) {
            $allNames += $Names
        }

        if ($InputFile) {
            if (-not (Test-Path -LiteralPath $InputFile)) {
                throw "InputFile not found: $InputFile"
            }

            $fileNames = Get-Content -LiteralPath $InputFile |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

            $allNames += $fileNames
        }

        if (-not $allNames -or $allNames.Count -eq 0) {
            throw "Provide at least one name via pipeline, -Name, -Names, or -InputFile."
        }

        $allNames = $allNames |
            ForEach-Object { $_.Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique

        $Matchers = foreach ($n in $allNames) {
            $fqdn = Normalize-Fqdn $n
            [pscustomobject]@{
                Raw  = $n
                Fqdn = $fqdn
            }
        }

        $typeFilter = @{}
        $includeAll = $false
        foreach ($t in $Types) {
            if ($t -eq 'ALL') {
                $includeAll = $true
                break
            }
            $typeFilter[$t.ToUpperInvariant()] = $true
        }

        function Should-EmitType {
            param([string]$TypeName)

            if ($includeAll) {
                return $true
            }

            return $typeFilter.ContainsKey($TypeName.ToUpperInvariant())
        }

        $ea = if ($Strict) { 'Stop' } else { 'SilentlyContinue' }

        Write-Verbose "Searching DNS server [$DnsServer] for $($allNames.Count) input name(s)."

        $zones = Get-DnsServerZone -ComputerName $DnsServer -ErrorAction Stop

        if ($Zone) {
            $zones = $zones | Where-Object { $Zone -contains $_.ZoneName }
            if (-not $zones) {
                throw "No matching zones found for: $($Zone -join ', ')"
            }
        }

        $forwardZones = $zones | Where-Object { -not $_.IsReverseLookupZone }
        $reverseZones = $zones | Where-Object { $_.IsReverseLookupZone }

        $zoneCache = @{}
        foreach ($z in $zones) {
            try {
                $zoneCache[$z.ZoneName] = Get-DnsServerResourceRecord `
                    -ComputerName $DnsServer `
                    -ZoneName $z.ZoneName `
                    -ErrorAction $ea
            } catch {
                if ($Strict) {
                    throw
                }
                Write-Verbose "Failed to read zone [$($z.ZoneName)] from [$DnsServer]: $($_.Exception.Message)"
                $zoneCache[$z.ZoneName] = @()
            }
        }

        $AByFqdn        = @{}
        $AAAAByFqdn     = @{}
        $CnameOwners    = @{}
        $PtrTargetsByIp = @{}
        $MatchedInputIPs = [System.Collections.Generic.HashSet[string]]::new()

        foreach ($z in $forwardZones) {
            $recs = $zoneCache[$z.ZoneName]

            foreach ($r in $recs) {
                $fqdn = Get-FqdnFromOwner -HostName $r.HostName -ZoneName $z.ZoneName

                switch ($r.RecordType) {
                    'A' {
                        if ($r.RecordData.IPv4Address) {
                            $ip = $r.RecordData.IPv4Address.ToString()
                            if (-not $AByFqdn.ContainsKey($fqdn)) {
                                $AByFqdn[$fqdn] = [System.Collections.Generic.List[string]]::new()
                            }
                            $AByFqdn[$fqdn].Add($ip)
                        }
                    }
                    'AAAA' {
                        if ($r.RecordData.IPv6Address) {
                            $ip6 = $r.RecordData.IPv6Address.ToString()
                            if (-not $AAAAByFqdn.ContainsKey($fqdn)) {
                                $AAAAByFqdn[$fqdn] = [System.Collections.Generic.List[string]]::new()
                            }
                            $AAAAByFqdn[$fqdn].Add($ip6)
                        }
                    }
                    'CNAME' {
                        if ($r.RecordData.HostNameAlias) {
                            $CnameOwners[$fqdn] = Normalize-Fqdn $r.RecordData.HostNameAlias
                        }
                    }
                }
            }
        }

        foreach ($z in $reverseZones) {
            if ($z.ZoneName -notmatch '\.in-addr\.arpa$') {
                continue
            }

            $recs = $zoneCache[$z.ZoneName] | Where-Object { $_.RecordType -eq 'PTR' }

            foreach ($r in $recs) {
                $ip = Convert-ReverseZoneRecordToIPv4 -ZoneName $z.ZoneName -HostName $r.HostName
                if (-not $ip) {
                    continue
                }

                $ptrTo = Normalize-Fqdn $r.RecordData.PtrDomainName
                if (-not $ptrTo) {
                    continue
                }

                if (-not $PtrTargetsByIp.ContainsKey($ip)) {
                    $PtrTargetsByIp[$ip] = [System.Collections.Generic.List[string]]::new()
                }
                $PtrTargetsByIp[$ip].Add($ptrTo)
            }
        }

        $out = [System.Collections.Generic.List[psobject]]::new(1024)

        foreach ($z in $forwardZones) {
            $recs = $zoneCache[$z.ZoneName]

            foreach ($r in $recs) {
                $fqdn = Get-FqdnFromOwner -HostName $r.HostName -ZoneName $z.ZoneName

                $ownerHit = Test-Match -Text $fqdn -Matchers $Matchers -LocalMatchMode $MatchMode -LocalExactFqdn:$ExactFqdn

                $targetSpecificText = $null
                if ($r.RecordType -eq 'CNAME' -and $r.RecordData.HostNameAlias) {
                    $targetSpecificText = $r.RecordData.HostNameAlias
                } elseif ($r.RecordType -eq 'SRV' -and $r.RecordData.DomainName) {
                    $targetSpecificText = $r.RecordData.DomainName
                }

                $targetHit = Test-Match -Text $targetSpecificText -Matchers $Matchers -LocalMatchMode $MatchMode -LocalExactFqdn:$ExactFqdn

                $otherTargetText = $null
                if ($r.RecordType -eq 'MX' -and $r.RecordData.MailExchange) {
                    $otherTargetText = $r.RecordData.MailExchange
                } elseif ($r.RecordType -eq 'NS' -and $r.RecordData.NameServer) {
                    $otherTargetText = $r.RecordData.NameServer
                }

                $otherHit = Test-Match -Text $otherTargetText -Matchers $Matchers -LocalMatchMode $MatchMode -LocalExactFqdn:$ExactFqdn

                $matchedName = $null
                if ($ownerHit) {
                    $matchedName = $ownerHit
                } elseif ($targetHit) {
                    $matchedName = $targetHit
                } elseif ($otherHit) {
                    $matchedName = $otherHit
                }

                if (-not $matchedName) {
                    continue
                }

                if (-not (Should-EmitType $r.RecordType)) {
                    continue
                }

                $addr = $null
                $details = $null
                $cnameTarget = $null
                $isDangling = $null
                $ptrTargets = $null
                $ptrStatus = $null

                switch ($r.RecordType) {
                    'A' {
                        if ($r.RecordData.IPv4Address) {
                            $addr = $r.RecordData.IPv4Address.ToString()
                        }

                        $details = 'IPv4'

                        if ($addr) {
                            [void]$MatchedInputIPs.Add($addr)
                        }

                        if ($CheckPtr -and $addr) {
                            if ($PtrTargetsByIp.ContainsKey($addr)) {
                                $targets = $PtrTargetsByIp[$addr]
                                $uniqTargets = $targets | Select-Object -Unique
                                $ptrTargets = $uniqTargets -join '; '

                                if ($targets -contains $fqdn) {
                                    $ptrStatus = 'Match'
                                } else {
                                    $ptrStatus = "PTRExists->OtherName($($uniqTargets.Count))"
                                }
                            } else {
                                $ptrStatus = 'NoPTR'
                            }
                        }
                    }

                    'AAAA' {
                        if ($r.RecordData.IPv6Address) {
                            $addr = $r.RecordData.IPv6Address.ToString()
                        }

                        $details = 'IPv6'

                        if ($CheckPtr) {
                            $ptrStatus = 'SkippedIPv6'
                        }
                    }

                    'CNAME' {
                        $cnameTarget = Normalize-Fqdn $r.RecordData.HostNameAlias
                        $details = "AliasTo=$cnameTarget"

                        if ($CheckDanglingCname) {
                            $isDangling = -not (Test-CnameResolvable `
                                -Name $cnameTarget `
                                -CnameOwners $CnameOwners `
                                -AByFqdn $AByFqdn `
                                -AAAAByFqdn $AAAAByFqdn)
                        }
                    }

                    'SRV' {
                        $details = "Target=$($r.RecordData.DomainName); Port=$($r.RecordData.Port); Priority=$($r.RecordData.Priority); Weight=$($r.RecordData.Weight)"
                    }

                    'TXT' {
                        $txt = $null
                        try {
                            $txt = $r.RecordData.DescriptiveText
                        } catch {
                            $txt = $null
                        }

                        if ($txt -is [System.Array]) {
                            $details = ($txt -join ' ')
                        } else {
                            $details = $txt
                        }
                    }

                    'MX' {
                        $details = "Exchange=$($r.RecordData.MailExchange); Preference=$($r.RecordData.Preference)"
                    }

                    'NS' {
                        $details = "NameServer=$($r.RecordData.NameServer)"
                    }

                    'SOA' {
                        $details = "MName=$($r.RecordData.PrimaryServer); RName=$($r.RecordData.ResponsiblePerson); Serial=$($r.RecordData.SerialNumber)"
                    }

                    default {
                        $details = $r.RecordType
                    }
                }

                $row = New-ResultRow `
                    -MatchedName $matchedName `
                    -Direction 'Forward' `
                    -Zone $z.ZoneName `
                    -Name $r.HostName `
                    -FQDN $fqdn `
                    -Type $r.RecordType `
                    -Details $details `
                    -TTL $r.TimeToLive `
                    -Address $addr `
                    -CnameTarget $cnameTarget `
                    -IsDanglingCname $isDangling `
                    -PtrTargets $ptrTargets `
                    -PtrStatus $ptrStatus

                if ($OnlyIssues) {
                    $hasIssue = $false

                    if ($CheckDanglingCname -and $r.RecordType -eq 'CNAME' -and $isDangling) {
                        $hasIssue = $true
                    }

                    if ($CheckPtr -and ($r.RecordType -eq 'A' -or $r.RecordType -eq 'AAAA') -and $ptrStatus -and $ptrStatus -ne 'Match') {
                        $hasIssue = $true
                    }

                    if (-not $hasIssue) {
                        continue
                    }
                }

                $out.Add($row)
            }
        }

        foreach ($z in $reverseZones) {
            $isIPv4Zone = ($z.ZoneName -match '\.in-addr\.arpa$')
            $recs = $zoneCache[$z.ZoneName] | Where-Object { $_.RecordType -eq 'PTR' }

            foreach ($r in $recs) {
                $ptrToFqdn = Normalize-Fqdn $r.RecordData.PtrDomainName
                $addr = $null

                if ($isIPv4Zone) {
                    $addr = Convert-ReverseZoneRecordToIPv4 -ZoneName $z.ZoneName -HostName $r.HostName
                }

                $matchedName = Test-Match -Text $ptrToFqdn -Matchers $Matchers -LocalMatchMode $MatchMode -LocalExactFqdn:$ExactFqdn
                $includedByIp = $false

                if (-not $matchedName) {
                    if (-not $IncludeReverseForInputIPs -or -not $addr) {
                        continue
                    }

                    if (-not $MatchedInputIPs.Contains($addr)) {
                        continue
                    }

                    $matchedName = '[RelatedByIP]'
                    $includedByIp = $true
                }

                if (-not (Should-EmitType 'PTR')) {
                    continue
                }

                $ptrStatus = $null
                if ($CheckPtr -and $isIPv4Zone -and $addr -and $ptrToFqdn) {
                    if ($AByFqdn.ContainsKey($ptrToFqdn) -and $AByFqdn[$ptrToFqdn].Count -gt 0) {
                        if ($AByFqdn[$ptrToFqdn] -contains $addr) {
                            $ptrStatus = 'Match'
                        } else {
                            $ptrStatus = 'PTR->OtherName'
                        }
                    } else {
                        $ptrStatus = 'TargetMissingA'
                    }
                }

                $detailText = $r.RecordData.PtrDomainName
                if ($includedByIp) {
                    $detailText = "$detailText (related by A/AAAA IP)"
                }

                $row = New-ResultRow `
                    -MatchedName $matchedName `
                    -Direction 'Reverse' `
                    -Zone $z.ZoneName `
                    -Name $r.HostName `
                    -FQDN $null `
                    -Type 'PTR' `
                    -Details $detailText `
                    -TTL $r.TimeToLive `
                    -Address $addr `
                    -CnameTarget $null `
                    -IsDanglingCname $null `
                    -PtrTargets $null `
                    -PtrStatus $ptrStatus

                if ($OnlyIssues) {
                    if (-not $CheckPtr -or (-not $ptrStatus -or $ptrStatus -eq 'Match')) {
                        continue
                    }
                }

                $out.Add($row)
            }
        }

        if ($OutputCsv) {
            $csvPath = $OutputCsv
            $isDir = $false

            if (Test-Path -LiteralPath $OutputCsv -PathType Container) {
                $isDir = $true
            }

            if ($isDir) {
                $fileName = 'dns-references_{0:yyyyMMdd_HHmmss}.csv' -f (Get-Date)
                $csvPath = Join-Path -Path $OutputCsv -ChildPath $fileName
            } else {
                $parent = Split-Path -Path $OutputCsv -Parent
                if ($parent -and -not (Test-Path -LiteralPath $parent -PathType Container)) {
                    New-Item -ItemType Directory -Path $parent -Force | Out-Null
                }
            }

            if ($NoClobber -and (Test-Path -LiteralPath $csvPath)) {
                throw "CSV already exists and -NoClobber is set: $csvPath"
            }

            $out |
                Sort-Object MatchedName, Direction, Zone, Type, Name |
                Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

            Write-Verbose "CSV written: $csvPath"
        }

        $out | Sort-Object MatchedName, Direction, Zone, Type, Name
    }
}
