
$manifest = Import-PowerShellDataFile "$PSScriptRoot\SATO.psd1"
$version = $manifest.ModuleVersion
$host.ui.RawUI.WindowTitle = "SATO v$version"


$banner = @"
  
   ____/\\\\\\\\\\\____        _____/\\\\\\\\\____        __/\\\\\\\\\\\\\\\___        _______/\\\\\______        
    __/\\\/////////\\\_        ___/\\\\\\\\\\\\\\\__        _\///////\\\/////__        _____/\\\///\\\____        
     _\//\\\______\///__        __/\\\/////////\\\_        _______\/\\\_______        ___/\\\/__\///\\\__         
      __\////\\\_________        _\/\\\_______\/\\\_        _______\/\\\_______        __/\\\______\//\\\_       
       _____\////\\\______        _\/\\\\\\\\\\\\\\\_        _______\/\\\_______        _\/\\\_______\/\\\_      
        _______\////\\\___        _\/\\\/////////\\\_        _______\/\\\_______        _\//\\\______/\\\__     
         __/\\\______\//\\\__      _\/\\\_______\/\\\_        _______\/\\\_______        __\///\\\__/\\\____    
          _\///\\\\\\\\\\\/___      _\/\\\_______\/\\\_        _______\/\\\_______        ____\///\\\\\/_____    
           ___\///////////____       _\///________\///__        _______\///________        _______\/////_______
                                                                                                             
                 _________  Secure Azure Token Operations  ___________                                       
                            Version $version                                                  
                          by Edrian Miranda aka ObiKuro                                     

"@


Write-Host $banner -ForegroundColor DarkGreen

Write-Host "--------------------------------------------------------------------------------------------------------------------------" -ForegroundColor DarkGreen








$modulesPath = Join-Path -Path $PSScriptRoot -ChildPath 'modules'
$scripts = Get-ChildItem -Path "$modulesPath\*.ps1" -ErrorAction SilentlyContinue

foreach ($script in $scripts) {
    try {
        . $script.FullName
    } catch {
        Write-Error "Failed to import $($script.FullName): $_"
    }
}


$PredefinedScopes = @{
    MsGraph = "https://graph.microsoft.com/.default offline_access openid"
    MSTeams = "https://api.spaces.skype.com/.default offline_access openid"
    Office = "https://manage.office.com/.default offline_access openid"
    Outlook = "https://outlook.office365.com/.default offline_access openid"
    WinGraph = "https://graph.windows.net/.default offline_access openid"
    CoreARM = "https://management.core.windows.net/.default offline_access openid"
    MaARM = "https://management.azure.com/.default offline_access openid"
    IntuneMam = "https://intunemam.microsoftonline.com/.default offline_access openid"
    SharePoint = "https://$SharePointTenantName$AdminSuffix.sharepoint.com/Sites.FullControl.All offline_access openid"
    OneDrive = "https://officeapps.live.com/.default offline_access openid"
    KeyVault = "https://vault.azure.net/.default offline_access openid"
}


$PredefinedGrantTypes = @(
    "client_credentials",
    "password",
    "refresh_token",
    "device_code",
    "jwt_assertion",
    "jwt_assertion_sign"
)


$PredefinedUserAgents = @{
    Windows10Chrome  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    Windows10Edge    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
    Windows10Firefox = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
    MacOSSafari      = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
    MacOSChrome      = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    LinuxFirefox     = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
    AndroidChrome    = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
    iOSSafari        = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
    ChromeOS         = "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    WindowsPhone     = "Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; Lumia 950) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.15254"
}


function Invoke-Sato {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("client_credentials", "password", "refresh_token", "device_code", "jwt_assertion", "jwt_assertion_sign")]
        [string]$GrantType,

        [Parameter(Mandatory = $true)]
        [string]$TenantID,

        [Parameter()]
        [string]$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c", # Default to Microsoft Office client ID

        [Parameter()]
        [string]$ClientSecret,

        [Parameter()]
        [string]$Username,

        [Parameter()]
        [string]$Password,

        [Parameter()]
        [string]$Scope = "https://graph.windows.net/.default offline_access openid",

        [Parameter()]
        [string]$RefreshToken,

        [Parameter()]
        [switch]$Decode,

        [Parameter()]
        [switch]$UseCAE,

        [Parameter()]
        [string]$AppID,

        [Parameter()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter()]
        [string]$CertificatePath,

        [Parameter()]
        [string]$KeyVaultName,

        [Parameter()]
        [string]$CertName,

        [Parameter()]
        [string]$KeyToken,

        [Parameter(Mandatory = $false)]
        [ValidateSet("MsGraph", "MSTeams", "Office", "Outlook", "WinGraph", "CoreARM", "MaARM", "IntuneMam", "SharePoint", "OneDrive", "KeyVault")]
        [string]$PredefinedScope,

        [Parameter()]
        [string]$UserAgent,

        [Parameter()]
        [ValidateSet("Windows10Chrome", "Windows10Edge", "Windows10Firefox", "MacOSSafari", "MacOSChrome", "LinuxFirefox", "AndroidChrome", "iOSSafari", "ChromeOS", "WindowsPhone")]
        [string]$PredefinedUserAgent
    )


    if ($PredefinedScope) {
        $Scope = $PredefinedScopes[$PredefinedScope]
    }


    if ($PredefinedUserAgent) {
        $UserAgent = $PredefinedUserAgents[$PredefinedUserAgent]
    }

    if ($UserAgent) {
        Write-Host "Using User-Agent: $UserAgent" -ForegroundColor Cyan
    }

    
    if ($GrantType -eq "jwt_assertion" -and !$Certificate) {
        if ($CertificatePath) {
            try {
                Write-Host "Loading certificate from file: $CertificatePath" -ForegroundColor Cyan
                $securePwd = Read-Host "Enter the certificate password" -AsSecureString
                $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                $Certificate.Import($CertificatePath, $securePwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
            } catch {
                Write-Error "Failed to load certificate from path: $CertificatePath. Error: $_"
                return
            }
        } else {
            Write-Error "Either a Certificate variable or CertificatePath must be provided for JWT assertion."
            return
        }
    }

    switch ($GrantType) {
        "password" {
            $response = Get-PasswordToken -TenantID $TenantID -ClientID $ClientID -Username $Username -Password $Password -Scope $Scope -UserAgent $UserAgent
        }

        "client_credentials" {
            $response = Get-ClientCredentialsToken -TenantID $TenantID -ClientID $ClientID -ClientSecret $ClientSecret -Scope $Scope -UserAgent $UserAgent
        }

        "refresh_token" {
            $response = Get-RefreshToken -TenantID $TenantID -ClientID $ClientID -RefreshToken $RefreshToken -Scope $Scope -UserAgent $UserAgent
        }

        "device_code" {
            $response = Get-DeviceCodeToken -TenantID $TenantID -ClientID $ClientID -Scope $Scope -UseCAE:$UseCAE -UserAgent $UserAgent
        }

        "jwt_assertion" {
            if ($Certificate) {
                Write-Host "Using local certificate for JWT assertion" -ForegroundColor Cyan
                $response = Get-CertificateToken -ClientCertificate $Certificate -TenantID $TenantID -AppID $AppID -Scope $Scope -UserAgent $UserAgent
            } else {
                Write-Error "A certificate must be provided for JWT assertion."
                return
            }
        }

        "jwt_assertion_sign" {
            if ($KeyVaultName -and $CertName -and $KeyToken) {
                Write-Host "Using Azure Key Vault for JWT assertion signing" -ForegroundColor DarkGreen
                $response = Get-KeyVaultSignedJwt -TenantID $TenantID -AppID $AppID -KeyVaultName $KeyVaultName -CertName $CertName -KeyToken $KeyToken -Scope $Scope -UserAgent $UserAgent

            } else {
                Write-Error "Key Vault details must be provided for JWT assertion signing."
                return
            }
        }

        default {
            Write-Error "Unsupported grant type: $GrantType"
            return
        }
    }

    if ($response) {
        Write-Host "Access Token:" -ForegroundColor DarkGreen
        Write-Output $response.access_token

        if ($response.refresh_token) {
            Write-Host "Refresh Token:" -ForegroundColor DarkGreen
            Write-Output $response.refresh_token
        }

        if ($Decode) {
            Decode-Jwt -Token $response.access_token
        }
    }
}


Export-ModuleMember -Function Invoke-Sato
