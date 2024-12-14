
# Handles different OAuth2 authentication grant types

function Get-PasswordToken {
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantID,

        [Parameter(Mandatory = $true)]
        [string]$ClientID,

        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $true)]
        [string]$Password,

        [Parameter(Mandatory = $true)]
        [string]$Scope
    )

    try {
        $Url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
        $RequestParams = @{
            client_id  = $ClientID
            grant_type = "password"
            username   = $Username
            password   = $Password
            scope      = $Scope
        }

        $response = Invoke-RestMethod -Uri $Url -Method POST -ContentType "application/x-www-form-urlencoded" -Body $RequestParams
        return $response
    } catch {
        Write-Error "Error obtaining password-based access token: $_"
    }
}

function Get-ClientCredentialsToken {
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantID,

        [Parameter(Mandatory = $true)]
        [string]$ClientID,

        [Parameter(Mandatory = $true)]
        [string]$ClientSecret,

        [Parameter(Mandatory = $true)]
        [string]$Scope
    )

    try {
        $Url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
        $RequestParams = @{
            client_id     = $ClientID
            client_secret = $ClientSecret
            grant_type    = "client_credentials"
            scope         = $Scope
        }

        $response = Invoke-RestMethod -Uri $Url -Method POST -ContentType "application/x-www-form-urlencoded" -Body $RequestParams
        return $response
    } catch {
        Write-Error "Error obtaining client credentials-based access token: $_"
    }
}

function Get-RefreshToken {
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantID,

        [Parameter(Mandatory = $true)]
        [string]$ClientID,

        [Parameter(Mandatory = $true)]
        [string]$RefreshToken,

        [Parameter(Mandatory = $true)]
        [string]$Scope
    )

    try {
        $Url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
        $RequestParams = @{
            client_id     = $ClientID
            refresh_token = $RefreshToken
            grant_type    = "refresh_token"
            scope         = $Scope
        }

        $response = Invoke-RestMethod -Uri $Url -Method POST -ContentType "application/x-www-form-urlencoded" -Body $RequestParams
        return $response
    } catch {
        Write-Error "Error obtaining refresh token-based access token: $_"
    }
}


function Get-DeviceCodeToken {
    param (
        [Parameter()]
        [string]$TenantID = "common",

        [Parameter()]
        [string]$ClientID,  # Default to Microsoft Office client ID

        [Parameter()]
        [string]$Scope ,

        [Parameter()]
        [switch]$UseCAE
    )

    try {
        
        $deviceCodeUrl = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/devicecode"
        $deviceCodeBody = @{
            client_id = $ClientID
            scope     = $Scope
        }

        $authResponse = Invoke-RestMethod -Uri $deviceCodeUrl -Method Post -ContentType "application/x-www-form-urlencoded" -Body $deviceCodeBody
        
        
        Write-Host $authResponse.message -ForegroundColor Yellow
        
        
        $tokenUrl = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
        $tokenBody = @{
            client_id  = $ClientID
            grant_type = "urn:ietf:params:oauth:grant-type:device_code"
            device_code = $authResponse.device_code
        }

        if ($UseCAE) {
            # Add 'cp1' as client claim to get a token valid for 24 hours
            $Claims = ( @{ "access_token" = @{ "xms_cc" = @{ "values" = @("cp1") } } } | ConvertTo-Json -Compress -Depth 99 )
            $tokenBody.Add("claims", $Claims)
        }

        $continue = $true
        $interval = $authResponse.interval
        $expires = $authResponse.expires_in
        $total = 0

        while ($continue) {
            Start-Sleep -Seconds $interval
            $total += $interval

            if ($total -gt $expires) {
                Write-Error "Timeout occurred while waiting for device code authorization."
                return
            }

            try {
                $response = Invoke-RestMethod -Uri $tokenUrl -Method Post -ContentType "application/x-www-form-urlencoded" -Body $tokenBody -ErrorAction SilentlyContinue
            } catch {
                $errorDetails = $_.ErrorDetails.Message | ConvertFrom-Json
                $continue = $errorDetails.error -eq "authorization_pending"

                if (!$continue) {
                    Write-Error $errorDetails.error_description
                    return
                }
            }

            if ($response) {
                return $response
            }
        }

    } catch {
        Write-Error "Error obtaining token via device code: $_"
    }
}


function Get-EstsAuthCookieToken {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("1fec8e78-bce4-4aaf-ab1b-5451cc387264", "1950a258-227b-4e31-a9cf-717495945fc2", "ecd6b820-32c2-49b6-98a6-444530e5a77a")]
        [string]$ClientID,

        [Parameter(Mandatory = $true)]
        [string]$ESTSAuthCookie,

        [Parameter(Mandatory = $true)]
        [string]$Scope
    )

    $Resource = ($Scope.Split('/')[0..2] -join '/') + '/'

    $Headers = @{}
    $cookie = "ESTSAUTH=$($ESTSAuthCookie)"
    $session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
    $cookie = [System.Net.Cookie]::new("ESTSAUTH", "$($ESTSAuthCookie)")
    $session.Cookies.Add('https://login.microsoftonline.com/', $cookie)
    $state = [System.Guid]::NewGuid().ToString()
    $redirect_uri = ([System.Uri]::EscapeDataString("https://login.microsoftonline.com/common/oauth2/nativeclient"))

    try {
        if ($PSVersionTable.PSVersion.Major -lt 7) {
            $sts_response = Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri "https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=$($ClientID)&resource=$($Resource)&redirect_uri=$($redirect_uri)&state=$($state)" -Headers $Headers
        } else {
            $sts_response = Invoke-WebRequest -UseBasicParsing -SkipHttpErrorCheck -MaximumRedirection 0 -ErrorAction SilentlyContinue -WebSession $session -Method Get -Uri "https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=$($ClientID)&resource=$($Resource)&redirect_uri=$($redirect_uri)&state=$($state)" -Headers $Headers
        }

        if ($sts_response.StatusCode -eq 302) {
            $uri = if ($PSVersionTable.PSVersion.Major -lt 7) {
                [System.Uri]$sts_response.Headers.Location
            } else {
                [System.Uri]$sts_response.Headers.Location[0]
            }

            $query = $uri.Query.TrimStart('?')
            $queryParams = @{ }
            $paramPairs = $query.Split('&')

            foreach ($pair in $paramPairs) {
                $parts = $pair.Split('=')
                $key = $parts[0]
                $value = $parts[1]
                $queryParams[$key] = $value
            }

            if ($queryParams.ContainsKey('code')) {
                $refreshToken = $queryParams['code']
            } else {
                throw [System.Exception] "Authorization code not found in redirected URL path. Redirect Location: $($sts_response.Headers.Location | Out-String)"
            }
        } else {
            throw [System.Exception] "No redirect from authorization code request. Full response: $($sts_response.RawContent | Out-String)"
        }

        if ($refreshToken) {
            $body = @{
                "resource"     = $Resource
                "client_id"    = $ClientID
                "grant_type"   = "authorization_code"
                "redirect_uri" = "https://login.microsoftonline.com/common/oauth2/nativeclient"
                "code"         = $refreshToken
                "scope"        = "openid"
            }

            $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/token" -Headers $Headers -Body $body
            return $response
        }
    } catch {
        throw [System.Exception] "Error during token retrieval: $($_.Exception.Message)"
    }
}
