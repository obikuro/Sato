
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
        [string]$Scope,

        [Parameter()]
        [string]$UserAgent
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

        $restArgs = @{
            Uri         = $Url
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Body        = $RequestParams
        }
        if ($UserAgent) { $restArgs.Headers = @{ 'User-Agent' = $UserAgent } }

        $response = Invoke-RestMethod @restArgs
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
        [string]$Scope,

        [Parameter()]
        [string]$UserAgent
    )

    try {
        $Url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
        $RequestParams = @{
            client_id     = $ClientID
            client_secret = $ClientSecret
            grant_type    = "client_credentials"
            scope         = $Scope
        }

        $restArgs = @{
            Uri         = $Url
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Body        = $RequestParams
        }
        if ($UserAgent) { $restArgs.Headers = @{ 'User-Agent' = $UserAgent } }

        $response = Invoke-RestMethod @restArgs
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
        [string]$Scope,

        [Parameter()]
        [string]$UserAgent
    )

    try {
        $Url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
        $RequestParams = @{
            client_id     = $ClientID
            refresh_token = $RefreshToken
            grant_type    = "refresh_token"
            scope         = $Scope
        }

        $restArgs = @{
            Uri         = $Url
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Body        = $RequestParams
        }
        if ($UserAgent) { $restArgs.Headers = @{ 'User-Agent' = $UserAgent } }

        $response = Invoke-RestMethod @restArgs
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
        [switch]$UseCAE,

        [Parameter()]
        [string]$UserAgent
    )

    try {

        $uaHeaders = @{}
        if ($UserAgent) { $uaHeaders['User-Agent'] = $UserAgent }

        $deviceCodeUrl = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/devicecode"
        $deviceCodeBody = @{
            client_id = $ClientID
            scope     = $Scope
        }

        $dcArgs = @{
            Uri         = $deviceCodeUrl
            Method      = 'Post'
            ContentType = 'application/x-www-form-urlencoded'
            Body        = $deviceCodeBody
        }
        if ($UserAgent) { $dcArgs.Headers = $uaHeaders }

        $authResponse = Invoke-RestMethod @dcArgs
        
        
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
                $tokArgs = @{
                    Uri         = $tokenUrl
                    Method      = 'Post'
                    ContentType = 'application/x-www-form-urlencoded'
                    Body        = $tokenBody
                    ErrorAction = 'SilentlyContinue'
                }
                if ($UserAgent) { $tokArgs.Headers = $uaHeaders }
                $response = Invoke-RestMethod @tokArgs
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
