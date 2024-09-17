

function Create-JwtHeaderPayload {
    param (
        [Parameter(Mandatory = $true)]
        [string]$AppID,

        [Parameter(Mandatory = $true)]
        [string]$TenantID,

        [Parameter(Mandatory = $true)]
        [string]$CertHash,

        [Parameter()]
        [string]$Scope = "https://graph.windows.net/.default offline_access openid"
    )

    $audience = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"

    
    $StartDate = [datetime]::UtcNow.AddSeconds(-10)
    $EndDate = [datetime]::UtcNow.AddMinutes(5)
    $JWTExpiration = [math]::Round(($EndDate - [datetime]"1970-01-01T00:00:00Z").TotalSeconds)
    $NotBefore = [math]::Round(($StartDate - [datetime]"1970-01-01T00:00:00Z").TotalSeconds)

    
    $jwtHeader = @{
        'alg' = "RS256"
        'typ' = "JWT"
        'x5t' = $CertHash
    }

   
    $jwtPayload = @{
        'aud' = $audience
        'exp' = $JWTExpiration
        'iss' = $AppID
        'jti' = [guid]::NewGuid().ToString()
        'nbf' = $NotBefore
        'sub' = $AppID
        'scp' = $Scope
    }

    return @{
        Header = $jwtHeader
        Payload = $jwtPayload
    }
}


function Get-KeyVaultSignedJwt {
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantID,

        [Parameter(Mandatory = $true)]
        [string]$AppID,

        [Parameter(Mandatory = $true)]
        [string]$KeyVaultName,

        [Parameter(Mandatory = $true)]
        [string]$CertName,

        [Parameter(Mandatory = $true)]
        [string]$KeyToken,

        [Parameter()]
        [string]$Scope = "https://graph.windows.net/.default offline_access openid"
    )

    $vaultUri = "https://$KeyVaultName.vault.azure.net"
    $uri = "$vaultUri/certificates/$($CertName)?api-version=7.3"
    $httpResponse = Invoke-RestMethod -Uri $uri -Headers @{ 'Authorization' = "Bearer $KeyToken" }
    $keycert = $httpResponse

    $certificateHash = $keycert.x5t
    $jwtParts = Create-JwtHeaderPayload -AppID $AppID -TenantID $TenantID -CertHash $certificateHash -Scope $Scope

    
    $jwtHeaderBytes = [System.Text.Encoding]::UTF8.GetBytes(($jwtParts.Header | ConvertTo-Json -Compress))
    $jwtPayloadBytes = [System.Text.Encoding]::UTF8.GetBytes(($jwtParts.Payload | ConvertTo-Json -Compress))
    $b64JwtHeader = [Convert]::ToBase64String($jwtHeaderBytes) -replace '\+','-' -replace '/','_' -replace '='
    $b64JwtPayload = [Convert]::ToBase64String($jwtPayloadBytes) -replace '\+','-' -replace '/','_' -replace '='

   
    $unsignedJwt = "$b64JwtHeader.$b64JwtPayload"
    $unsignedJwtBytes = [System.Text.Encoding]::UTF8.GetBytes($unsignedJwt)
    $hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
    $jwtSha256Hash = $hasher.ComputeHash($unsignedJwtBytes)
    $jwtSha256HashB64 = [Convert]::ToBase64String($jwtSha256Hash) -replace '\+','-' -replace '/','_' -replace '='

    
$signUri = "$($keycert.kid)/sign?api-version=7.3"
$signResponse = Invoke-RestMethod -Uri $signUri -Method POST -Headers @{
    'Authorization' = "Bearer $($KeyToken)"
    'Content-Type'  = 'application/json'
} -Body ([ordered]@{
    'alg'   = 'RS256'
    'value' = $jwtSha256HashB64
} | ConvertTo-Json)

$signature = $signResponse.value

   


$signedJWT = $unsignedJwt + "." + $signature

    
    $uri = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
    $headers = @{'Content-Type' = 'application/x-www-form-urlencoded'}
    $body = @{
        'client_id' = $AppID
        'client_assertion' = $signedJWT
        'client_assertion_type' = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        'scope' = $Scope
        'grant_type' = 'client_credentials'
    }

    try {
        
        $response = Invoke-RestMethod -Uri $uri -Method POST -Headers $headers -Body $body
        return $response
    } catch {
        Write-Error "Failed to obtain access token: $_"
    }
}


function Get-CertificateToken {
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$ClientCertificate,

        [Parameter(Mandatory = $true)]
        [string]$TenantID,

        [Parameter(Mandatory = $true)]
        [string]$AppID,

        [Parameter()]
        [string]$Scope = "https://graph.windows.net/.default offline_access openid"
    )

    $audience = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"

    
    $certificateHash = [System.Convert]::ToBase64String($ClientCertificate.GetCertHash()) -replace '\+','-' -replace '/','_' -replace '='

    
    $jwtParts = Create-JwtHeaderPayload -AppID $AppID -TenantID $TenantID -CertHash $certificateHash -Scope $Scope

    
    $jwtHeaderBytes = [System.Text.Encoding]::UTF8.GetBytes(($jwtParts.Header | ConvertTo-Json -Compress))
    $jwtPayloadBytes = [System.Text.Encoding]::UTF8.GetBytes(($jwtParts.Payload | ConvertTo-Json -Compress))
    $b64JwtHeader = [Convert]::ToBase64String($jwtHeaderBytes) -replace '\+','-' -replace '/','_' -replace '='
    $b64JwtPayload = [Convert]::ToBase64String($jwtPayloadBytes) -replace '\+','-' -replace '/','_' -replace '='

    
    $unsignedJwt = "$b64JwtHeader.$b64JwtPayload"

    
    $privateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($ClientCertificate)
    $signedData = $privateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($unsignedJwt), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $signature = [Convert]::ToBase64String($signedData) -replace '\+','-' -replace '/','_' -replace '='

    
    $signedJWT = "$unsignedJwt.$signature"

    
    $uri = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
    $headers = @{'Content-Type' = 'application/x-www-form-urlencoded'}
    $body = @{
        'client_id' = $AppID
        'client_assertion' = $signedJWT
        'client_assertion_type' = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        'scope' = $Scope
        'grant_type' = 'client_credentials'
    }

    try {
        
        $response = Invoke-RestMethod -Uri $uri -Method POST -Headers $headers -Body $body
        return $response
    } catch {
        Write-Error "Failed to obtain access token: $_"
    }
}

