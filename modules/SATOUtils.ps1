
function Fix-Base64Padding {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Base64String
    )
    while ($Base64String.Length % 4) {
        $Base64String += "="
    }
    return $Base64String
}


function Convert-FromEpoch {
    param (
        [Parameter(Mandatory = $true)]
        [int64]$EpochTime
    )
    return [System.DateTimeOffset]::FromUnixTimeSeconds($EpochTime).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
}


function Decode-Base64 {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Base64String
    )
    return [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($Base64String))
}



function Decode-Jwt {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    try {
        
        if (!$Token.Contains(".") -or !$Token.StartsWith("eyJ")) {
            throw "Invalid token format"
        }

       
        $TokenParts = $Token.Split(".")
        $HeaderBase64 = Fix-Base64Padding -Base64String $TokenParts[0].Replace('-', '+').Replace('_', '/')
        $HeaderJson = Decode-Base64 -Base64String $HeaderBase64
        $HeaderObject = $HeaderJson | ConvertFrom-Json

        
        $PayloadBase64 = Fix-Base64Padding -Base64String $TokenParts[1].Replace('-', '+').Replace('_', '/')
        $PayloadJson = Decode-Base64 -Base64String $PayloadBase64
        $PayloadObject = $PayloadJson | ConvertFrom-Json

        
        $ClaimDescriptions = @{
            aud = "Audience"
            iss = "Issuer"
            iat = "Issued At"
            nbf = "Not Before"
            exp = "Expiration Time"
            acr = "Authentication Context Class Reference"
            aio = "Authentication Information"
            amr = "Authentication Methods References"
            appid = "Application ID"
            appidacr = "Application ID Authentication Context Class Reference"
            idtyp = "Identity Type"
            ipaddr = "IP Address"
            name = "Name"
            oid = "Object ID"
            puid = "Personal User ID"
            rh = "Refresh Token"
            scp = "Scope"
            sub = "Subject"
            tid = "Tenant ID"
            unique_name = "Unique Name"
            upn = "User Principal Name"
            uti = "Token Unique ID"
            ver = "Token Version"
            xms_idrel = "ID Token Restrictions"
        }

        $PayloadObjectWithDescriptions = @{}
        foreach ($claim in $PayloadObject.PSObject.Properties) {
            $description = $ClaimDescriptions[$claim.Name]
            if ($description) {
                $PayloadObjectWithDescriptions.Add($description, $claim.Value)
            } else {
                $PayloadObjectWithDescriptions.Add($claim.Name, $claim.Value)
            }
        }

        
        if ($PayloadObject.iat) { $PayloadObjectWithDescriptions["Issued At"] = Convert-FromEpoch -EpochTime $PayloadObject.iat }
        if ($PayloadObject.nbf) { $PayloadObjectWithDescriptions["Not Before"] = Convert-FromEpoch -EpochTime $PayloadObject.nbf }
        if ($PayloadObject.exp) { $PayloadObjectWithDescriptions["Expiration Time"] = Convert-FromEpoch -EpochTime $PayloadObject.exp }

        
        Write-Host "Decoded JWT Token:" -ForegroundColor DarkGreen
        Write-Host "Header:" -ForegroundColor Yellow
        $HeaderObject | ConvertTo-Json -Depth 10 | Write-Host -ForegroundColor White
        Write-Host "`nPayload:" -ForegroundColor Yellow
        foreach ($key in $PayloadObjectWithDescriptions.Keys) {
            $value = $PayloadObjectWithDescriptions[$key]
            if ($ClaimDescriptions.ContainsValue($key)) {
                Write-Host "$($key):" -ForegroundColor Green -NoNewline
            } else {
                Write-Host "$($key):" -ForegroundColor Red -NoNewline
            }
            Write-Host " $value" -ForegroundColor White
        }
    } catch {
        Write-Error "Error decoding JWT: $_"
    }
}





Export-ModuleMember -Function Fix-Base64Padding, Convert-FromEpoch, Decode-Base64, Decode-Jwt
