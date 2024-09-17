# SATO (Secure Azure Token Operations)

**SATO**  is a specialized toolkit designed to assist a red teamer in effectively managing Azure tokens, enabling advanced manipulation of oauth 2.0 grant types used in Azure authentication mechanisms. This tool was built with offensive operations in mind, where tokens play a critical role in maintaining access and persistence in cloud environments.

## Why SATO?

Azure assessments often present scenarios where credentials or certificates might be exposed, such as compromised passwords, service principal secrets, or certificates. If the opposite side is aware of the compromise and changes these credentials, tokens like access or refresh tokens remain valid until they expire. **SATO** capitalizes on this, offering red teams a way to continue their operations by working directly with these tokens.

Moreover, **tokens can bypass Conditional Access Policies (CAP)** that enforce Multi-Factor Authentication (MFA) based on factors such as location and some others. CAPs are checked during authentication, while an **access token** is used for authorization. Since tokens are issued post-authentication, they can bypass such controls, making them a powerful tool for persistence.

**SATO** helps you exchange various pieces of authentication information (like passwords, client secrets, certificates, or permissions such as Key Vault signing) for valid **access** and **refresh tokens**. This approach ensures that even if primary credentials are invalidated, tokens can be leveraged to maintain access until they naturally expire, thereby maintaining operational continuity during engagements.

## Key Features

- **Token Acquisition & Persistence**:
   - Exchange compromised credentials or certificates for  access and refresh tokens, ensuring continued access.
   - Leverage tokens to bypass certain Conditional Access Policies that enforce MFA or location-based restrictions.
  
- **Dynamic Grant Types**:
   - Supports multiple OAuth2 flows, including:
     - `client_credentials`
     - `password`
     - `refresh_token`
     - `device_code`
     - `jwt_assertion` and `jwt_assertion by key vault sign` (for certificates and Key Vault-based JWT signing)
  
- **Advanced JWT Signing**:
   - Sign JWTs using a compromised certificate or through Azure Key Vault signing permissions, giving flexibility depending on the environment being 

- **Predefined Scopes**:
   - Easily select common Azure scopes (like **Microsoft Graph**, **Office 365**, or **Azure Key Vault**) through predefined options, simplifying the process of token requests.
  
- **In-Depth JWT Analysis**:
   - Decode and analyze JWT tokens to understand the permissions granted, token expiration, and key claims, which are essential for understanding the scope and longevity of the access gained.
 



# SATO - Secure Azure Token Operations


## Getting Started

### Installation

To use **SATO**, follow these steps:

1. Clone the repository from GitHub:
    ```bash
    git clone https://github.com/obikuro/Sato.git
    ```

2. Import the module in PowerShell:
    ```powershell
    Import-Module .\Sato\SATO.psd1
    ```

---

## Available Grant Types

The following **OAuth2 grant types** are supported by SATO:

- **`client_credentials`**: Used when interacting with service principals (SPs)
- **`password`**: Exchanges a username and password for tokens.
- **`refresh_token`**: Uses a refresh token to obtain a new access token.
- **`device_code`**: Interactive login -- device code phishing
- **`jwt_assertion`**: Uses certificates private key for token acquisition.
- **`jwt_assertion_sign`**: Signs a JWT using Azure Key Vault signing permissions for token acquisition.

### Grant Type Parameter

```bash
-GrantType <grant_type>
```


## Predefined Scopes

SATO offers predefined scopes for ease of use. These cover various Microsoft services such as Microsoft Graph, Azure Management, and more. You can select a predefined scope using the `-PredefinedScope` parameter.

- **MsGraph**: New Microsoft Graph
- **MSTeams**: Microsoft Teams
- **Office**: Office 365
- **Outlook**: Microsoft Outlook
- **WinGraph**: Old Microsoft Graph
- **CoreARM**: Classic Azure Resource Manager provider
- **MaARM**: Azure Resource Manager provider
- **IntuneMam**: Intune Mobile Application Management
- **SharePoint**: SharePoint
- **OneDrive**: OneDrive
- **KeyVault**: Azure Key Vault


## Examples

### Client Credentials Flow

This flow is used when you have access to a service principal's client ID and secret.

```powershell
Invoke-Sato -GrantType "client_credentials" -TenantID "target-tenant-id" -ClientID "target-SP-id" -ClientSecret "target-SP-secret" -PredefinedScope WinGraph
```

### Password Flow
Use this flow to exchange a username and password for an access token.

```powershell
Invoke-Sato -GrantType "password" -TenantID "target-tenant-id"  -Username "user@domain.com" -Password "target-user-password" -PredefinedScope WinGraph
```
### Refresh Token Flow
Use a refresh token to obtain a new access token.

```powershell
Invoke-Sato -GrantType "refresh_token" -TenantID "target-tenant-id"  -RefreshToken "target-refresh-token" -Scope "<https://management.azure.com/.default>"
```

### JWT Assertion Flow
For scenarios where you want to use a compromised SP certificate's private key to obtain an access token.

```powershell
Invoke-Sato -GrantType "jwt_assertion" -TenantID "target-tenant-id" -AppID "target-sp-id" -CertificatePath "C:\\path-to\\cert.pfx"
```

- `-CertificatePath`: This parameter is used to specify the file path to a certificate (e.g., `.pfx` file). 
  
- `-Certificate`: Use this parameter when you already have a certificate object loaded in memory (e.g., from a previous import or operation). 


### JWT Assertion Sign with Key Vault
For red teams using Azure Key Vault to sign JWT tokens.

```powershell
Invoke-Sato -GrantType "jwt_assertion_sign" -TenantID "target-tenant-id" -AppID "target-sp-id" -KeyVaultName "key vault-name" -CertName "certificate-name" -KeyToken "keyvault-access-token"
```
When using the jwt_assertion_sign grant type, you must have signing permissions on an Azure Key Vault. This method takes advantage of Key Vault's signing capabilities to sign a crafted jwt token and exchange it for a valid Azure token.


### Device Code Flow
use this grant for device code phishing scenarios

```powershell
Invoke-Sato -GrantType "device_code" -TenantID "target-tenant-id"  -Scope "<https://graph.microsoft.com/.default>"
```


## Important Notes

### Use of `-UseCAE`

The `-UseCAE` flag is used to enable Continuous Access Evaluation (CAE). When you specify `-UseCAE`, the CAE claim (`cp1`) will be included in the token, allowing you to maintain a token with an extended validity window. 

### Family of Client IDs (FOCI)
By default, SATO uses a Microsoft client ID, which is part of the Family of Client IDs (FOCI). This allows for seamless multi-tenant access without providing a client secret.





