<#
.SYNOPSIS
    Grants Sites.Selected permission to an Azure AD app on a specific SharePoint Online site using Microsoft Graph PowerShell.

.DESCRIPTION
    Connects to Microsoft Graph with Sites.FullControl.All, resolves the SharePoint site ID,
    and grants the specified app registration scoped access to the target site.
    Requires the app to already have Sites.Selected granted and admin-consented in Entra ID.
    Optionally tests app access by listing drives and uploading a test file via Graph REST.

.PARAMETER SiteUrl
    The URL of the SharePoint site to grant access to.

.PARAMETER AppClientId
    The Client ID (GUID) of the Azure AD app registration.

.PARAMETER AppDisplayName
    The display name of the Azure AD app registration.

.PARAMETER Permission
    The permission level to grant: read or write.

.PARAMETER DryRun
    Shows what would be granted without making any changes.

.PARAMETER TestAccess
    After grant, tests access as the target app by listing drives and uploading a file.

.PARAMETER TenantId
    Tenant ID or domain used to request an app-only token for test calls.

.PARAMETER AppClientSecret
    Client secret for the target app, required only when -TestAccess is used.

.PARAMETER UploadPath
    Path (from site drive root) to upload during test, for example Reports/test.txt.

.PARAMETER UploadContent
    Text content used for the upload test.

.EXAMPLE
    .\Grant-SitesSelected-Graph.ps1
    Runs with default values for the QGPGGS site.

.EXAMPLE
    .\Grant-SitesSelected-Graph.ps1 -Permission read -DryRun
    Previews a read grant without making changes.

.EXAMPLE
    $secret = Read-Host "App client secret" -AsSecureString
    .\Grant-SitesSelected-Graph.ps1 -Permission write -TestAccess -TenantId "hpwqld.onmicrosoft.com" -AppClientSecret $secret
    Grants write permission, then tests list drives and upload using the app identity.
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [string]$SiteUrl = "https://hpwqld.sharepoint.com/sites/SSQCCMS-TEST",
    [string]$AppClientId = "ca4f341a-a9bf-45fd-82e7-0ff75ed66966",
    [string]$AppDisplayName = "QGPGGS-SHAREPOINT",
    [ValidateSet("read", "write")]
    [string]$Permission = "read",
    [switch]$DryRun,
    [switch]$TestAccess,
    [string]$TenantId = "hpwqld.onmicrosoft.com",
    [SecureString]$AppClientSecret,
    [string]$UploadPath = "Reports/test.txt",
    [string]$UploadContent = "Hello from Sites.Selected!"
)

# Ensure Microsoft.Graph.Sites is available
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Sites))
{
    Write-Error "Microsoft.Graph.Sites module is not installed. Run: Install-Module Microsoft.Graph.Sites -Scope CurrentUser"
    exit 1
}

Write-Host "Connecting to Microsoft Graph (Sites.FullControl.All)..." -ForegroundColor Cyan
try
{
    Connect-MgGraph -Scopes "Sites.FullControl.All" -ErrorAction Stop
}
catch
{
    Write-Error "Failed to connect to Microsoft Graph: $_"
    exit 1
}

# Derive the Graph REST path from the URL
$uri = [System.Uri]$SiteUrl
$siteRelPath = $uri.AbsolutePath   # e.g. /sites/qgpggs
$graphPath = "https://graph.microsoft.com/v1.0/sites/$($uri.Host):$($siteRelPath):"

Write-Host "Resolving site ID for $SiteUrl ..." -ForegroundColor Cyan
try
{
    $site = Invoke-MgGraphRequest -Uri $graphPath -Method GET -ErrorAction Stop
}
catch
{
    Write-Error "Failed to resolve site '${SiteUrl}': $_"
    exit 1
}

Write-Host ""
Write-Host "Site       : $($site.WebUrl)" -ForegroundColor White
Write-Host "Site ID    : $($site.Id)" -ForegroundColor White
Write-Host "App ID     : $AppClientId" -ForegroundColor White
Write-Host "App Name   : $AppDisplayName" -ForegroundColor White
Write-Host "Permission : $Permission" -ForegroundColor White
Write-Host ""

if ($DryRun)
{
    Write-Host "[DRY RUN] Would grant '$Permission' to app '$AppDisplayName' ($AppClientId) on $($site.WebUrl)" -ForegroundColor Yellow
    exit 0
}

$body = @{
    roles               = @($Permission)
    grantedToIdentities = @(
        @{
            application = @{
                id          = $AppClientId
                displayName = $AppDisplayName
            }
        }
    )
}

try
{
    if ($PSCmdlet.ShouldProcess("$($site.WebUrl)", "Grant '$Permission' to app '$AppDisplayName' ($AppClientId)"))
    {
        $result = Invoke-MgGraphRequest `
            -Uri "https://graph.microsoft.com/v1.0/sites/$($site.id)/permissions" `
            -Method POST `
            -Body ($body | ConvertTo-Json -Depth 5) `
            -ContentType "application/json" `
            -ErrorAction Stop

        Write-Host "✓ Permission '$Permission' successfully granted." -ForegroundColor Green
        Write-Host "  Permission ID: $($result.id)" -ForegroundColor Gray

        Write-Output ([pscustomobject]@{
                Action       = "GrantSitePermission"
                SiteUrl      = $site.WebUrl
                SiteId       = $site.Id
                AppClientId  = $AppClientId
                AppName      = $AppDisplayName
                Permission   = $Permission
                PermissionId = $result.id
            })
    }
}
catch
{
    Write-Error "Failed to grant permission for site '$SiteUrl' and app '$AppClientId': $_"
    exit 1
}

if (-not $TestAccess)
{
    return
}

if (-not $AppClientSecret)
{
    Write-Error "-TestAccess requires -AppClientSecret. Provide it as a SecureString (for example via Read-Host -AsSecureString)."
    exit 1
}

Write-Host "" 
Write-Host "Testing access as app '$AppDisplayName' ($AppClientId)..." -ForegroundColor Cyan

try
{
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($AppClientSecret)
    $secretPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)

    $tokenResponse = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -ContentType "application/x-www-form-urlencoded" -Body @{
        client_id     = $AppClientId
        scope         = "https://graph.microsoft.com/.default"
        client_secret = $secretPlain
        grant_type    = "client_credentials"
    } -ErrorAction Stop

    $headers = @{ Authorization = "Bearer $($tokenResponse.access_token)" }
}
catch
{
    Write-Error "Failed to acquire app token for tenant '$TenantId', app '$AppClientId': $_"
    exit 1
}
finally
{
    if ($bstr -and $bstr -ne [IntPtr]::Zero)
    {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

try
{
    $drivesUrl = "https://graph.microsoft.com/v1.0/sites/$($site.id)/drives"
    $drives = Invoke-RestMethod -Method GET -Uri $drivesUrl -Headers $headers -ErrorAction Stop
    $driveCount = @($drives.value).Count
    Write-Host "✓ Test GET succeeded: /sites/{site-id}/drives (count: $driveCount)" -ForegroundColor Green

    Write-Output ([pscustomobject]@{
            Action     = "TestListDrives"
            SiteId     = $site.Id
            SiteUrl    = $site.WebUrl
            DriveCount = $driveCount
        })
}
catch
{
    Write-Error "Failed test GET /sites/{site-id}/drives for site '$SiteUrl' and app '$AppClientId': $_"
    exit 1
}

try
{
    $uploadUrl = "https://graph.microsoft.com/v1.0/sites/$($site.id)/drive/items/root:/${UploadPath}:/content"
    $uploadBytes = [System.Text.Encoding]::UTF8.GetBytes($UploadContent)
    $upload = Invoke-RestMethod -Method PUT -Uri $uploadUrl -Headers $headers -ContentType "text/plain" -Body $uploadBytes -ErrorAction Stop
    Write-Host "✓ Test PUT succeeded: /sites/{site-id}/drive/items/root:/${UploadPath}:/content" -ForegroundColor Green

    Write-Output ([pscustomobject]@{
            Action       = "TestUploadFile"
            SiteId       = $site.Id
            SiteUrl      = $site.WebUrl
            UploadedPath = $UploadPath
            ItemId       = $upload.id
            WebUrl       = $upload.webUrl
        })
}
catch
{
    Write-Error "Failed test PUT upload for site '$SiteUrl' and app '$AppClientId' at path '$UploadPath': $_"
    exit 1
}

