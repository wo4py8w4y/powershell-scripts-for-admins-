<#
.SYNOPSIS
    Creates a Graph app registration and assigns SharePoint Sites.Selected permissions for a target site.

.DESCRIPTION
    Prompts for application name, SharePoint site URL, and web ID, then performs app registration,
    permission assignment, and validation steps using Microsoft Graph PowerShell.

.NOTES
    CHANGELOG
    ----------
    2026-06-03 - Normalized SharePoint URL input and added null checks for site resolution.
    2026-06-01 - Added interactive prompts for AppName, SharePointSiteUrl, and WebId.
    2026-06-01 - Added prompt to keep app registration before optional removal.
    2026-06-01 - Added specific app naming and existing app lookup before create.
    2026-06-01 - Added prompt-driven site permission role selection for reusable runs.
    2026-06-01 - Added transcript and structured troubleshooting logging.
    2026-06-01 - Added manual admin consent pause when Graph app role assignment returns 403.
    2026-06-01 - Changed 403 handling to stop cleanly after showing rerun guidance.
#>

#Requires -Version 7.0

$script:LogPath = $null
$script:TranscriptStarted = $false

function Write-Log
{
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level,
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [hashtable]$Data
    )

    if (-not $script:LogPath)
    {
        return
    }

    $entry = [PSCustomObject]@{
        Timestamp = (Get-Date).ToString('o')
        Level     = $Level
        Message   = $Message
        Data      = if ($Data) { ($Data | ConvertTo-Json -Compress -Depth 10) } else { $null }
    }

    $entry | ConvertTo-Json -Compress | Add-Content -Path $script:LogPath
}

function Start-TroubleshootingLogging
{
    $logFolder = Join-Path -Path $env:TEMP -ChildPath 'SitesSelectedLogs'
    if (-not (Test-Path -Path $logFolder))
    {
        New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
    }

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:LogPath = Join-Path -Path $logFolder -ChildPath ("sites-selected-{0}.jsonl" -f $timestamp)
    $transcriptPath = Join-Path -Path $logFolder -ChildPath ("sites-selected-{0}.transcript.log" -f $timestamp)

    Start-Transcript -Path $transcriptPath -Append | Out-Null
    $script:TranscriptStarted = $true

    Write-Log -Level INFO -Message 'Troubleshooting logging started.' -Data @{ JsonLogPath = $script:LogPath; TranscriptPath = $transcriptPath }
    Write-Host "[LOG] JSON log: $script:LogPath" -ForegroundColor DarkCyan
    Write-Host "[LOG] Transcript: $transcriptPath" -ForegroundColor DarkCyan
}

function Stop-TroubleshootingLogging
{
    if ($script:TranscriptStarted)
    {
        Stop-Transcript | Out-Null
        $script:TranscriptStarted = $false
    }
}

function Stop-WithAdminConsentRequired
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host $Message -ForegroundColor Yellow
    Write-Host 'Rerun this script after admin consent has been granted.' -ForegroundColor Yellow
    Write-Log -Level WARN -Message 'Stopped for manual admin consent.' -Data @{ Message = $Message }
    Stop-TroubleshootingLogging
    exit 1
}

function Read-RequiredInput
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$PromptText
    )

    while ($true)
    {
        $value = Read-Host $PromptText
        if (-not [string]::IsNullOrWhiteSpace($value))
        {
            return $value.Trim()
        }

        Write-Warning "A value is required. Please try again."
    }
}

function Read-YesNo
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$PromptText,
        [bool]$DefaultYes = $true
    )

    $suffix = if ($DefaultYes) { '[Y] Yes [N] No (default: Y)' } else { '[Y] Yes [N] No (default: N)' }
    while ($true)
    {
        $value = Read-Host "$PromptText $suffix"
        if ([string]::IsNullOrWhiteSpace($value))
        {
            return $DefaultYes
        }

        if ($value -match '^[Yy]') { return $true }
        if ($value -match '^[Nn]') { return $false }

        Write-Warning 'Please enter Y or N.'
    }
}

function Read-Choice
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$PromptText,
        [Parameter(Mandatory = $true)]
        [string[]]$Choices,
        [Parameter(Mandatory = $true)]
        [string]$DefaultChoice
    )

    $choicesText = ($Choices -join '/')
    while ($true)
    {
        $value = Read-Host "$PromptText [$choicesText] (default: $DefaultChoice)"
        if ([string]::IsNullOrWhiteSpace($value))
        {
            return $DefaultChoice
        }

        $match = $Choices | Where-Object { $_.ToLower() -eq $value.Trim().ToLower() } | Select-Object -First 1
        if ($match)
        {
            return $match
        }

        Write-Warning "Invalid choice. Allowed values: $choicesText"
    }
}

function Get-SpecificAppName
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$AppNameBase,
        [Parameter(Mandatory = $true)]
        [string]$SharePointSiteUrl,
        [Parameter(Mandatory = $true)]
        [string]$WebId
    )

    $siteToken = 'site'
    $tenantToken = 'tenant'
    try
    {
        $siteUri = [uri]$SharePointSiteUrl
        $tenantToken = ($siteUri.Host.Split('.')[0] -replace '[^a-zA-Z0-9]', '').ToLower()

        $rawPath = $siteUri.AbsolutePath.Trim('/').ToLower()
        if (-not [string]::IsNullOrWhiteSpace($rawPath))
        {
            $siteToken = ($rawPath -replace '[^a-zA-Z0-9]', '-')
            $siteToken = $siteToken.Trim('-')
            if ([string]::IsNullOrWhiteSpace($siteToken))
            {
                $siteToken = 'site'
            }
        }
    }
    catch
    {
        # Keep defaults if URL parsing fails.
    }

    $webToken = ($WebId -replace '[^a-zA-Z0-9]', '').ToLower()
    if ($webToken.Length -gt 8)
    {
        $webToken = $webToken.Substring(0, 8)
    }

    $baseToken = ($AppNameBase -replace '[^a-zA-Z0-9_-]', '-')
    $baseToken = $baseToken.Trim('-')

    return "$baseToken-$tenantToken-$siteToken-$webToken"
}

Write-Host "### Step 1: Prepare Your Environment" -ForegroundColor Cyan
Start-TroubleshootingLogging

$AppNameBase = Read-RequiredInput -PromptText "Enter app name base"
$SharePointSiteUrl = Read-RequiredInput -PromptText "Enter SharePoint site URL (e.g. https://tenant.sharepoint.com/sites/siteName)"
$WebId = Read-RequiredInput -PromptText "Enter Web ID"
$SitePermissionRole = Read-Choice -PromptText 'Enter site permission role to grant' -Choices @('read', 'write', 'owner', 'fullcontrol') -DefaultChoice 'write'
$AppName = Get-SpecificAppName -AppNameBase $AppNameBase -SharePointSiteUrl $SharePointSiteUrl -WebId $WebId
Write-Log -Level INFO -Message 'Collected operator inputs.' -Data @{ AppNameBase = $AppNameBase; SharePointSiteUrl = $SharePointSiteUrl; WebId = $WebId; SitePermissionRole = $SitePermissionRole; AppName = $AppName }

Write-Host "Using values:" -ForegroundColor Cyan
Write-Host "  AppNameBase: $AppNameBase" -ForegroundColor Yellow
Write-Host "  AppName (specific): $AppName" -ForegroundColor Yellow
Write-Host "  SharePointSiteUrl: $SharePointSiteUrl" -ForegroundColor Yellow
Write-Host "  WebId: $WebId" -ForegroundColor Yellow
Write-Host "  SitePermissionRole: $SitePermissionRole" -ForegroundColor Yellow

Write-Host "### Step 2: Import Required Modules" -ForegroundColor Cyan

$requiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Applications',
    'Microsoft.Graph.Sites',
    'Microsoft.Graph.Users'
)

foreach ($module in $requiredModules)
{
    if (-not (Get-Module -Name $module -ListAvailable))
    {
        Write-Host "Installing $module..." -ForegroundColor Yellow
        Install-Module $module -Scope CurrentUser -Force
    }

    Import-Module $module -ErrorAction Stop
    Write-Host "[OK] $module loaded" -ForegroundColor Green
}

Write-Host "### Step 3: Connect to Microsoft Graph" -ForegroundColor Cyan
$scopes = @(
    'Application.ReadWrite.All',
    'AppRoleAssignment.ReadWrite.All',
    'Sites.FullControl.All',
    'Directory.Read.All'
)

Connect-MgGraph -Scopes $scopes
Write-Log -Level INFO -Message 'Connected to Microsoft Graph.' -Data @{ Scopes = ($scopes -join ',') }

Write-Host "### Step 4: Resolve Site Details" -ForegroundColor Cyan
try
{
    $normalizedSharePointSiteUrl = $SharePointSiteUrl.Trim()
    if ($normalizedSharePointSiteUrl -notmatch '^[a-zA-Z][a-zA-Z0-9+.-]*://')
    {
        $normalizedSharePointSiteUrl = "https://$normalizedSharePointSiteUrl"
    }

    $siteUri = $null
    if (-not [System.Uri]::TryCreate($normalizedSharePointSiteUrl, [System.UriKind]::Absolute, [ref]$siteUri))
    {
        throw "SharePoint site URL '$SharePointSiteUrl' is not a valid absolute URL."
    }

    if ([string]::IsNullOrWhiteSpace($siteUri.Host))
    {
        throw "SharePoint site URL '$normalizedSharePointSiteUrl' is missing a host name."
    }

    $sitePath = $siteUri.AbsolutePath
    if ([string]::IsNullOrWhiteSpace($sitePath))
    {
        $sitePath = '/'
    }
    else
    {
        $sitePath = $sitePath.TrimEnd('/')
        if ([string]::IsNullOrWhiteSpace($sitePath))
        {
            $sitePath = '/'
        }
    }

    # Graph site lookup format: host:/relative/path:
    $siteLookupId = "{0}:{1}:" -f $siteUri.Host, $sitePath
    $resolvedSite = Get-MgSite -SiteId $siteLookupId -ErrorAction Stop
    if (-not $resolvedSite -or [string]::IsNullOrWhiteSpace($resolvedSite.Id))
    {
        throw "Graph returned no site for lookup '$siteLookupId'."
    }

    $SiteId = $resolvedSite.Id
    Write-Log -Level INFO -Message 'Resolved site details.' -Data @{ InputSharePointSiteUrl = $SharePointSiteUrl; NormalizedSharePointSiteUrl = $normalizedSharePointSiteUrl; SiteLookupId = $siteLookupId; SiteId = $SiteId; ResolvedWebId = [string]$resolvedSite.WebId }
}
catch
{
    Write-Log -Level ERROR -Message 'Failed to resolve site details.' -Data @{ SharePointSiteUrl = $SharePointSiteUrl; Error = $_.Exception.Message }
    Stop-TroubleshootingLogging
    throw "Failed to resolve SiteId from SharePoint URL '$SharePointSiteUrl'. Verify the URL format and your Graph site read permissions. Details: $($_.Exception.Message)"
}

if ($resolvedSite.WebId -and ($resolvedSite.WebId.ToString() -ne $WebId))
{
    Write-Warning "Provided WebId does not match resolved site WebId. Continuing with resolved SiteId: $SiteId"
}

Write-Host "Resolved SiteId: $SiteId" -ForegroundColor Green

Write-Host "### Step 5: Find or create the Entra app registration" -ForegroundColor Cyan
$escapedDisplayName = $AppName -replace "'", "''"
$app = Get-MgApplication -Filter "displayName eq '$escapedDisplayName'" -Top 1 -ErrorAction SilentlyContinue
$appWasCreatedInRun = $false

if ($app)
{
    Write-Host "[OK] Found existing app registration with matching name." -ForegroundColor Green
    Write-Log -Level INFO -Message 'Reused existing app registration.' -Data @{ AppId = $app.AppId; ObjectId = $app.Id; DisplayName = $app.DisplayName }
}
else
{
    $app = New-MgApplication -DisplayName $AppName -SignInAudience 'AzureADMyOrg'
    $appWasCreatedInRun = $true
    Write-Host "App registration created successfully" -ForegroundColor Green
    Write-Log -Level INFO -Message 'Created new app registration.' -Data @{ AppId = $app.AppId; ObjectId = $app.Id; DisplayName = $app.DisplayName }
}

Write-Host "App ID (Client ID): $($app.AppId)"
Write-Host "Object ID: $($app.Id)"
Write-Host "Press any key to continue..." -ForegroundColor Yellow
[void][System.Console]::ReadKey($true)

Write-Host "### Step 6: Add Microsoft Graph Sites.Selected permission" -ForegroundColor Cyan

$graphApiId = '00000003-0000-0000-c000-000000000000'
$graphSitesSelected = '883ea226-0bf2-4a8f-9f9d-92c9162a727d'

$permission = @{
    Id   = $graphSitesSelected
    Type = 'Role'
}

$requiredResourceAccess = @{
    ResourceAppId  = $graphApiId
    ResourceAccess = @($permission)
}

Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess @($requiredResourceAccess)
Write-Host "[OK] Added Microsoft Graph Sites.Selected permission" -ForegroundColor Green
Write-Log -Level INFO -Message 'Updated Graph permission.' -Data @{ AppObjectId = $app.Id; PermissionId = $graphSitesSelected; ResourceAppId = $graphApiId }

Write-Host "### Step 7: Add SharePoint Sites.Selected permission" -ForegroundColor Cyan

$sharepointApiId = '00000003-0000-0ff1-ce00-000000000000'
$sharepointSitesSelected = '20d37865-089c-4dee-8c41-6967602d4ac8'

$permission = @{
    Id   = $sharepointSitesSelected
    Type = 'Role'
}

$requiredResourceAccess = @{
    ResourceAppId  = $sharepointApiId
    ResourceAccess = @($permission)
}

$app = Get-MgApplication -ApplicationId $app.Id
$existingPermissions = $app.RequiredResourceAccess + $requiredResourceAccess

Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess $existingPermissions
Write-Host "[OK] Added SharePoint Sites.Selected permission" -ForegroundColor Green
Write-Log -Level INFO -Message 'Updated SharePoint permission.' -Data @{ AppObjectId = $app.Id; PermissionId = $sharepointSitesSelected; ResourceAppId = $sharepointApiId }

Write-Host "### Step 8: Wait for permission propagation" -ForegroundColor Cyan
Start-Sleep -Seconds 10

$ConsentAttempted = 0
$ConsentSucceeded = 0
$ConsentFailed = 0
$SitePermissionAttempted = 0
$SitePermissionSucceeded = 0
$SitePermissionFailed = 0

Write-Host "### Step 9: Grant admin consent" -ForegroundColor Cyan
$sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue
if (-not $sp)
{
    $sp = New-MgServicePrincipal -AppId $app.AppId
    Write-Host "[OK] Service principal created" -ForegroundColor Green
    Start-Sleep -Seconds 5
    Write-Log -Level INFO -Message 'Created service principal.' -Data @{ ServicePrincipalId = $sp.Id; AppId = $app.AppId }
}
else
{
    Write-Host "[OK] Service principal already exists" -ForegroundColor Green
    Write-Log -Level INFO -Message 'Reused existing service principal.' -Data @{ ServicePrincipalId = $sp.Id; AppId = $app.AppId }
}

foreach ($resource in $app.RequiredResourceAccess)
{
    $resourceSp = Get-MgServicePrincipal -Filter "appId eq '$($resource.ResourceAppId)'"

    foreach ($perm in $resource.ResourceAccess)
    {
        if ($perm.Type -eq 'Role')
        {
            $ConsentAttempted++
            try
            {
                $existingGrant = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue |
                    Where-Object { $_.AppRoleId -eq $perm.Id }

                if (-not $existingGrant)
                {
                    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id -ResourceId $resourceSp.Id -AppRoleId $perm.Id -ErrorAction Stop | Out-Null
                    Write-Host "[OK] Granted admin consent for permission: $($perm.Id)" -ForegroundColor Green
                    Write-Log -Level INFO -Message 'Granted app role assignment.' -Data @{ ServicePrincipalId = $sp.Id; ResourceServicePrincipalId = $resourceSp.Id; AppRoleId = $perm.Id }
                }
                else
                {
                    Write-Host "[INFO] Admin consent already granted for: $($perm.Id)" -ForegroundColor Yellow
                    Write-Log -Level INFO -Message 'App role assignment already present.' -Data @{ ServicePrincipalId = $sp.Id; AppRoleId = $perm.Id }
                }

                $ConsentSucceeded++
            }
            catch
            {
                Write-Warning "Could not grant consent for permission $($perm.Id): $($_.Exception.Message)"
                Write-Log -Level ERROR -Message 'Failed to grant app role assignment.' -Data @{ ServicePrincipalId = $sp.Id; AppRoleId = $perm.Id; Error = $_.Exception.Message }
                $ConsentFailed++

                if ($_.Exception.Message -match '403|Authorization_RequestDenied|Insufficient privileges')
                {
                    Stop-WithAdminConsentRequired -Message @"
Admin consent is required for this API permission, and the current account cannot grant it.

Grant the permission manually in the Entra admin center or rerun this step with an account that has sufficient admin rights.
Required app role ID: $($perm.Id)
Resource app ID: $($resource.ResourceAppId)
"@
                    Write-Log -Level WARN -Message 'Paused for manual admin consent after 403.' -Data @{ ServicePrincipalId = $sp.Id; AppRoleId = $perm.Id; ResourceAppId = $resource.ResourceAppId }
                }
            }
        }
    }
}

Write-Host "### Step 10: Configure site permissions" -ForegroundColor Cyan
Start-Sleep -Seconds 15

try
{
    $SitePermissionAttempted++

    $body = @{
        roles               = @($SitePermissionRole)
        grantedToIdentities = @(@{
                application = @{
                    id          = $app.AppId
                    displayName = $AppName
                }
            })
    } | ConvertTo-Json -Depth 10

    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/sites/$SiteId/permissions" -Body $body -ContentType 'application/json' | Out-Null
    Write-Host "[OK] Granted $($SitePermissionRole.ToUpper()) permission to target site" -ForegroundColor Green
    Write-Log -Level INFO -Message 'Granted site permission.' -Data @{ SiteId = $SiteId; Role = $SitePermissionRole; AppId = $app.AppId }
    $SitePermissionSucceeded++
}
catch
{
    Write-Warning "Could not grant permission to target site: $($_.Exception.Message)"
    Write-Log -Level ERROR -Message 'Failed to grant site permission.' -Data @{ SiteId = $SiteId; Role = $SitePermissionRole; AppId = $app.AppId; Error = $_.Exception.Message }

    if ($_.Exception.Message -match '403|Authorization_RequestDenied|Insufficient privileges')
    {
        Stop-WithAdminConsentRequired -Message @"
Manual site permission assignment is required here, but the current account could not complete it.

Confirm the app has the required admin-consented API permissions, then grant the site permission manually or rerun with an admin account.
Target SiteId: $SiteId
Role requested: $SitePermissionRole
"@
        Write-Log -Level WARN -Message 'Paused for manual site permission handling after 403.' -Data @{ SiteId = $SiteId; Role = $SitePermissionRole; AppId = $app.AppId }
    }
    $SitePermissionFailed++
}

Write-Host "### Step 11: Verify app registration" -ForegroundColor Cyan
$verifyApp = Get-MgApplication -ApplicationId $app.Id
Write-Host "App Name: $($verifyApp.DisplayName)" -ForegroundColor Cyan
Write-Host "App ID: $($verifyApp.AppId)" -ForegroundColor Cyan
Write-Host "Object ID: $($verifyApp.Id)" -ForegroundColor Cyan
Write-Host "Required Permissions: $($verifyApp.RequiredResourceAccess.Count)" -ForegroundColor Cyan

Write-Host "### Step 12: Verify service principal and role assignments" -ForegroundColor Cyan
$verifySp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'"
Write-Host "Service Principal ID: $($verifySp.Id)" -ForegroundColor Cyan
Write-Host "Service Principal Display Name: $($verifySp.DisplayName)" -ForegroundColor Cyan

$roleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $verifySp.Id
Write-Host "Total Role Assignments: $($roleAssignments.Count)" -ForegroundColor Cyan
foreach ($assignment in $roleAssignments)
{
    Write-Host "  - Role ID: $($assignment.AppRoleId)" -ForegroundColor Green
}

Write-Host "### Step 13: Keep or remove app registration" -ForegroundColor Cyan
if (-not $appWasCreatedInRun)
{
    Write-Host '[INFO] Existing app registration was reused. No removal action will be taken.' -ForegroundColor Yellow
    Write-Log -Level INFO -Message 'Skipped cleanup because app was reused.' -Data @{ AppId = $app.AppId }
}
else
{
    $keepAppRegistration = Read-YesNo -PromptText 'Keep this app registration?' -DefaultYes $true
    if ($keepAppRegistration)
    {
        Write-Host '[OK] Keeping app registration and service principal.' -ForegroundColor Green
        Write-Log -Level INFO -Message 'Operator chose to keep app registration.' -Data @{ AppId = $app.AppId; ServicePrincipalId = $verifySp.Id }
    }
    else
    {
        Write-Host 'Removing service principal and app registration...' -ForegroundColor Yellow
        try
        {
            if ($verifySp -and $verifySp.Id)
            {
                Remove-MgServicePrincipal -ServicePrincipalId $verifySp.Id -ErrorAction Stop
                Write-Host '[OK] Service principal removed.' -ForegroundColor Green
                Write-Log -Level INFO -Message 'Removed service principal.' -Data @{ ServicePrincipalId = $verifySp.Id }
            }

            Remove-MgApplication -ApplicationId $app.Id -ErrorAction Stop
            Write-Host '[OK] App registration removed.' -ForegroundColor Green
            Write-Log -Level INFO -Message 'Removed app registration.' -Data @{ AppId = $app.AppId; AppObjectId = $app.Id }
        }
        catch
        {
            Write-Warning "Could not remove app registration resources: $($_.Exception.Message)"
            Write-Log -Level ERROR -Message 'Failed to remove app registration resources.' -Data @{ AppId = $app.AppId; Error = $_.Exception.Message }
        }
    }
}

Write-Host "Summary: Consent A/S/F=$ConsentAttempted/$ConsentSucceeded/$ConsentFailed | SitePermission A/S/F=$SitePermissionAttempted/$SitePermissionSucceeded/$SitePermissionFailed" -ForegroundColor Cyan
Write-Log -Level INFO -Message 'Run summary.' -Data @{ ConsentAttempted = $ConsentAttempted; ConsentSucceeded = $ConsentSucceeded; ConsentFailed = $ConsentFailed; SitePermissionAttempted = $SitePermissionAttempted; SitePermissionSucceeded = $SitePermissionSucceeded; SitePermissionFailed = $SitePermissionFailed }

Write-Log -Level INFO -Message 'Script completed.' -Data @{ AppId = $app.AppId; SiteId = $SiteId; Role = $SitePermissionRole }
Stop-TroubleshootingLogging

