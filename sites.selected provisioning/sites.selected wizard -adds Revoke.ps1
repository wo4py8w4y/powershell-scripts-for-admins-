#requires -Version 7.0
<#
.SYNOPSIS
    Provision Entra ID app registrations for SharePoint Online Sites.Selected, manage certificates,
    grant & revoke site-level permissions, and validate grants — with step-by-step console output and file logging.

.DESCRIPTION
    Creates/ensures two app registrations:
      - "QGPGGS SharePoint" (target): Microsoft Graph "Sites.Selected" application permission.
      - "Sites.Selected provisioning" (provisioner): Microsoft Graph "Sites.FullControl.All" application permission.
    Provides menus to:
      1) Create & attach self-signed certs
      2) Export CER/PFX
      3) Prompt for site URLs + roles (read|write|manage|fullcontrol), then grant to target app
      4) Revoke existing site permissions for the target app  <-- [REVOKE]
      5) Validate the resulting grants

.NOTES
    - Uses first‑party Microsoft.Graph PowerShell.
    - Avoids Sites.Read.All. Uses Sites.Selected + explicit per‑site grants (least privilege).
    - Logging to ./logs with timestamped file names; console shows step numbers & statuses.

.REFERENCES
    - Delete permission on a site (Microsoft Graph): DELETE /sites/{siteId}/permissions/{permissionId}  <-- used by Remove-MgSitePermission  <-- [REVOKE]
      https://learn.microsoft.com/graph/api/site-delete-permission?view=graph-rest-1.0
    - Remove-MgSitePermission cmdlet (Microsoft.Graph.Sites)  <-- [REVOKE]
      https://learn.microsoft.com/powershell/module/microsoft.graph.sites/remove-mgsitepermission?view=graph-powershell-1.0
    - Selected permissions model & roles (Sites.Selected)
      https://learn.microsoft.com/graph/permissions-selected-overview

.CHANGELOG
    - 2026-03-11: Initial version – apps, certs, grants, verification. Author: Aaron Francis
    - 2026-03-11: Added interactive menu for certificate creation/export, URL prompts, and end-of-run validation prompt. Author: Aaron Francis
    - 2026-03-11: Added step-by-step console output and timestamped file logging. Author: Aaron Francis
    - 2026-03-11: Added REVOKE permission option (interactive) using Remove-MgSitePermission. Author: Aaron Francis
#>

param(
    # Fixed to your tenant
    [string]$TenantId = "ec445a2a-b5ba-46f6-bead-4595e9fbd4a2",

    # Default role if user presses Enter at role prompt
    [ValidateSet('Read', 'Write', 'Manage', 'FullControl')]
    [string]$DefaultRole = 'FullControl',

    # App names (per your request)
    [string]$TargetAppName = "QGPGGS SharePoint",
    [string]$ProvisionerAppName = "Sites.Selected provisioning",

    # Certificate & output settings
    [int]$CertValidityYears = 2,
    [string]$CertOutFolder = (Join-Path -Path $PSScriptRoot -ChildPath "certs"),
    [string]$LogFolder = (Join-Path -Path $PSScriptRoot -ChildPath "logs")
)

$script:TenantId = $TenantId
$script:DefaultRole = $DefaultRole
$script:TargetAppName = $TargetAppName
$script:ProvisionerAppName = $ProvisionerAppName
$script:CertValidityYears = $CertValidityYears
$script:CertOutFolder = $CertOutFolder
$script:LogFolder = $LogFolder

#region Logging & Preconditions

$script:Step = 0
$script:LogFile = $null

function Initialize-Logger {
    if (-not (Test-Path $script:LogFolder)) { $null = New-Item -ItemType Directory -Path $script:LogFolder -Force }
    $ts = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $script:LogFile = Join-Path $script:LogFolder "SitesSelected_$ts.log"

    "=== Sites.Selected Provisioning Log ===" | Out-File -FilePath $script:LogFile -Encoding UTF8
    "Start: $(Get-Date -Format o)" | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
    "Tenant: $script:TenantId" | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
    "" | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
}

function Write-RunLog {
    param(
        [Parameter(Mandatory)] [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS', 'STEP', 'DEBUG')]
        [string]$Level = 'INFO'
    )
    $stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$stamp][$Level] $Message"

    if ($Level -eq 'ERROR') { Write-Error $line -ErrorAction Continue }
    elseif ($Level -eq 'WARN') { Write-Warning $Message }
    else { Write-Information $line -InformationAction Continue }

    $line | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
}

function Step { param([Parameter(Mandatory)][string]$Description); $script:Step++; Write-RunLog -Level STEP -Message ("Step {0}: {1}" -f $script:Step, $Description) }

<#
 # {function Test-IsElevated {
    try {
        if ($IsWindows) {
            $id = [Security.Principal.WindowsIdentity]::GetCurrent()
            $p  = [Security.Principal.WindowsPrincipal]::new($id)
            return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        } else { return (id -u) -eq 0 }
    } catch { return $false }
}
if (-not (Test-IsElevated)) { Write-Warning "Recommended to run elevated so certificates can be created/exported smoothly." }

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Write-Warning "Installing Microsoft.Graph (current user scope)..."
    Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
}
Import-Module Microsoft.Graph -ErrorAction Stop:Enter a comment or description}
#>

Initialize-Logger
Write-RunLog -Message "Logger initialized. Log file: $script:LogFile"
#endregion

#region Graph helpers & script state

$script:RequiredScopes = @(
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "Directory.ReadWrite.All",
    "Sites.FullControl.All",
    "Organization.Read.All"
)

$script:Target = $null
$script:Provisioner = $null
$script:TargetCert = $null
$script:ProvisionerCert = $null
$script:GraphSp = $null

function Connect-GraphAdmin {
    Step "Connecting to Microsoft Graph with delegated admin scopes"
    Connect-MgGraph -TenantId $script:TenantId -Scopes $script:RequiredScopes -NoWelcome -UseDeviceAuthentication -ContextScope Process
    $ctx = Get-MgContext
    if (-not $ctx.TenantId) { throw "Unable to establish Graph context for tenant $script:TenantId." }
    Write-RunLog -Message "Connected to tenant: $($ctx.TenantId)" -Level SUCCESS
}
function Get-GraphServicePrincipal { param([string]$AppId) Get-MgServicePrincipal -All -Filter "appId eq '$AppId'" | Select-Object -First 1 }

function New-OrGetApplication {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param([string]$DisplayName)

    $app = Get-MgApplication -All -Filter "displayName eq '$DisplayName'" | Select-Object -First 1
    if (-not $app) {
        Write-RunLog -Message "Creating application '$DisplayName'..."
        if (-not $PSCmdlet.ShouldProcess("Application '$DisplayName'", "Create")) {
            throw "Creation of application '$DisplayName' was not approved."
        }
        $app = New-MgApplication -DisplayName $DisplayName
        Write-RunLog -Message "Created application '$DisplayName' (AppId: $($app.AppId))" -Level SUCCESS
    }
    else {
        Write-RunLog -Message "Application exists '$DisplayName' (AppId: $($app.AppId))"
    }

    $sp = Get-MgServicePrincipal -All -Filter "appId eq '$($app.AppId)'" | Select-Object -First 1
    if (-not $sp) {
        Write-RunLog -Message "Creating service principal for '$DisplayName'..."
        if (-not $PSCmdlet.ShouldProcess("Service principal for '$DisplayName'", "Create")) {
            throw "Creation of service principal for '$DisplayName' was not approved."
        }
        $sp = New-MgServicePrincipal -AppId $app.AppId
        Write-RunLog -Message "Created service principal '$DisplayName' (ObjectId: $($sp.Id))" -Level SUCCESS
    }
    else {
        Write-RunLog -Message "Service principal exists for '$DisplayName' (ObjectId: $($sp.Id))"
    }

    [pscustomobject]@{ App = $app; Sp = $sp }
}

function Set-AppAndPermissionState {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param()
    Step "Ensuring Microsoft Graph SP and required app role grants"
    $script:GraphSp = Get-GraphServicePrincipal -AppId "00000003-0000-0000-c000-000000000000"
    if (-not $script:GraphSp) { throw "Cannot find Microsoft Graph service principal in this tenant." }
    Write-RunLog -Message "Found Microsoft Graph SP (ObjectId: $($script:GraphSp.Id))"

    # Target app -> Sites.Selected
    $script:Target = New-OrGetApplication -DisplayName $script:TargetAppName
    $sitesSelectedRoleId = ($script:GraphSp.AppRoles | Where-Object { $_.Value -eq "Sites.Selected" -and $_.AllowedMemberTypes -contains 'Application' }).Id
    if (-not $sitesSelectedRoleId) { throw "Graph app role 'Sites.Selected' not found." }

    $existingSel = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $script:Target.Sp.Id -All |
    Where-Object { $_.ResourceId -eq $script:GraphSp.Id -and $_.AppRoleId -eq $sitesSelectedRoleId }
    if (-not $existingSel) {
        if (-not $PSCmdlet.ShouldProcess("$script:TargetAppName", "Grant Graph app role Sites.Selected")) {
            throw "Grant of Sites.Selected to '$script:TargetAppName' was not approved."
        }
        Write-RunLog -Message "Granting admin consent: $script:TargetAppName -> Graph/Sites.Selected"
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $script:Target.Sp.Id -PrincipalId $script:Target.Sp.Id -ResourceId $script:GraphSp.Id -AppRoleId $sitesSelectedRoleId | Out-Null
        Write-RunLog -Message "Admin consent granted: $script:TargetAppName -> Sites.Selected" -Level SUCCESS
    }
    else {
        Write-RunLog -Message "Admin consent already present: $script:TargetAppName -> Sites.Selected"
    }

    # Provisioner app -> Sites.FullControl.All
    $script:Provisioner = New-OrGetApplication -DisplayName $script:ProvisionerAppName
    $fullControlRoleId = ($script:GraphSp.AppRoles | Where-Object { $_.Value -eq "Sites.FullControl.All" -and $_.AllowedMemberTypes -contains 'Application' }).Id
    if (-not $fullControlRoleId) { throw "Graph app role 'Sites.FullControl.All' not found." }

    $existingFull = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $script:Provisioner.Sp.Id -All |
    Where-Object { $_.ResourceId -eq $script:GraphSp.Id -and $_.AppRoleId -eq $fullControlRoleId }
    if (-not $existingFull) {
        if (-not $PSCmdlet.ShouldProcess("$script:ProvisionerAppName", "Grant Graph app role Sites.FullControl.All")) {
            throw "Grant of Sites.FullControl.All to '$script:ProvisionerAppName' was not approved."
        }
        Write-RunLog -Message "Granting admin consent: $script:ProvisionerAppName -> Graph/Sites.FullControl.All"
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $script:Provisioner.Sp.Id -PrincipalId $script:Provisioner.Sp.Id -ResourceId $script:GraphSp.Id -AppRoleId $fullControlRoleId | Out-Null
        Write-RunLog -Message "Admin consent granted: $script:ProvisionerAppName -> Sites.FullControl.All" -Level SUCCESS
    }
    else {
        Write-RunLog -Message "Admin consent already present: $script:ProvisionerAppName -> Sites.FullControl.All"
    }
}

function New-AndAttachCertificate {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Microsoft.Graph.PowerShell.Models.MicrosoftGraphApplication]$App,
        [string]$SubjectCN, [int]$Years
    )
    if (-not (Test-Path $script:CertOutFolder)) { $null = New-Item -ItemType Directory -Path $script:CertOutFolder -Force }

    Write-RunLog -Message "Creating self‑signed certificate ($Years year[s]) for '$($App.DisplayName)'..."
    if (-not $PSCmdlet.ShouldProcess("Application '$($App.DisplayName)'", "Create and attach certificate '$SubjectCN'")) {
        throw "Certificate creation/attachment for '$($App.DisplayName)' was not approved."
    }
    $cert = New-SelfSignedCertificate -Subject $SubjectCN -CertStoreLocation "Cert:\CurrentUser\My" -KeyLength 2048 -KeyExportPolicy Exportable -KeyAlgorithm RSA -NotAfter (Get-Date).AddYears($Years)
    Write-RunLog -Message "Certificate created (Thumbprint: $($cert.Thumbprint))" -Level SUCCESS

    $cerPath = Join-Path $script:CertOutFolder ("{0}.cer" -f ($SubjectCN -replace '[\\/:*?"<>| ]', '_'))
    Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
    Write-RunLog -Message "Exported CER to '$cerPath'"

    $newKeyCred = @{
        type          = "AsymmetricX509Cert"
        usage         = "Verify"
        key           = [Convert]::ToBase64String($cert.RawData)
        displayName   = $SubjectCN
        endDateTime   = $cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        startDateTime = $cert.NotBefore.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    # Re-serialize existing keys as plain hashtables; skip any with missing Key bytes or null dates
    $existingKeys = @($App.KeyCredentials | Where-Object { $_.Key -and $_.EndDateTime } | ForEach-Object {
            @{
                type          = $_.Type
                usage         = $_.Usage
                displayName   = $_.DisplayName
                endDateTime   = ([DateTime]$_.EndDateTime).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                startDateTime = ([DateTime]$_.StartDateTime).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                keyId         = $_.KeyId.ToString()
                key           = [Convert]::ToBase64String($_.Key)
            }
        })
    $body = @{ keyCredentials = @($existingKeys) + @($newKeyCred) }
    $null = Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($App.Id)" -Body ($body | ConvertTo-Json -Depth 10) -ContentType "application/json"
    Write-RunLog -Message "Attached certificate key credential to app '$($App.DisplayName)'" -Level SUCCESS
    $cert
}

function Export-CertCer {
    param([string]$Thumbprint, [string]$OutFile)
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object Thumbprint -eq $Thumbprint
    if (-not $cert) { throw "Certificate with thumbprint $Thumbprint not found in CurrentUser\My." }
    Export-Certificate -Cert $cert -FilePath $OutFile | Out-Null
    Write-RunLog -Message "Exported CER: $OutFile" -Level SUCCESS
}

function Export-CertPfx {
    param([string]$Thumbprint, [string]$OutFile, [securestring]$Password)
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object Thumbprint -eq $Thumbprint
    if (-not $cert) { throw "Certificate with thumbprint $Thumbprint not found in CurrentUser\My." }
    Export-PfxCertificate -Cert $cert -FilePath $OutFile -Password $Password | Out-Null
    Write-RunLog -Message "Exported PFX: $OutFile (password not logged)" -Level SUCCESS
}

function Resolve-GraphSiteId {
    param([string]$SiteUrl)
    $uri = [Uri]$SiteUrl
    $api = "https://graph.microsoft.com/v1.0/sites/$($uri.Host):$($uri.AbsolutePath)"
    Write-RunLog -Message "Resolving SiteId for $SiteUrl"
    $id = (Invoke-MgGraphRequest -Method GET -Uri $api).id
    Write-RunLog -Message "Resolved SiteId: $id" -Level SUCCESS
    $id
}

function Grant-SitePermissionToApp {
    param(
        [string]$ProvisionerClientId, [string]$ProvisionerCertThumbprint, [string]$TargetAppId, [string]$SiteId,
        [ValidateSet('read', 'write', 'manage', 'fullcontrol')][string]$Role
    )
    Write-RunLog -Message "Connecting as provisioning app to grant '$Role' on SiteId [$SiteId]"
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    Connect-MgGraph -TenantId $script:TenantId -ClientId $ProvisionerClientId -CertificateThumbprint $ProvisionerCertThumbprint -NoWelcome
    Write-RunLog -Message "Connected as provisioning app" -Level SUCCESS

    Write-RunLog -Message "Granting role '$Role' to TargetAppId: $TargetAppId on SiteId: $SiteId"
    $perm = New-MgSitePermission -SiteId $SiteId -Roles $Role -GrantedToIdentities @(@{ application = @{ id = $TargetAppId; displayName = $script:TargetAppName } })
    Write-RunLog -Message "Grant created (PermissionId: $($perm.id))" -Level SUCCESS
    $perm
}

function Test-AppSitePermission {
    param([string]$SiteId, [string]$TargetAppId)
    Write-RunLog -Message "Validating permissions on SiteId: $SiteId for AppId: $TargetAppId"
    $perms = Get-MgSitePermission -SiteId $SiteId -All
    $perms | Where-Object { $_.grantedToIdentitiesV2.application.id -contains $TargetAppId }
}

# [REVOKE] List app-specific permission objects on a site
function Get-TargetAppSitePermission {
    param([string]$SiteId, [string]$TargetAppId)
    Write-RunLog -Message "Retrieving permission objects on SiteId: $SiteId for AppId: $TargetAppId"
    $perms = Get-MgSitePermission -SiteId $SiteId -All
    $perms | Where-Object { $_.grantedToIdentitiesV2.application.id -contains $TargetAppId }
}

# [REVOKE] Remove a specific permission object on a site (uses provisioning app w/ Sites.FullControl.All)
function Revoke-SitePermissionFromApp {
    param([string]$ProvisionerClientId, [string]$ProvisionerCertThumbprint, [string]$SiteId, [string]$PermissionId)

    Write-RunLog -Message "Connecting as provisioning app to revoke PermissionId [$PermissionId] on SiteId [$SiteId]"
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    Connect-MgGraph -TenantId $script:TenantId -ClientId $ProvisionerClientId -CertificateThumbprint $ProvisionerCertThumbprint -NoWelcome
    Write-RunLog -Message "Connected as provisioning app" -Level SUCCESS

    # Remove-MgSitePermission -> DELETE /sites/{siteId}/permissions/{permissionId}
    Remove-MgSitePermission -SiteId $SiteId -PermissionId $PermissionId -Confirm:$false
    Write-RunLog -Message "Revoked permission (PermissionId: $PermissionId) on SiteId: $SiteId" -Level SUCCESS
}

#endregion

#region Interactive Prompts & Menus

function Read-SiteGrantInput {
    param(
        [string]$DefaultRole = 'FullControl',
        [string]$DefaultUrl = 'https://hpwqld.sharepoint.com/sites/qgpggs'
    )
    $entries = @()
    Write-Information "" -InformationAction Continue
    Write-RunLog -Level INFO -Message "Prompting for SharePoint site URLs to grant to '$script:TargetAppName'"
    Write-Information "Enter SharePoint site URLs (blank to finish). Press Enter with no URL to use default: $DefaultUrl" -InformationAction Continue

    while ($true) {
        $url = Read-Host "Site URL (Enter for default, blank twice to finish)"
        if ([string]::IsNullOrWhiteSpace($url)) {
            if ($entries.Count -eq 0 -and $DefaultUrl) {
                $url = $DefaultUrl
                Write-RunLog -Message "Using default URL: $url"
            }
            else { break }
        }
        if ($url -notmatch '^https://[^/]+\.sharepoint\.com/.+') {
            Write-RunLog -Level WARN -Message "URL does not look like SharePoint Online. Please try again."
            continue
        }
        $role = Read-Host "Role [read|write|manage|fullcontrol] (default: $DefaultRole)"
        if ([string]::IsNullOrWhiteSpace($role)) { $role = $DefaultRole }
        $role = $role.ToLowerInvariant()
        if ($role -eq 'fullaccess') { $role = 'fullcontrol' }
        if ($role -notin @('read', 'write', 'manage', 'fullcontrol')) {
            Write-RunLog -Level WARN -Message "Invalid role. Please enter read|write|manage|fullcontrol."
            continue
        }
        Write-RunLog -Message "Queued grant: $url => $role"
        $entries += @{ Url = $url; Role = $role }
    }
    return , $entries
}

# [REVOKE] Prompt for sites to revoke and perform revocation
function Invoke-SitePermissionRevocationPrompt {
    if (-not $script:ProvisionerCert) {
        Write-RunLog -Level WARN -Message "Provisioning app certificate not present. Create it first (Certificate Menu -> Option 1)."
        return
    }

    Write-Information "" -InformationAction Continue
    Write-RunLog -Level INFO -Message "Prompting for SharePoint site URLs to REVOKE permissions for '$script:TargetAppName'"
    Write-Information "Enter SharePoint site URLs to revoke (blank to finish). Example: https://hpwqld.sharepoint.com/sites/qgpggs" -InformationAction Continue

    $urls = @()
    while ($true) {
        $url = Read-Host "Site URL to revoke (blank to finish)"
        if ([string]::IsNullOrWhiteSpace($url)) { break }
        if ($url -notmatch '^https://[^/]+\.sharepoint\.com/.+') {
            Write-RunLog -Level WARN -Message "URL does not look like SharePoint Online. Please try again."
            continue
        }
        $urls += $url
    }
    if ($urls.Count -eq 0) {
        Write-RunLog -Message "No sites entered; skipping revoke."
        return
    }

    foreach ($u in $urls) {
        Step "Revocation flow for $u"
        $siteId = Resolve-GraphSiteId -SiteUrl $u
        $current = Get-TargetAppSitePermission -SiteId $siteId -TargetAppId $script:Target.App.AppId

        if (-not $current) {
            Write-RunLog -Level WARN -Message "No permission objects found for target app on $u"
            continue
        }

        # Show and confirm
        Write-Information "`nPermissions for $u linked to '$script:TargetAppName':" -InformationAction Continue
        $idx = 0
        $map = @{}
        foreach ($p in $current) {
            $idx++
            $roles = ($p.roles -join ',')
            Write-Information "[$idx] PermissionId: $($p.id)  Roles: $roles" -InformationAction Continue
            $map[$idx] = $p.id
        }

        $sel = Read-Host "Enter number(s) to revoke (comma-separated) or 'ALL' to revoke all"
        if ([string]::IsNullOrWhiteSpace($sel)) { Write-RunLog -Message "No selection; skipping $u"; continue }

        $toRevoke = @()
        if ($sel.Trim().ToUpperInvariant() -eq 'ALL') {
            $toRevoke = $current.id
        }
        else {
            foreach ($token in $sel.Split(',', [System.StringSplitOptions]::RemoveEmptyEntries)) {
                $parsed = 0
                if ([int]::TryParse($token.Trim(), [ref]$parsed) -and $map.ContainsKey($parsed)) {
                    $toRevoke += $map[$parsed]
                }
            }
        }
        if ($toRevoke.Count -eq 0) { Write-RunLog -Message "Nothing selected to revoke for $u"; continue }

        $confirm = Read-Host "Confirm revoke on $u for $($toRevoke.Count) permission(s)? [Y/N]"
        if ($confirm -notmatch '^[Yy]$') { Write-RunLog -Message "Revoke canceled for $u"; continue }

        foreach ($permissionId in $toRevoke) {
            Revoke-SitePermissionFromApp -ProvisionerClientId $script:Provisioner.App.AppId -ProvisionerCertThumbprint $script:ProvisionerCert.Thumbprint -SiteId $siteId -PermissionId $permissionId
        }

        # Post-check
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Connect-GraphAdmin
        $left = Get-TargetAppSitePermission -SiteId $siteId -TargetAppId $script:Target.App.AppId
        if ($left) {
            $leftIds = ($left.id -join ', ')
            Write-RunLog -Level WARN -Message "Still present after revoke on $($u): $leftIds (Graph propagation may take ~60s)"
        }
        else {
            Write-RunLog -Level SUCCESS -Message "All selected permissions revoked on $u"
        }
    }
}

function Show-CertMenu {
    Write-Information "" -InformationAction Continue
    Write-Information "=== Certificate Menu ===" -InformationAction Continue
    Write-Information "[1] Create & attach certificates for both apps" -InformationAction Continue
    Write-Information "[2] Export certificate(s) to CER" -InformationAction Continue
    Write-Information "[3] Export certificate(s) to PFX" -InformationAction Continue
    Write-Information "[4] Skip certificate operations" -InformationAction Continue
    $choice = Read-Host "Select an option [1-4]"
    switch ($choice) {
        '1' { Step "Creating & attaching certificates for both apps"; $script:ProvisionerCert = New-AndAttachCertificate -App $script:Provisioner.App -SubjectCN "CN=$script:ProvisionerAppName" -Years $script:CertValidityYears; $script:TargetCert = New-AndAttachCertificate -App $script:Target.App -SubjectCN "CN=$script:TargetAppName" -Years $script:CertValidityYears }
        '2' { Step "Exporting certificate(s) to CER"; if (-not (Test-Path $script:CertOutFolder)) { $null = New-Item -ItemType Directory -Path $script:CertOutFolder -Force }; $appSelect = Read-Host "Export CER for (T)arget, (P)rovisioner, (B)oth? [T/P/B]"; if ($appSelect -match '^[TtB]$') { if ($script:TargetCert) { Export-CertCer -Thumbprint $script:TargetCert.Thumbprint -OutFile (Join-Path $script:CertOutFolder "QGPGGS_SharePoint.cer") } else { Write-RunLog -Level WARN -Message "Target cert not found; create via option 1." } }; if ($appSelect -match '^[PpB]$') { if ($script:ProvisionerCert) { Export-CertCer -Thumbprint $script:ProvisionerCert.Thumbprint -OutFile (Join-Path $script:CertOutFolder "SitesSelected_provisioning.cer") } else { Write-RunLog -Level WARN -Message "Provisioner cert not found; create via option 1." } } }
        '3' { Step "Exporting certificate(s) to PFX"; if (-not (Test-Path $script:CertOutFolder)) { $null = New-Item -ItemType Directory -Path $script:CertOutFolder -Force }; $appSelect = Read-Host "Export PFX for (T)arget, (P)rovisioner, (B)oth? [T/P/B]"; $pass = Read-Host "Enter PFX password" -AsSecureString; if ($appSelect -match '^[TtB]$') { if ($script:TargetCert) { Export-CertPfx -Thumbprint $script:TargetCert.Thumbprint -OutFile (Join-Path $script:CertOutFolder "QGPGGS_SharePoint.pfx") -Password $pass } else { Write-RunLog -Level WARN -Message "Target cert not found; create via option 1." } }; if ($appSelect -match '^[PpB]$') { if ($script:ProvisionerCert) { Export-CertPfx -Thumbprint $script:ProvisionerCert.Thumbprint -OutFile (Join-Path $script:CertOutFolder "SitesSelected_provisioning.pfx") -Password $pass } else { Write-RunLog -Level WARN -Message "Provisioner cert not found; create via option 1." } } }
        default { Write-RunLog -Message "Skipping certificate operations." }
    }
}

#endregion

#region Main orchestration

try {
    Step "Connecting to Graph as admin"
    Connect-GraphAdmin

    Step "Ensuring apps and Graph permissions"
    Set-AppAndPermissionState

    Step "Certificate operations"
    Show-CertMenu

    Write-Information "" -InformationAction Continue
    Step "Prompting for site URLs & roles for GRANT"
    $proceedGrant = Read-Host "Do you want to enter site URLs and grant permissions now? [Y/N]"
    $siteGrants = @()
    if ($proceedGrant -match '^[Yy]$') {
        $siteGrants = Read-SiteGrantInput -DefaultRole $script:DefaultRole
        if ($siteGrants.Count -eq 0) {
            Write-RunLog -Message "No sites entered; skipping grants."
        }
        else {
            if (-not $script:ProvisionerCert) {
                Write-RunLog -Level WARN -Message "Provisioning cert not present. Create it first (Certificate Menu -> Option 1)."
            }
            else {
                foreach ($g in $siteGrants) {
                    Step "Granting '$($g.Role)' to '$script:TargetAppName' on $($g.Url)"
                    $siteId = Resolve-GraphSiteId -SiteUrl $g.Url
                    $perm = Grant-SitePermissionToApp -ProvisionerClientId $script:Provisioner.App.AppId -ProvisionerCertThumbprint $script:ProvisionerCert.Thumbprint -TargetAppId $script:Target.App.AppId -SiteId $siteId -Role $g.Role
                    Write-RunLog -Level SUCCESS -Message "Grant complete (PermissionId: $($perm.id)) for $($g.Url)"
                }
            }
        }
    }
    else {
        Write-RunLog -Message "Grant phase skipped by operator."
    }

    # [REVOKE] New revoke option
    Write-Information "" -InformationAction Continue
    Step "Prompting for REVOKE"
    $doRevoke = Read-Host "Do you want to REVOKE existing permissions for '$script:TargetAppName'? [Y/N]"
    if ($doRevoke -match '^[Yy]$') {
        Step "Revocation flow"
        Invoke-SitePermissionRevocationPrompt
    }
    else {
        Write-RunLog -Message "Revoke skipped."
    }

    # Validation (optional)
    Write-Information "" -InformationAction Continue
    Step "Validation prompt"
    $doValidate = Read-Host "Validate permissions on any sites you just GRANTED? [Y/N]"
    if ($doValidate -match '^[Yy]$' -and $siteGrants.Count -gt 0) {
        Step "Reconnecting as admin for validation"
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Connect-GraphAdmin

        foreach ($g in $siteGrants) {
            Step "Validating grant on $($g.Url)"
            $siteId = Resolve-GraphSiteId -SiteUrl $g.Url
            $found = Test-AppSitePermission -SiteId $siteId -TargetAppId $script:Target.App.AppId
            if ($found) {
                $roles = ($found | Select-Object -ExpandProperty roles) -join ","
                Write-RunLog -Level SUCCESS -Message "OK: $($g.Url) -> roles: $roles"
            }
            else {
                Write-RunLog -Level WARN -Message "Not found (yet): $($g.Url) — Graph propagation may take ~60 seconds. Re-check later."
            }
        }
    }
    else {
        Write-RunLog -Message "Validation skipped."
    }

    Step "Summary"
    $resolvedCertFolder = if (Test-Path $script:CertOutFolder) { (Resolve-Path $script:CertOutFolder).Path } else { $script:CertOutFolder }
    $resolvedLogFile = if (Test-Path $script:LogFile) { (Resolve-Path $script:LogFile).Path } else { $script:LogFile }

    $summary = [pscustomobject]@{
        TenantId                  = $script:TenantId
        TargetAppName             = $script:Target.App.DisplayName
        TargetAppId               = $script:Target.App.AppId
        TargetSpObjectId          = $script:Target.Sp.Id
        ProvisionerAppName        = $script:Provisioner.App.DisplayName
        ProvisionerAppId          = $script:Provisioner.App.AppId
        ProvisionerSpObjectId     = $script:Provisioner.Sp.Id
        ProvisionerCertThumbprint = if ($script:ProvisionerCert) { $script:ProvisionerCert.Thumbprint } else { "" }
        TargetCertThumbprint      = if ($script:TargetCert) { $script:TargetCert.Thumbprint } else { "" }
        CertFolder                = $resolvedCertFolder
        LogFile                   = $resolvedLogFile
    }

    Write-Information "`n==== Provisioning Summary ====" -InformationAction Continue
    $summary | Format-List | Out-String | Tee-Object -FilePath $script:LogFile -Append | Out-Host
    Write-RunLog -Level SUCCESS -Message "Completed. Log file: $script:LogFile"

}
catch {
    Write-RunLog -Level ERROR -Message $_.ToString()
    throw
}
finally {
    # Optionally auto-disconnect:
    # Disconnect-MgGraph | Out-Null
}

#endregion
