$scriptPath='c:\TEMP\ENTRA\sites.selected wizard -adds Revoke.ps1'

Write-Output '--SMOKE_START--'

'Connect-MgGraph','Disconnect-MgGraph','Get-MgContext','Get-MgApplication','New-MgApplication','Get-MgServicePrincipal','New-MgServicePrincipal','Get-MgServicePrincipalAppRoleAssignment','New-MgServicePrincipalAppRoleAssignment','Update-MgApplication','Invoke-MgGraphRequest','Get-MgSitePermission','New-MgSitePermission','Remove-MgSitePermission','Read-Host' | ForEach-Object {
    if (Get-Command $_ -ErrorAction SilentlyContinue | Where-Object CommandType -eq 'Function') {
        Remove-Item ("function:global:{0}" -f $_) -ErrorAction SilentlyContinue
    }
}

Import-Module Microsoft.Graph.Sites -ErrorAction Stop

$global:MockAppsByName = @{}
$global:MockSpsByAppId = @{}
$global:ReadHostQueue = [System.Collections.Generic.Queue[string]]::new()
@('4','N','N','N') | ForEach-Object { $global:ReadHostQueue.Enqueue($_) }

function global:Read-Host {
    param([Parameter(Position=0)][string]$Prompt,[switch]$AsSecureString)
    if ($AsSecureString) { return (ConvertTo-SecureString 'dummy' -AsPlainText -Force) }
    if ($global:ReadHostQueue.Count -gt 0) { return $global:ReadHostQueue.Dequeue() }
    return ''
}

function global:Connect-MgGraph { param([string]$TenantId,[string[]]$Scopes,[string]$ClientId,[string]$CertificateThumbprint,[switch]$NoWelcome) }
function global:Disconnect-MgGraph { param() }
function global:Get-MgContext { [pscustomobject]@{ TenantId='ec445a2a-b5ba-46f6-bead-4595e9fbd4a2' } }
function global:Get-MgApplication {
    param([switch]$All,[string]$Filter)
    if ($Filter -match "displayName eq '(.+)'") {
        $name = $Matches[1]
        if ($global:MockAppsByName.ContainsKey($name)) { return $global:MockAppsByName[$name] }
    }
    $null
}
function global:New-MgApplication {
    param([string]$DisplayName)
    $app = [pscustomobject]@{ DisplayName=$DisplayName; AppId=[guid]::NewGuid().Guid; Id=[guid]::NewGuid().Guid; KeyCredentials=@() }
    $global:MockAppsByName[$DisplayName] = $app
    $app
}
function global:Get-MgServicePrincipal {
    param([switch]$All,[string]$Filter)
    if ($Filter -match "appId eq '00000003-0000-0000-c000-000000000000'") {
        return [pscustomobject]@{
            Id='graph-sp-obj-id'
            AppRoles=@(
                [pscustomobject]@{ Value='Sites.Selected'; AllowedMemberTypes=@('Application'); Id='role-sites-selected' },
                [pscustomobject]@{ Value='Sites.FullControl.All'; AllowedMemberTypes=@('Application'); Id='role-sites-fullcontrol-all' }
            )
        }
    }
    if ($Filter -match "appId eq '(.+)'") {
        $appId = $Matches[1]
        if ($global:MockSpsByAppId.ContainsKey($appId)) { return $global:MockSpsByAppId[$appId] }
    }
    $null
}
function global:New-MgServicePrincipal {
    param([string]$AppId)
    $sp=[pscustomobject]@{ AppId=$AppId; Id=[guid]::NewGuid().Guid }
    $global:MockSpsByAppId[$AppId]=$sp
    $sp
}
function global:Get-MgServicePrincipalAppRoleAssignment { param([string]$ServicePrincipalId,[switch]$All) @() }
function global:New-MgServicePrincipalAppRoleAssignment { param([string]$ServicePrincipalId,[string]$PrincipalId,[string]$ResourceId,[string]$AppRoleId) [pscustomobject]@{ Id=[guid]::NewGuid().Guid } }
function global:Update-MgApplication { param([string]$ApplicationId,$KeyCredentials) }
function global:Invoke-MgGraphRequest { param([string]$Method,[string]$Uri) [pscustomobject]@{ id='mock-site-id' } }
function global:Get-MgSitePermission { param([string]$SiteId,[switch]$All) @() }
function global:New-MgSitePermission { param([string]$SiteId,[string[]]$Roles,$GrantedToIdentities) [pscustomobject]@{ id='mock-perm-id' } }
function global:Remove-MgSitePermission { param([string]$SiteId,[string]$PermissionId,[switch]$Confirm) }

try {
    & $scriptPath -ErrorAction Stop
    Write-Output 'SMOKE_TEST_RESULT=PASS'
}
catch {
    Write-Output ("SMOKE_TEST_RESULT=FAIL :: {0}" -f $_.Exception.Message)
    if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
        Write-Output ("FAIL_POSITION :: {0}" -f $_.InvocationInfo.PositionMessage)
    }
    if ($_.ScriptStackTrace) {
        Write-Output ("FAIL_STACK :: {0}" -f $_.ScriptStackTrace)
    }
}

Write-Output '--SMOKE_END--'
