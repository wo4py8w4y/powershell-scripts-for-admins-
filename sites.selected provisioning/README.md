.SYNOPSIS
    Provision Entra ID app registrations for SharePoint Online Sites.Selected, creates certificates for authentication,
    grant & revoke site-level permissions, and validate the sites.selected permisions have applied correctly.
    Menu driven selections and full logging output and informational output to console.
Sites.selected has many many different ways to action and many sites make it more complicated than it really should be.

.DESCRIPTION
    Creates/ensures two app registrations:
      - "My SharePoint" (target): Microsoft Graph "Sites.Selected" application permission.
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
