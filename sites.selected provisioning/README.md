Here are some different scripts all of which are about adding the permission to a sharepoint site via graph api; i haven't settled on which apprach is the best yet; some day i will narrow down the scripts here.


## Sites.Selected provisioning (SharePoint Online)

### Synopsis
Provision **Entra ID app registrations** for SharePoint Online **Sites.Selected**, create certificates for authentication, **grant & revoke** site-level permissions, and validate that the Sites.Selected permissions have applied correctly.

This script is **menu-driven**, writes **full logs**, and outputs step-by-step informational status to the console.

> Sites.Selected has many different ways to implement it, and many sites make it more complicated than it really should be.

---

### Description
Creates/ensures **two** app registrations:

- **My SharePoint** *(target app)*  
  - Microsoft Graph **application permission**: `Sites.Selected`
- **Sites.Selected provisioning** *(provisioner app)*  
  - Microsoft Graph **application permission**: `Sites.FullControl.All`

Provides menus to:

1. **Create & attach** self-signed certificates  
2. **Export** `CER` / `PFX`  
3. Prompt for **site URLs + roles** (`read` | `write` | `manage` | `fullcontrol`), then **grant** to the target app  
4. **Revoke** existing site permissions for the target app *(REVOKE)*  
5. **Validate** the resulting grants

---

### Notes
- Uses **first‑party** `Microsoft.Graph` PowerShell modules.
- Avoids `Sites.Read.All`. Uses **Sites.Selected + explicit per‑site grants** (*least privilege*).
- Logging writes to `./logs` with **timestamped** file names; the console shows **step numbers & statuses**.

---

### References
- Delete permission on a site (Microsoft Graph): `DELETE /sites/{siteId}/permissions/{permissionId}` *(used by `Remove-MgSitePermission` — REVOKE)*  
  `https://learn.microsoft.com/graph/api/site-delete-permission?view=graph-rest-1.0`

- `Remove-MgSitePermission` cmdlet (`Microsoft.Graph.Sites`) *(REVOKE)*  
  `https://learn.microsoft.com/powershell/module/microsoft.graph.sites/remove-mgsitepermission?view=graph-powershell-1.0`

- Selected permissions model & roles (`Sites.Selected`)  
  `https://learn.microsoft.com/graph/permissions-selected-overview`

---

### Changelog
- **2026-03-11**: Initial version — apps, certs, grants, verification. Author: Aaron Francis  
- **2026-03-11**: Added interactive menu for certificate creation/export, URL prompts, and end-of-run validation prompt. Author: Aaron Francis  
- **2026-03-11**: Added step-by-step console output and timestamped file logging. Author: Aaron Francis  
- **2026-03-11**: Added **REVOKE** permission option (interactive) using `Remove-MgSitePermission`. Author: Aaron Francis
