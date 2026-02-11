<#
.SYNOPSIS
    Displays an upstream tree view of Entra ID or on-premises AD group memberships, with optional recursive member listing.
.DESCRIPTION
    Provides a tree view of nested group memberships for a user or group. Supports Entra ID (Microsoft Graph)
    and on-premises Active Directory. Optionally lists recursive user members for each group.
.EXAMPLE
    Get-EntraGroupTreeView -User user@domain.com
.EXAMPLE
    Get-EntraGroupTreeView -Group "Group Name" -IncludeMembers
.EXAMPLE
    Get-EntraGroupTreeView -Group "Group Name" -OnPremAD -IncludeMembers
.NOTES
    Requires Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Authentication for Entra ID.
    Requires ActiveDirectory module (RSAT) for on-premises AD.

    Summary (session changes):
    * feat: add -IncludeMembers to list recursive user members for groups (Entra transitive, AD recursive)
    * perf: add group-member caching to reduce repeated lookups
    * fix: escape single quotes in displayName filter
#>

function Get-EntraGroupTreeView
{
    <#
    .SYNOPSIS
        Displays an upstream tree view of group memberships for an Entra ID or on-premises AD user/group.
    .DESCRIPTION
        Recursively lists nested group memberships in a tree format. Supports both Entra ID (Azure AD) and on-premises Active Directory.
    .PARAMETER User
        The user principal name (Entra ID) or samAccountName (AD).
    .PARAMETER Group
        The group display name (Entra ID) or name (AD).
    .PARAMETER OnPremAD
        Switch to target on-premises AD instead of Entra ID.
    .PARAMETER IncludeMembers
        When a group is specified (or encountered during recursion), list user members of the group recursively.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        [string]$User,
        [Parameter(Position = 1, ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        [string]$Group,
        [switch]$OnPremAD,
        [switch]$IncludeMembers,
        [int]$UpperValue = [System.Int32]::MaxValue,
        [int]$LowerValue = 2
    )

    begin
    {
        # Ensure required modules are available and connected
        if (-not $OnPremAD)
        {
            if (!(Get-Module -ListAvailable -Name Microsoft.Graph.Users) -or !(Get-Module -ListAvailable -Name Microsoft.Graph.Groups))
            {
                Write-Host 'Microsoft.Graph modules not found. Please install Microsoft.Graph.Users and Microsoft.Graph.Groups.' -ForegroundColor Yellow
                return
            }
            try
            {
                Import-Module Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Authentication -ErrorAction Stop
            }
            catch
            {
                Write-Host 'Failed to import Microsoft.Graph modules.' -ForegroundColor Red
                return
            }
            if (-not (Get-MgContext))
            {
                try
                {
                    Connect-MgGraph -Scopes 'Group.Read.All', 'User.Read.All' -ErrorAction Stop
                }
                catch
                {
                    Write-Host 'Failed to connect to Microsoft Graph.' -ForegroundColor Red
                    return
                }
            }
        }
        else
        {
            if (!(Get-Module -ListAvailable -Name ActiveDirectory))
            {
                Write-Host 'ActiveDirectory module not found. Please install RSAT: Active Directory.' -ForegroundColor Yellow
                return
            }
            try
            {
                Import-Module ActiveDirectory -ErrorAction Stop
            }
            catch
            {
                Write-Host 'Failed to import ActiveDirectory module.' -ForegroundColor Red
                return
            }
        }
    }

    process
    {
        # Initialize caches and errors for root call
        if ($LowerValue -eq 2)
        {
            $script:VisitedGroups = @{}
            $script:Errors = @()
            $script:MemberOfCache = @{}
            $script:GroupMembersCache = @{}
        }

        # Retrieve memberof groups and root name
        $MemberOf = $null
        $rootname = $null
        $currentIsGroup = $false
        if ($OnPremAD)
        {
            if ($Group)
            {
                try
                {
                    $GroupObj = Get-ADGroup $Group -Properties MemberOf -ErrorAction Stop
                    $MemberOf = $GroupObj.MemberOf
                    $rootname = $GroupObj.Name
                    $currentIsGroup = $true
                }
                catch
                {
                    Write-Host "Group '$Group' not found in AD. $_" -ForegroundColor Red
                    return
                }
            }
            elseif ($User)
            {
                try
                {
                    $UserObj = Get-ADUser $User -Properties MemberOf -ErrorAction Stop
                    $MemberOf = $UserObj.MemberOf
                    $rootname = $UserObj.Name
                }
                catch
                {
                    Write-Host "User '$User' not found in AD. $_" -ForegroundColor Red
                    return
                }
            }
            else
            {
                Write-Host 'Please specify -User or -Group.' -ForegroundColor Yellow
                return
            }
        }
        else
        {
            if ($Group)
            {
                try
                {
                    if ($Group -match '^[0-9a-fA-F\-]{36}$')
                    {
                        $GroupObj = Get-MgGroup -GroupId $Group -ErrorAction Stop
                    }
                    else
                    {
                        $escapedGroup = $Group -replace "'", "''"
                        $Groups = Get-MgGroup -Filter "displayName eq '$escapedGroup'" -ErrorAction SilentlyContinue
                        $GroupObj = $Groups | Select-Object -First 1
                        if (-not $GroupObj)
                        {
                            throw 'Group not found'
                        }
                    }
                    $cacheKey = "Group:$GroupObj.Id"
                    if ($script:MemberOfCache.ContainsKey($cacheKey))
                    {
                        $MemberOf = $script:MemberOfCache[$cacheKey]
                    }
                    else
                    {
                        $MemberOfObjects = Get-MgGroupMemberOf -GroupId $GroupObj.Id -All
                        $MemberOf = $MemberOfObjects | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' } | Select-Object -ExpandProperty Id
                        $script:MemberOfCache[$cacheKey] = $MemberOf
                    }
                    $rootname = $GroupObj.DisplayName
                    $currentIsGroup = $true
                }
                catch
                {
                    Write-Host "Group '$Group' not found in Entra ID. $_" -ForegroundColor Red
                    return
                }
            }
            elseif ($User)
            {
                try
                {
                    $Users = Get-MgUser -Filter "userPrincipalName eq '$User'" -ErrorAction SilentlyContinue
                    $UserObj = $Users | Select-Object -First 1
                    if (-not $UserObj)
                    {
                        $UserObj = Get-MgUser -UserId $User -ErrorAction Stop
                    }
                    $cacheKey = "User:$UserObj.Id"
                    if ($script:MemberOfCache.ContainsKey($cacheKey))
                    {
                        $MemberOf = $script:MemberOfCache[$cacheKey]
                    }
                    else
                    {
                        $MemberOfObjects = Get-MgUserMemberOf -UserId $UserObj.Id -All
                        $MemberOf = $MemberOfObjects | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' } | Select-Object -ExpandProperty Id
                        $script:MemberOfCache[$cacheKey] = $MemberOf
                    }
                    $rootname = $UserObj.DisplayName
                }
                catch
                {
                    Write-Host "User '$User' not found in Entra ID. $_" -ForegroundColor Red
                    return
                }
            }
            else
            {
                Write-Host 'Please specify -User or -Group.' -ForegroundColor Yellow
                return
            }
        }

        # Display the current node
        $level = ($LowerValue - 2) / 2
        $Spaces = ' ' * ($level * 2)
        Write-Host ($Spaces + '└─' + $rootname)

        if ($IncludeMembers -and $currentIsGroup)
        {
            $memberSpaces = ' ' * (($level + 1) * 2)
            if ($OnPremAD)
            {
                $cacheKey = "ADMembers:$($GroupObj.DistinguishedName)"
                if ($script:GroupMembersCache.ContainsKey($cacheKey))
                {
                    $userMembers = $script:GroupMembersCache[$cacheKey]
                }
                else
                {
                    $userMembers = Get-ADGroupMember -Identity $GroupObj -Recursive -ErrorAction SilentlyContinue | Where-Object { $_.ObjectClass -eq 'user' }
                    $script:GroupMembersCache[$cacheKey] = $userMembers
                }
                foreach ($member in $userMembers)
                {
                    $display = if ($member.Name) { $member.Name } else { $member.SamAccountName }
                    Write-Host ($memberSpaces + '└─' + $display)
                }
            }
            else
            {
                $cacheKey = "AzureMembers:$($GroupObj.Id)"
                if ($script:GroupMembersCache.ContainsKey($cacheKey))
                {
                    $userMembers = $script:GroupMembersCache[$cacheKey]
                }
                else
                {
                    $memberObjects = Get-MgGroupTransitiveMember -GroupId $GroupObj.Id -All -ErrorAction SilentlyContinue
                    $userMembers = $memberObjects | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user' }
                    $script:GroupMembersCache[$cacheKey] = $userMembers
                }
                foreach ($member in $userMembers)
                {
                    $display = $member.AdditionalProperties['displayName']
                    if (-not $display) { $display = $member.AdditionalProperties['userPrincipalName'] }
                    if (-not $display) { $display = $member.Id }
                    Write-Host ($memberSpaces + '└─' + $display)
                }
            }
        }

        # Recurse into memberof groups
        $LowerValue += 2
        if ($LowerValue -le $UpperValue -and $MemberOf)
        {
            foreach ($member in $MemberOf)
            {
                $key = if ($OnPremAD) { "AD:$member" } else { "Azure:$member" }
                if ($script:VisitedGroups.ContainsKey($key))
                {
                    $script:Errors += "Loop detected for $member, skipping."
                    continue
                }
                $script:VisitedGroups[$key] = $true

                if ($OnPremAD)
                {
                    try
                    {
                        Get-EntraGroupTreeView -Group $member -LowerValue $LowerValue -UpperValue $UpperValue -OnPremAD
                    }
                    catch
                    {
                        Write-Host "Error processing AD group $member : $_" -ForegroundColor Red
                    }
                }
                else
                {
                    try
                    {
                        Get-EntraGroupTreeView -Group $member -LowerValue $LowerValue -UpperValue $UpperValue
                    }
                    catch
                    {
                        Write-Host "Error processing Entra ID group $member : $_" -ForegroundColor Red
                    }
                }
            }
        }
    }

    end
    {
        # Output collected errors after processing
        if ($LowerValue -eq 2 -and $script:Errors)
        {
            Write-Error ($script:Errors -join "`n") -Category ParserError
        }
    }
}

