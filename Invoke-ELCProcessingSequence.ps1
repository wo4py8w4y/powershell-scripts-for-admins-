<#
.SYNOPSIS
    Endlessly automates Managed Folder Assistant invocation and diagnostic log polling for targets.
.DESCRIPTION
    1. Runs inside an infinite while($true) loop.
    2. Filters mailboxes dynamically each cycle where email addresses start with 'qbuildseq'.
    3. Sequentially triggers Start-ManagedFolderAssistant.
    4. Pauses for 200 seconds with real-time countdown progress.
    5. Appends pivoted ELC diagnostic logs to a centralized CSV audit trail.
    6. Fault-tolerant loop design continues on individual mailbox errors.
.NOTES
    Architecture: Continuous Daemon, REST-optimized, Fault-Tolerant, Color-Coded.
#>

param (
    [Parameter(Mandatory = $false)]
    [string]$PrefixFilter = "qbuildseqmrc",

    [Parameter(Mandatory = $false)]
    [int]$PauseDelaySeconds = 200,

    # Cooldown pause time before starting the next infinite iteration loop cycle
    [Parameter(Mandatory = $false)]
    [int]$CycleCooldownMinutes = 30,

    [Parameter(Mandatory = $false)]
    [int]$MaxRetries = 4
)

# --- Global Initialization ---
$Global:MasterAuditLog = ".\ELC_Processing_AuditLog_$(Get-Date -Format 'yyyy-MM-dd_HH-mm').csv"

# --- Telemetry & Logging Modules ---

function Write-AuditLog {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [Parameter(Mandatory=$false)][ValidateSet("Info", "Success", "Warning", "Error", "Progress", "Cycle")]$Status = "Info"
    )
    $Color = switch ($Status) {
        "Success"   { "Green" }
        "Warning"   { "Yellow" }
        "Error"     { "Red" }
        "Progress"  { "Magenta" }
        "Cycle"     { "Cyan" } # Standout visual marker for cycle boundaries
        Default     { "Gray" }
    }
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$($Status.ToUpper())] $Message" -ForegroundColor $Color
}

function Test-ExchangeOnlineConnection {
    if (Get-Module -Name ExchangeOnlineManagement -ListAvailable) {
        try {
            $ConnectedSessions = Get-ConnectionInformation -ErrorAction Stop | Where-Object { $_.State -eq 'Connected' }
            return [bool]$ConnectedSessions
        } catch { return $false }
    }
    return $false
}

function Invoke-WithRetry {
    param(
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
        [string]$EntityName = "Unknown"
    )
    $Attempt = 0
    do {
        try { return & $ScriptBlock } 
        catch {
            $Attempt++
            if ($Attempt -ge $MaxRetries) { throw $_ }
            $SleepSeconds = [math]::Pow(2, $Attempt) + (Get-Random -Minimum 1 -Maximum 4)
            Write-AuditLog "EXO API Throttling hit on $EntityName. Auto-backing off for ${SleepSeconds}s..." "Warning"
            Start-Sleep -Seconds $SleepSeconds
        }
    } while ($Attempt -lt $MaxRetries)
}

# --- Core Processing Core ---

function Get-ManagedFolderAssistantLogs {
    param (
        [Parameter(Mandatory=$true)][object]$MailboxObject
    )

    $MailboxIdentity = $MailboxObject.UserPrincipalName
    
    try {
        Write-AuditLog "Extracting diagnostic XML payload for $MailboxIdentity..." "Info"
        
        $LogProps = Invoke-WithRetry -EntityName "DiagLogs-$MailboxIdentity" -ScriptBlock {
            Export-MailboxDiagnosticLogs -Identity $MailboxIdentity -ExtendedProperties -ErrorAction Stop
        }

        if ([string]::IsNullOrWhiteSpace($LogProps.MailboxLog)) {
            Write-AuditLog "Diagnostic MailboxLog payload was empty or unpopulated for $MailboxIdentity." "Warning"
            return $null
        }

        $XmlProps = [xml]$LogProps.MailboxLog
        $ELCData = $XmlProps.Properties.MailboxTable.Property | Where-Object { $_.Name -like "ELC*" }

        if (-not $ELCData) {
            Write-AuditLog "No explicit ELC parameters present in XML metadata for $MailboxIdentity." "Warning"
            return $null
        }

        $RecordHash = [ordered]@{
            'Timestamp'        = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            'Mailbox Name'     = $MailboxObject.DisplayName
            'UPN'              = $MailboxIdentity
            'Exchange GUID'    = $MailboxObject.ExchangeGuid
        }

        foreach ($Prop in $ELCData) {
            $RecordHash[$Prop.Name] = $Prop.Value
        }

        return [PSCustomObject]$RecordHash
    }
    catch {
        Write-AuditLog "Non-terminating extraction error on $MailboxIdentity : $($_.Exception.Message)" "Error"
        return $null
    }
}

function Invoke-ELCProcessingSequence {
    if (-not (Test-ExchangeOnlineConnection)) {
        Write-AuditLog "Execution Blocked: Please execute Connect-ExchangeOnline before running this pipeline." "Error"
        return
    }

    $CycleCount = 0

    # Explicit infinite monitoring engine wrap
    while ($true) {
        $CycleCount++
        Write-Host "`n====================================================================================" -ForegroundColor DarkGray
        Write-AuditLog "INITIALIZING AUTOMATION LOOP CYCLE #$CycleCount" "Cycle"
        Write-Host "====================================================================================`n" -ForegroundColor DarkGray

        # Dynamically discover targets every loop cycle to catch new provisioning changes automatically
        Write-AuditLog "Querying directory matrix for email addresses starting with '$PrefixFilter'..." "Progress"
        $TargetMailboxes = @()
        try {
            $TargetMailboxes = Invoke-WithRetry -EntityName "BulkMailboxDiscovery" -ScriptBlock {
                Get-EXOMailbox -ResultSize Unlimited -Properties DisplayName, UserPrincipalName, ExchangeGuid, EmailAddresses -ErrorAction Stop | 
                Where-Object { $_.EmailAddresses -match "^smtp:$PrefixFilter" -or $_.EmailAddresses -match "^SMTP:$PrefixFilter" }
            }
        } catch {
            Write-AuditLog "Discovery phase broken this cycle: $($_.Exception.Message). Will attempt retry on next pass..." "Error"
            Start-Sleep -Seconds 30
            continue
        }

        $TotalQueue = $TargetMailboxes.Count
        if ($TotalQueue -eq 0) {
            Write-AuditLog "Zero mailboxes matched the criteria prefix '$PrefixFilter' on this cycle pass." "Warning"
        } else {
            Write-AuditLog "Target matrix acquired. Found $TotalQueue matching mailboxes. Beginning batch execution..." "Success"
            $CurrentIndex = 0

            foreach ($Mailbox in $TargetMailboxes) {
                $CurrentIndex++
                $UPN = $Mailbox.UserPrincipalName
                
                Write-Progress -Activity "Executing ELC Continuous Cycle #$CycleCount" -Status "Processing ($CurrentIndex/$TotalQueue): $UPN" -PercentComplete (($CurrentIndex / $TotalQueue) * 100)
                Write-AuditLog "[$CurrentIndex/$TotalQueue] Starting processing tree for: $UPN" "Progress"

                # 1. Trigger MFA
                try {
                    Write-AuditLog "Invoking Start-ManagedFolderAssistant for $UPN..." "Info"
                    Invoke-WithRetry -EntityName "StartMFA-$UPN" -ScriptBlock {
                        Start-ManagedFolderAssistant -Identity $UPN -ErrorAction Stop
                    }
                    Write-AuditLog "MFA command successfully committed for $UPN." "Success"
                } 
                catch {
                    Write-AuditLog "MFA trigger failed on $UPN. Continuing loop iteration to bypass fault..." "Error"
                    Write-Host "----------------------------------------------------" -ForegroundColor DarkGray
                    continue
                }

                # 2. Cooldown Countdown
                Write-AuditLog "Pausing for $PauseDelaySeconds seconds to allow backend worker compilation..." "Info"
                for ($i = $PauseDelaySeconds; $i -gt 0; $i--) {
                    Write-Progress -Activity "MFA Cooldown Phase (Cycle #$CycleCount - Mailbox $CurrentIndex/$TotalQueue)" -Status "Waiting for backend on $UPN... ${i}s remaining" -PercentComplete (($CurrentIndex / $TotalQueue) * 100)
                    Start-Sleep -Seconds 1
                }

                # 3. Process XML Matrix Logs
                try {
                    $PivotedLogData = Get-ManagedFolderAssistantLogs -MailboxObject $Mailbox
                    
                    if ($null -ne $PivotedLogData) {
                        $PivotedLogData | Export-Csv -Path $Global:MasterAuditLog -NoTypeInformation -Append -ErrorAction Stop
                        Write-AuditLog "ELC transaction record successfully appended to CSV for $UPN." "Success"
                    } else {
                        Write-AuditLog "No log entries captured for $UPN (Diagnostic block unpopulated)." "Warning"
                    }
                }
                catch {
                    Write-AuditLog "Failed to append log row for $UPN : $($_.Exception.Message). Continuing loop..." "Error"
                }
                
                Write-Host "----------------------------------------------------" -ForegroundColor DarkGray
            }
        }

        Write-Progress -Activity "Executing ELC Continuous Cycle #$CycleCount" -Completed
        
        # Inter-cycle delay phase to prevent API abuse thresholds
        Write-AuditLog "Cycle #$CycleCount ended. Cooldown window active for the next $CycleCooldownMinutes minutes..." "Cycle"
        for ($m = $CycleCooldownMinutes; $m -gt 0; $m--) {
            for ($s = 59; $s -ge 0; $s--) {
                Write-Progress -Activity "Daemon Inter-Cycle Sleep Pipeline" -Status "Next monitoring scan in -> ${m}m ${s}s remaining [Ctrl+C to Terminate]" -PercentComplete ((($CycleCooldownMinutes - $m) / $CycleCooldownMinutes) * 100)
                Start-Sleep -Seconds 1
            }
        }
        Write-Progress -Activity "Daemon Inter-Cycle Sleep Pipeline" -Completed
    }
}

# --- Launch Entry Point ---
Clear-Host
Invoke-ELCProcessingSequence