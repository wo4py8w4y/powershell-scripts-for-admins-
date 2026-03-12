$scriptPath='c:\TEMP\ENTRA\sites.selected wizard -adds Revoke.ps1'

Write-Output '--LIVE_DRY_START--'

$global:LiveInputQueue = [System.Collections.Generic.Queue[string]]::new()
@('4','N','N','N') | ForEach-Object { $global:LiveInputQueue.Enqueue($_) }

function global:Read-Host {
    param([Parameter(Position=0)][string]$Prompt,[switch]$AsSecureString)
    if ($AsSecureString) { return (ConvertTo-SecureString 'dummy' -AsPlainText -Force) }
    if ($global:LiveInputQueue.Count -gt 0) { return $global:LiveInputQueue.Dequeue() }
    return ''
}

try {
    & $scriptPath -ErrorAction Stop
    Write-Output 'LIVE_DRY_PATH_RESULT=PASS'
}
catch {
    Write-Output ("LIVE_DRY_PATH_RESULT=FAIL :: {0}" -f $_.Exception.Message)
    if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
        Write-Output ("FAIL_POSITION :: {0}" -f $_.InvocationInfo.PositionMessage)
    }
}
finally {
    Remove-Item function:global:Read-Host -ErrorAction SilentlyContinue
    Remove-Variable LiveInputQueue -Scope Global -ErrorAction SilentlyContinue
}

Write-Output '--LIVE_DRY_END--'
