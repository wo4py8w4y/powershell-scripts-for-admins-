<#
.SYNOPSIS
    Continuous daemon combining real-time mailbox telemetry with historical tracking and a searchable SPA dashboard.
.DESCRIPTION
    1. Extracts real-time Folder, Permission, and Quota data.
    2. Extracts historical Size and ELC deletion data, persisting it to a local JSON file.
    3. Injects payloads into an HTML Single Page Application (SPA).
    4. Webhint-compliant: All inline styles extracted to proper CSS classes.
#>

param (
    [string]$PrefixFilter = "qbuildseq",
    [int]$RefreshIntervalMinutes = 30,
    [int]$MaxHistorySnapshots = 48,
    [int]$MaxRetries = 4
)

# --- Global Initialization ---
$Global:HistoryFile = ".\MailboxMetricsHistory.json"
$Global:DashboardPath = ".\Unified_Mailbox_Dashboard.html"

# --- Telemetry & Logging ---
function Write-AuditLog {
    param([string]$Message, [string]$Status = "Info")
    $Color = switch ($Status) {
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error"   { "Red" }
        "Progress"{ "Magenta" }
        "Cycle"   { "Cyan" }
        Default   { "Gray" }
    }
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] [$($Status.ToUpper())] $Message" -ForegroundColor $Color
}

function Invoke-WithRetry {
    param([scriptblock]$ScriptBlock, [string]$EntityName = "Unknown")
    $Attempt = 0
    do {
        try { return & $ScriptBlock } 
        catch {
            if ($_.Exception.GetType().Name -match "ParameterBindingException|CommandNotFoundException") { throw $_ }
            $Attempt++
            if ($Attempt -ge $MaxRetries) { throw $_ }
            $SleepSeconds = [math]::Pow(2, $Attempt) + (Get-Random -Minimum 1 -Maximum 4)
            Write-AuditLog "API Throttling on $EntityName. Backing off ${SleepSeconds}s..." "Warning"
            Start-Sleep -Seconds $SleepSeconds
        }
    } while ($Attempt -lt $MaxRetries)
}

function Convert-SizeToBytes {
    param([object]$Value)
    if ($null -eq $Value) { return 0 }
    $TextValue = [string]$Value
    if ($TextValue -match '\((?<Bytes>[\d,]+)\s+bytes\)') { return [int64](($matches.Bytes) -replace ',', '') }
    if ($TextValue -match '^\d+$') { return [int64]$TextValue }
    return 0
}

# --- HTML SPA Generator ---
function Build-UnifiedDashboard {
    param (
        [array]$CurrentMailboxes,
        [array]$CurrentFolders,
        [array]$CurrentPerms,
        [array]$HistoryData
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $RefreshSeconds = $RefreshIntervalMinutes * 60
    
    $JsonCurrentMbx  = ConvertTo-Json -InputObject @($CurrentMailboxes) -Depth 5 -Compress
    $JsonCurrentFld  = ConvertTo-Json -InputObject @($CurrentFolders) -Depth 5 -Compress
    $JsonCurrentPerm = ConvertTo-Json -InputObject @($CurrentPerms) -Depth 5 -Compress
    $JsonHistory     = ConvertTo-Json -InputObject @($HistoryData) -Depth 10 -Compress

    $HtmlTemplate = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta http-equiv="refresh" content="$RefreshSeconds" />
<title>Unified Mailbox & ELC Monitor</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
    :root { --bg:#0f1117; --card:#1a1d27; --border:#2a2d3a; --text:#e4e6eb; --muted:#8b8fa3; --accent:#4f8cff; --accent2:#6c5ce7; --green:#27ae60; --red:#e74c3c; --amber:#f39c12; }
    * { box-sizing:border-box; margin:0; padding:0; }
    body { font-family:'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--text); padding:24px; min-height:100vh; }
    
    /* Header & Controls */
    .header-container { display:flex; justify-content:space-between; align-items:flex-end; flex-wrap:wrap; margin-bottom:24px; gap:15px; }
    .header h1 { font-size:1.75rem; font-weight:700; background:linear-gradient(135deg,var(--accent),var(--accent2)); -webkit-background-clip:text; -webkit-text-fill-color:transparent; margin-bottom:5px; }
    .meta { font-size:0.85rem; color:var(--muted); line-height:1.5; }
    
    /* Custom Searchable Dropdown */
    .controls { display:flex; flex-direction:column; align-items:flex-start; width: 100%; max-width: 400px; position: relative;}
    .search-label { font-size:0.85rem; color:var(--muted); margin-bottom:6px; display:block; }
    .custom-select-wrapper { position: relative; width: 100%; }
    #mbxSearch { width: 100%; padding: 10px 14px; background-color: #0d1017; color: var(--text); border: 1px solid var(--border); border-radius: 8px; font-size: 0.95rem; outline: none; transition: border-color 0.2s; }
    #mbxSearch:focus { border-color: var(--accent); box-shadow: 0 0 0 2px rgba(79,140,255,0.15); }
    .custom-options { position: absolute; top: 105%; left: 0; right: 0; background: #0d1017; border: 1px solid var(--border); border-radius: 8px; max-height: 300px; overflow-y: auto; z-index: 1000; display: none; box-shadow: 0 10px 24px rgba(0,0,0,0.5); }
    .custom-option { padding: 10px 14px; cursor: pointer; color: var(--text); border-bottom: 1px solid var(--border); font-size: 0.9rem; }
    .custom-option:last-child { border-bottom: none; }
    .custom-option:hover { background: rgba(79,140,255,0.15); color: var(--accent); }
    .autocomplete-subtext { color: var(--muted); font-size: 0.8rem; display: block; margin-top: 2px; }

    /* Tabs */
    .tabs { display:flex; gap:10px; margin-bottom:20px; border-bottom:1px solid var(--border); padding-bottom:10px; }
    .tab-btn { background:transparent; color:var(--muted); border:none; padding:8px 16px; font-size:1rem; font-weight:600; cursor:pointer; border-radius:6px; transition:all 0.2s; }
    .tab-btn:hover { background:rgba(79,140,255,0.1); color:var(--text); }
    .tab-btn.active { background:rgba(79,140,255,0.15); color:var(--accent); }
    .tab-content { display:none; }
    .tab-content.active { display:block; }

    /* Layout & Cards */
    .kpi-strip { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:16px; margin-bottom:24px; }
    .kpi { background:var(--card); border:1px solid var(--border); border-radius:14px; padding:20px 18px; text-align:center; box-shadow:0 10px 24px rgba(0,0,0,0.18); }
    .kpi .value { font-size:2.2rem; font-weight:700; line-height:1; }
    .kpi .label { font-size:0.85rem; color:var(--muted); margin-top:8px; }
    .kpi.blue .value { color:var(--accent); } .kpi.green .value { color:var(--green); } .kpi.amber .value { color:var(--amber); }
    
    .chart-grid { display:grid; grid-template-columns:2fr 1fr; gap:24px; margin-bottom:24px; }
    .chart-full { grid-column: span 2; }
    @media (max-width:900px) { .chart-grid { grid-template-columns:1fr; } .chart-full { grid-column: span 1; } }

    /* Sections */
    .section { background:var(--card); border:1px solid var(--border); border-radius:16px; padding:22px; margin-bottom:24px; box-shadow:0 12px 28px rgba(0,0,0,0.18); }
    .section-chart { margin-bottom: 0; }
    .section-amber { border-left: 4px solid var(--amber); }
    .section-accent { border-left: 4px solid var(--accent); }
    .section h2 { font-size:1.15rem; font-weight:600; margin-bottom:16px; color:#ffffff; }

    /* Tables */
    .table-wrap { overflow:auto; border-radius:12px; }
    table { width:100%; border-collapse:collapse; font-size:0.85rem; }
    th { text-align:left; padding:11px 12px; background:#0d1017; color:var(--muted); font-weight:600; text-transform:uppercase; border-bottom:2px solid var(--border); }
    td { padding:10px 12px; border-bottom:1px solid var(--border); }
    tr:hover { background:rgba(79,140,255,0.06); }
    
    /* Utilities */
    .badge { display:inline-block; padding:3px 10px; border-radius:999px; font-size:0.75rem; font-weight:700; }
    .badge-blue { background:rgba(79,140,255,0.15); color:var(--accent); }
    .badge-amber { background:rgba(243,156,18,0.15); color:var(--amber); }
    .badge-red { background:rgba(231,76,60,0.18); color:var(--red); }
    
    .chart-container { position:relative; height:300px; width:100%; }
    .chart-compact { height: 250px; }
    .text-center { text-align: center; }
    .text-green { color: var(--green); }
</style>
</head>
<body>

<div class="header-container">
    <div class="header">
        <h1>&#128187; Unified Mailbox Dashboard</h1>
        <div class="meta">
            <div>Last Sync: <strong>$Timestamp</strong></div>
            <div>Auto-Refresh: <strong>Every $RefreshIntervalMinutes Minutes</strong></div>
        </div>
    </div>
    <div class="controls">
        <label for="mbxSearch" class="search-label">Search & Filter Target:</label>
        <div class="custom-select-wrapper">
            <input type="text" id="mbxSearch" placeholder="Type to search mailboxes..." autocomplete="off">
            <div id="mbxDropdown" class="custom-options"></div>
        </div>
    </div>
</div>

<div class="tabs">
    <button class="tab-btn active" onclick="switchTab('tab-dash', this)">&#128202; Trends & Quotas</button>
    <button class="tab-btn" onclick="switchTab('tab-mailboxes', this)">&#128421;&#65039; Core Statistics</button>
    <button class="tab-btn" onclick="switchTab('tab-folders', this)">&#128465;&#65039; Folder Diagnostics</button>
    <button class="tab-btn" onclick="switchTab('tab-perms', this)">&#128101; Access Control</button>
</div>

<div id="tab-dash" class="tab-content active">
    <div class="kpi-strip">
        <div class="kpi blue"><div class="value" id="kpi-count">0</div><div class="label">Mailboxes in View</div></div>
        <div class="kpi green"><div class="value" id="kpi-used">0 GB</div><div class="label">Aggregate Storage Used</div></div>
        <div class="kpi amber"><div class="value" id="kpi-recov">0 GB</div><div class="label">Total Recoverable Items</div></div>
    </div>

    <div class="chart-grid">
        <div class="section section-chart">
            <h2>Longitudinal Size Growth (MB)</h2>
            <div class="chart-container"><canvas id="sizeLineChart"></canvas></div>
        </div>
        <div class="section section-chart">
            <h2>Current Quota Availability (GB)</h2>
            <div class="chart-container"><canvas id="quotaPieChart"></canvas></div>
        </div>
        <div class="section chart-full section-chart">
            <h2>ELC Processing History (Items Deleted)</h2>
            <div class="chart-container chart-compact"><canvas id="elcBarChart"></canvas></div>
        </div>
    </div>
</div>

<div id="tab-mailboxes" class="tab-content">
    <div class="section">
        <h2>Core Mailbox Statistics</h2>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Display Name</th><th>User Principal Name</th><th>Total Items</th><th>Total Size</th></tr></thead>
                <tbody id="tbl-mailboxes"></tbody>
            </table>
        </div>
    </div>
</div>

<div id="tab-folders" class="tab-content">
    <div class="section section-amber">
        <h2>High-Impact Folder Diagnostics</h2>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Mailbox</th><th>Folder Name</th><th>Folder Type</th><th>Item Count</th><th>Folder Size</th></tr></thead>
                <tbody id="tbl-folders"></tbody>
            </table>
        </div>
    </div>
</div>

<div id="tab-perms" class="tab-content">
    <div class="section section-accent">
        <h2>Delegate Access Control List</h2>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Mailbox</th><th>Delegate Entity</th><th>Access Rights</th></tr></thead>
                <tbody id="tbl-perms"></tbody>
            </table>
        </div>
    </div>
</div>

<script>
    // Injected JSON Payloads
    const curMailboxes = $JsonCurrentMbx;
    const curFolders = $JsonCurrentFld;
    const curPerms = $JsonCurrentPerm;
    const historyData = $JsonHistory;

    // Chart instances
    let sizeLineChart = null;
    let quotaPieChart = null;
    let elcBarChart = null;

    function switchTab(tabId, btn) {
        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.getElementById(tabId).classList.add('active');
        btn.classList.add('active');
    }

    function initAutocomplete() {
        const input = document.getElementById('mbxSearch');
        const dropdown = document.getElementById('mbxDropdown');

        if (!Array.isArray(curMailboxes) || curMailboxes.length === 0) return;

        let optionsHTML = `<div class="custom-option" onclick="selectOption('ALL', '-- Show All Mailboxes --')"><strong>-- Show All Mailboxes --</strong></div>`;
        curMailboxes.forEach(m => {
            optionsHTML += `<div class="custom-option" onclick="selectOption('\${m.UPN}', '\${m.DisplayName} (\${m.UPN})')">\${m.DisplayName} <span class="autocomplete-subtext">\${m.UPN}</span></div>`;
        });
        dropdown.innerHTML = optionsHTML;

        input.addEventListener('focus', () => dropdown.style.display = 'block');
        input.addEventListener('input', () => {
            dropdown.style.display = 'block';
            const filterText = input.value.toLowerCase();
            const options = dropdown.getElementsByClassName('custom-option');
            
            for (let i = 1; i < options.length; i++) {
                const txt = options[i].textContent.toLowerCase();
                options[i].style.display = txt.includes(filterText) ? '' : 'none';
            }
        });

        document.addEventListener('click', (e) => {
            if (!input.contains(e.target) && !dropdown.contains(e.target)) {
                dropdown.style.display = 'none';
            }
        });
    }

    function selectOption(upn, text) {
        document.getElementById('mbxSearch').value = text;
        document.getElementById('mbxDropdown').style.display = 'none';
        localStorage.setItem('activeMbxFilter', upn);
        applyFilter(upn);
    }

    function init() {
        initAutocomplete();
        const savedMbx = localStorage.getItem('activeMbxFilter') || 'ALL';
        let savedText = '-- Show All Mailboxes --';
        
        if (savedMbx !== 'ALL') {
            let match = curMailboxes.find(m => m.UPN === savedMbx);
            if(match) {
                savedText = `\${match.DisplayName} (\${match.UPN})`;
            } else {
                localStorage.setItem('activeMbxFilter', 'ALL');
            }
        }

        document.getElementById('mbxSearch').value = savedText;
        applyFilter(savedMbx);
    }

    function applyFilter(filterUPN) {
        const fMailboxes = filterUPN === 'ALL' ? curMailboxes : curMailboxes.filter(m => m.UPN === filterUPN);
        const fFolders = filterUPN === 'ALL' ? curFolders : curFolders.filter(f => f.UPN === filterUPN);
        const fPerms = filterUPN === 'ALL' ? curPerms : curPerms.filter(p => p.UPN === filterUPN);

        document.getElementById('kpi-count').innerText = fMailboxes.length;
        let sumUsed = fMailboxes.reduce((acc, curr) => acc + curr.TotalBytes, 0);
        document.getElementById('kpi-used').innerText = (sumUsed / 1073741824).toFixed(2) + ' GB';
        let sumRecov = fFolders.filter(f => f.FolderType === 'RecoverableItems').reduce((acc, curr) => acc + curr.SizeBytes, 0);
        document.getElementById('kpi-recov').innerText = (sumRecov / 1073741824).toFixed(2) + ' GB';

        const mbxBody = document.getElementById('tbl-mailboxes'); mbxBody.innerHTML = '';
        fMailboxes.forEach(m => {
            let uMB = (m.TotalBytes / 1048576).toFixed(2);
            mbxBody.innerHTML += `<tr><td>\${m.DisplayName}</td><td>\${m.UPN}</td><td>\${m.ItemCount}</td><td><span class='badge badge-blue'>\${uMB} MB</span></td></tr>`;
        });

        const fldBody = document.getElementById('tbl-folders'); fldBody.innerHTML = '';
        if(fFolders.length === 0) fldBody.innerHTML = "<tr><td colspan='5' class='text-center'>No high-impact folders found.</td></tr>";
        fFolders.forEach(f => {
            let sMB = (f.SizeBytes / 1048576).toFixed(2);
            let bClass = f.FolderType === 'RecoverableItems' ? 'badge-amber' : 'badge-red';
            fldBody.innerHTML += `<tr><td>\${f.DisplayName}</td><td>\${f.FolderName}</td><td><span class='badge \${bClass}'>\${f.FolderType}</span></td><td>\${f.ItemCount}</td><td>\${sMB} MB</td></tr>`;
        });

        const permBody = document.getElementById('tbl-perms'); permBody.innerHTML = '';
        if(fPerms.length === 0) permBody.innerHTML = "<tr><td colspan='3' class='text-center text-green'>&#9989; No explicit delegates.</td></tr>";
        fPerms.forEach(p => {
            permBody.innerHTML += `<tr><td>\${p.DisplayName}</td><td>\${p.Delegate}</td><td><span class='badge badge-amber'>\${p.Rights}</span></td></tr>`;
        });

        renderCharts(filterUPN, fMailboxes);
    }

    function renderCharts(filterUPN, filteredMbxArray) {
        const timeLabels = [];
        const histSizeData = [];
        const histElcData = [];

        if (Array.isArray(historyData)) {
            historyData.forEach(snap => {
                timeLabels.push(snap.Timestamp);
                
                if (filterUPN === 'ALL') {
                    let totalBytes = snap.Mailboxes.reduce((sum, m) => sum + m.TotalBytes, 0);
                    let totalELC = snap.Mailboxes.reduce((sum, m) => sum + m.ELCDeletedItems, 0);
                    histSizeData.push((totalBytes / 1048576).toFixed(2));
                    histElcData.push(totalELC);
                } else {
                    let target = snap.Mailboxes.find(m => m.UPN === filterUPN);
                    histSizeData.push(target ? (target.TotalBytes / 1048576).toFixed(2) : 0);
                    histElcData.push(target ? target.ELCDeletedItems : 0);
                }
            });
        }

        if (sizeLineChart) sizeLineChart.destroy();
        sizeLineChart = new Chart(document.getElementById('sizeLineChart').getContext('2d'), {
            type: 'line',
            data: {
                labels: timeLabels,
                datasets: [{ label: 'Mailbox Size (MB)', data: histSizeData, borderColor: '#4f8cff', backgroundColor: 'rgba(79, 140, 255, 0.2)', fill: true, tension: 0.3 }]
            },
            options: { responsive: true, maintainAspectRatio: false, scales: { y: { grid: { color: '#2a2d3a' }, ticks: { color: '#8b8fa3' } }, x: { grid: { display: false }, ticks: { color: '#8b8fa3' } } }, plugins: { legend: { labels: { color: '#e4e6eb' } } } }
        });

        if (elcBarChart) elcBarChart.destroy();
        elcBarChart = new Chart(document.getElementById('elcBarChart').getContext('2d'), {
            type: 'bar',
            data: {
                labels: timeLabels,
                datasets: [{ label: 'ELC Deleted Items', data: histElcData, backgroundColor: '#e74c3c' }]
            },
            options: { responsive: true, maintainAspectRatio: false, scales: { y: { grid: { color: '#2a2d3a' }, ticks: { color: '#8b8fa3' } }, x: { grid: { display: false }, ticks: { color: '#8b8fa3' } } }, plugins: { legend: { labels: { color: '#e4e6eb' } } } }
        });

        let sumUsed = filteredMbxArray.reduce((sum, m) => sum + m.TotalBytes, 0);
        let sumQuota = filteredMbxArray.reduce((sum, m) => sum + m.QuotaBytes, 0);
        let sumFree = sumQuota > sumUsed ? sumQuota - sumUsed : 0;

        if (quotaPieChart) quotaPieChart.destroy();
        quotaPieChart = new Chart(document.getElementById('quotaPieChart').getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: ['Used (GB)', 'Available Space (GB)'],
                datasets: [{
                    data: [(sumUsed / 1073741824).toFixed(2), (sumFree / 1073741824).toFixed(2)],
                    backgroundColor: ['rgba(79, 140, 255, 0.8)', 'rgba(42, 45, 58, 0.8)'],
                    borderColor: ['#1a1d27', '#1a1d27'], borderWidth: 2
                }]
            },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { color: '#e4e6eb' } } } }
        });
    }

    window.onload = init;
</script>
</body>
</html>
"@

    Set-Content -Path $Global:DashboardPath -Value $HtmlTemplate -Encoding UTF8
    Write-AuditLog "Unified Dashboard generated successfully." "Success"
}

# --- Main Execution Engine ---
Clear-Host
Write-AuditLog "Starting Unified Exchange Daemon..." "Cycle"

$BrowserOpened = $false

while ($true) {
    $HistoryArray = @()
    if (Test-Path $Global:HistoryFile) {
        try {
            $HistoryContent = Get-Content $Global:HistoryFile -Raw
            if (-not [string]::IsNullOrWhiteSpace($HistoryContent)) {
                $ParsedHistory = $HistoryContent | ConvertFrom-Json
                if ($ParsedHistory) { $HistoryArray = @($ParsedHistory) }
            }
        } catch { Write-AuditLog "Failed to parse history JSON. Starting fresh." "Warning" }
    }

    Write-AuditLog "Querying Exchange Online for targets..." "Progress"
    $Mailboxes = Invoke-WithRetry -EntityName "Discovery" -ScriptBlock {
        Get-EXOMailbox -ResultSize Unlimited -Properties DisplayName, UserPrincipalName, ProhibitSendQuota, EmailAddresses -ErrorAction Stop | 
        Where-Object { $_.EmailAddresses -match "^smtp:$PrefixFilter" -or $_.EmailAddresses -match "^SMTP:$PrefixFilter" }
    }

    if ($Mailboxes.Count -eq 0) {
        Write-AuditLog "No mailboxes found matching '$PrefixFilter'." "Warning"
        Start-Sleep -Seconds ($RefreshIntervalMinutes * 60)
        continue
    }

    $ColMailboxData = @(); $ColFolderData = @(); $ColPermData = @(); $HistorySnapData = @()
    $Index = 0

    foreach ($MB in $Mailboxes) {
        $Index++
        Write-Progress -Activity "Polling Telemetry" -Status "($Index/$($Mailboxes.Count)): $($MB.DisplayName)" -PercentComplete (($Index / $Mailboxes.Count) * 100)
        
        $Stats = Invoke-WithRetry -EntityName "Stats-$($MB.UserPrincipalName)" -ScriptBlock { Get-EXOMailboxStatistics -Identity $MB.UserPrincipalName -Properties ItemCount, TotalItemSize -ErrorAction Stop }
        $TotalBytes = Convert-SizeToBytes -Value $Stats.TotalItemSize
        
        $ColMailboxData += [PSCustomObject]@{
            DisplayName = $MB.DisplayName; UPN = $MB.UserPrincipalName; ItemCount = $Stats.ItemCount
            TotalBytes = $TotalBytes; QuotaBytes = Convert-SizeToBytes -Value $MB.ProhibitSendQuota
        }

        $Folders = Invoke-WithRetry -EntityName "Folders-$($MB.UserPrincipalName)" -ScriptBlock { 
            Get-EXOMailboxFolderStatistics -Identity $MB.UserPrincipalName -FolderScope RecoverableItems -ErrorAction SilentlyContinue
            Get-EXOMailboxFolderStatistics -Identity $MB.UserPrincipalName -FolderScope DeletedItems -ErrorAction SilentlyContinue
        }
        foreach ($F in $Folders) {
            if ($F.FolderType -in @('RecoverableItems', 'DeletedItems')) {
                $ColFolderData += [PSCustomObject]@{
                    DisplayName = $MB.DisplayName; UPN = $MB.UserPrincipalName; FolderName = $F.Name
                    FolderType = $F.FolderType; ItemCount = $F.ItemsInFolder; SizeBytes = Convert-SizeToBytes -Value $F.FolderSize
                }
            }
        }

        $Perms = Invoke-WithRetry -EntityName "Perms-$($MB.UserPrincipalName)" -ScriptBlock { Get-EXOMailboxPermission -Identity $MB.UserPrincipalName -ErrorAction Stop }
        foreach ($P in $Perms) {
            if ($P.User -notmatch "NT AUTHORITY|S-1-5-21|System" -and $P.IsInherited -eq $false) {
                $ColPermData += [PSCustomObject]@{ DisplayName = $MB.DisplayName; UPN = $MB.UserPrincipalName; Delegate = $P.User; Rights = ($P.AccessRights -join ", ") }
            }
        }

        $ELCDeleted = 0
        try {
            $LogProps = Invoke-WithRetry -EntityName "ELC-$($MB.UserPrincipalName)" -ScriptBlock { Export-MailboxDiagnosticLogs -Identity $MB.UserPrincipalName -ExtendedProperties -ErrorAction Stop }
            if ($LogProps.MailboxLog) {
                $Xml = [xml]$LogProps.MailboxLog
                $DumpsterProp = $Xml.Properties.MailboxTable.Property | Where-Object { $_.Name -eq "ElcLastRunDeletedFromDumpsterItemCount" }
                $RootProp = $Xml.Properties.MailboxTable.Property | Where-Object { $_.Name -eq "ElcLastRunDeletedFromRootItemCount" }
                $ELCDeleted = [int]($DumpsterProp.Value) + [int]($RootProp.Value)
            }
        } catch { }

        $HistorySnapData += [PSCustomObject]@{ UPN = $MB.UserPrincipalName; TotalBytes = $TotalBytes; ELCDeletedItems = $ELCDeleted }
    }
    Write-Progress -Activity "Polling Telemetry" -Completed

    $HistoryArray += [PSCustomObject]@{ Timestamp = (Get-Date -Format "HH:mm"); Mailboxes = $HistorySnapData }
    if ($HistoryArray.Count -gt $MaxHistorySnapshots) { $HistoryArray = $HistoryArray[($HistoryArray.Count - $MaxHistorySnapshots)..($HistoryArray.Count - 1)] }
    
    ConvertTo-Json -InputObject @($HistoryArray) -Depth 10 -Compress | Set-Content -Path $Global:HistoryFile -Encoding UTF8

    Build-UnifiedDashboard -CurrentMailboxes $ColMailboxData -CurrentFolders $ColFolderData -CurrentPerms $ColPermData -HistoryData $HistoryArray

    if (-not $BrowserOpened) { Invoke-Item $Global:DashboardPath; $BrowserOpened = $true }

    Write-AuditLog "Cycle complete. Standby for $RefreshIntervalMinutes minutes..." "Cycle"
    for ($m = $RefreshIntervalMinutes; $m -gt 0; $m--) {
        for ($s = 59; $s -ge 0; $s--) {
            Write-Progress -Activity "Daemon Standby" -Status "Next cycle in -> ${m}m ${s}s [Ctrl+C to Stop]" -PercentComplete ((($RefreshIntervalMinutes - $m) / $RefreshIntervalMinutes) * 100)
            Start-Sleep -Seconds 1
        }
    }
}