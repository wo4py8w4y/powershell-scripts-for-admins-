<#
.SYNOPSIS
    Generates a continuous, high-performance visual terminal stream using random arrays and structured patterns.
.DESCRIPTION
    1. Interactively prompts for render type, refresh frames, and character metrics.
    2. Uses native low-level .NET Console methods to bypass slow Write-Host pipelines.
    3. Employs extended CP437 block rendering characters.
    4. Loops infinitely until terminated manually via Ctrl+C.
.NOTES
    Architecture: High-Performance Canvas, Fully Decoupled, Interactive Parameters.
    Location: Brisbane, QLD
#>

# --- UI Configuration Module ---

function Get-RenderConfiguration {
    <# Generates a clean UI setup matrix to gather execution variables without code modification #>
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $Form = New-Object Windows.Forms.Form
    $Form.Text = "Terminal Engine Configuration"
    $Form.Size = New-Object Drawing.Size(400, 320)
    $Form.StartPosition = "CenterScreen"
    $Form.FormBorderStyle = "FixedDialog"
    $Form.MaximizeBox = $false

    # Render Type Selector
    $LblMode = New-Object Windows.Forms.Label
    $LblMode.Text = "Execution Pattern Mode:"; $LblMode.Location = "20,20"; $LblMode.Width = 150; $Form.Controls.Add($LblMode)

    $CboMode = New-Object Windows.Forms.ComboBox
    $CboMode.Location = "20,40"; $CboMode.Width = 340
    [void]$CboMode.Items.Add("Hybrid Matrix (Random & Geometric Patterns)")
    [void]$CboMode.Items.Add("Geometric Grid Waves Only")
    [void]$CboMode.Items.Add("Pure Chaos Matrix (Random Placement)")
    $CboMode.SelectedIndex = 0; $Form.Controls.Add($CboMode)

    # Frame Delay Tracking
    $LblDelay = New-Object Windows.Forms.Label
    $LblDelay.Text = "Frame Refresh Delay (Milliseconds):"; $LblDelay.Location = "20,80"; $LblDelay.Width = 220; $Form.Controls.Add($LblDelay)

    $NumDelay = New-Object Windows.Forms.NumericUpDown
    $NumDelay.Location = "20,100"; $NumDelay.Width = 100; $NumDelay.Minimum = 1; $NumDelay.Maximum = 500; $NumDelay.Value = 30
    $Form.Controls.Add($NumDelay)

    # Stream Density Threshold
    $LblDensity = New-Object Windows.Forms.Label
    $LblDensity.Text = "Render Stream Density (1 - 50 Objects per Frame):"; $LblDensity.Location = "20,140"; $LblDensity.Width = 280; $Form.Controls.Add($LblDensity)

    $NumDensity = New-Object Windows.Forms.NumericUpDown
    $NumDensity.Location = "20,160"; $NumDensity.Width = 100; $NumDensity.Minimum = 1; $NumDensity.Maximum = 50; $NumDensity.Value = 15
    $Form.Controls.Add($NumDensity)

    # Action Trigger
    $BtnLaunch = New-Object Windows.Forms.Button
    $BtnLaunch.Text = "Initialize Continuous Canvas"; $BtnLaunch.Location = "20,210"; $BtnLaunch.Width = 340; $BtnLaunch.Height = 40
    $BtnLaunch.DialogResult = [Windows.Forms.DialogResult]::OK
    $Form.Controls.Add($BtnLaunch)

    if ($Form.ShowDialog() -eq [Windows.Forms.DialogResult]::OK) {
        return [PSCustomObject]@{
            Mode    = $CboMode.SelectedIndex
            Delay   = [int]$NumDelay.Value
            Density = [int]$NumDensity.Value
        }
    }
    return $null
}

# --- Core Graphical Engine ---

function Invoke-TerminalMatrix {
    $Config = Get-RenderConfiguration
    if ($null -eq $Config) {
        Write-Host "[INFO] Operation aborted by user." -ForegroundColor Yellow
        return
    }

    # Extended Character Arrays (CP437 Block Elements and Geometric Symbols)
    $ExtendedChars = @(
        [char]0x2588, # █ Full Block
        [char]0x2584, # ▄ Lower Half Block
        [char]0x2580, # ▀ Upper Half Block
        [char]0x2591, # ░ Light Shade
        [char]0x2592, # ▒ Medium Shade
        [char]0x2593, # ▓ Dark Shade
        [char]0x25C4, # ◄ Left Pointer
        [char]0x25BA, # ► Right Pointer
        [char]0x25B2, # ▲ Up Pointer
        [char]0x25BC, # ▼ Down Pointer
        [char]0x25C6, # ◆ Filled Diamond
        [char]0x25CE, # ◎ Bullseye
        [char]0x25A3  # ▣ White Square Containing Small Black Square
    )

    # Console Color Array (Excluding Black to maintain visibility against background)
    $Colors = @(
        [ConsoleColor]::Cyan,
        [ConsoleColor]::DarkCyan,
        [ConsoleColor]::Green,
        [ConsoleColor]::DarkGreen,
        [ConsoleColor]::Magenta,
        [ConsoleColor]::DarkMagenta,
        [ConsoleColor]::Yellow,
        [ConsoleColor]::Blue,
        [ConsoleColor]::Red
    )

    # Prepare Console Interface Screen Space
    [Console]::Clear()
    [Console]::CursorVisible = $false
    
    $StepTracker = 0

    try {
        # Infinite Loop Control Layer (Keeps the screen active indefinitely)
        while ($true) {
            $Width  = [Console]::WindowWidth
            $Height = [Console]::WindowHeight
            
            # Recalculate parameters in case window size adjusts mid-execution
            if ($Width -lt 10) { $Width = 80 }
            if ($Height -lt 10) { $Height = 25 }

            $StepTracker++

            # --- Pattern Pass Layer ---
            if ($Config.Mode -eq 0 -or $Config.Mode -eq 1) {
                # Generates moving wave equations/patterns mapped dynamically to coordinates
                for ($x = 0; $x -lt $Width; $x += 4) {
                    # Mathematical sine ripple mapping coordinates out of frame cycles
                    $TargetY = [int](($Height / 2) + (($Height / 3) * [math]::Sin(($x + $StepTracker) / 8)))
                    
                    if ($TargetY -ge 0 -and $TargetY -lt $Height -and $x -lt $Width) {
                        [Console]::SetCursorPosition($x, $TargetY)
                        [Console]::ForegroundColor = $Colors[$StepTracker % $Colors.Count]
                        [Console]::Write($ExtendedChars[$StepTracker % 6]) # Renders block shades
                    }
                }
            }

            # --- Random / Chaos Matrix Pass Layer ---
            if ($Config.Mode -eq 0 -or $Config.Mode -eq 2) {
                for ($i = 0; $i -lt $Config.Density; $i++) {
                    # Establish secure random coordinate mapping
                    $RandX = Get-Random -Minimum 0 -Maximum $Width
                    $RandY = Get-Random -Minimum 0 -Maximum $Height
                    
                    # Prevent clipping edge-case faults
                    if ($RandX -ge $Width) { $RandX = $Width - 1 }
                    if ($RandY -ge $Height) { $RandY = $Height - 1 }

                    $RandChar  = $ExtendedChars[(Get-Random -Minimum 0 -Maximum $ExtendedChars.Count)]
                    $RandColor = $Colors[(Get-Random -Minimum 0 -Maximum $Colors.Count)]

                    # Low-level pointer placement avoids the memory/string bloating of Write-Host pipelines
                    [Console]::SetCursorPosition($RandX, $RandY)
                    [Console]::ForegroundColor = $RandColor
                    [Console]::Write($RandChar)
                }
            }

            # Occasional line clear sweep to prevent absolute structural stagnation
            if ($StepTracker % 150 -eq 0) {
                $SweepY = Get-Random -Minimum 0 -Maximum $Height
                [Console]::SetCursorPosition(0, $SweepY)
                [Console]::Write((" " * $Width))
            }

            # Performance throttle to control CPU thread capacity utilization
            Start-Sleep -Milliseconds $Config.Delay
        }
    }
    catch [System.Management.Automation.PipelineStoppedException] {
        # Catch standard break commands cleanly
    }
    finally {
        # Graceful cleanup structure restoration
        [Console]::ResetColor()
        [Console]::Clear()
        [Console]::CursorVisible = $true
        Write-Host "[SUCCESS] Terminal UI engine safely unmounted." -ForegroundColor Green
    }
}

# --- Launch Entry Point ---
Invoke-TerminalMatrix