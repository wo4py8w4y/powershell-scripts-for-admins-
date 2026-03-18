<#
.SYNOPSIS
    Measures and tracks mouse movement distance with GUI and CLI support, converts to multiple units.

.DESCRIPTION
    Monitors mouse cursor position changes, calculates total distance traveled in pixels/cm/meters,
    and saves metrics to a configuration file. Supports continuous tracking or GUI mode.

.PARAMETER DurationSeconds
    How long to track (seconds). If 0, runs continuously until stopped (default: 0 = continuous)

.PARAMETER OutputPath
    Path to save the INI file (default: current directory)

.PARAMETER FileName
    Name of the INI file (default: mouse-tracker.cfg)

.PARAMETER GUI
    Display a GUI window for real-time tracking and control

.PARAMETER DPI
    Screen DPI for pixel-to-distance conversion (default: auto-detect)

.EXAMPLE
    .\MouseDistanceTracker.ps1 -GUI

.EXAMPLE
    .\MouseDistanceTracker.ps1 -DurationSeconds 60 -OutputPath "C:\Reports"

.EXAMPLE
    .\MouseDistanceTracker.ps1 -GUI -DPI 96
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$DurationSeconds = 0,

    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = 'C:\Users\aaron.francis\OneDrive - Departments of CHDE and EPW\pwshScripts\Utilities\mouse-tracker.cfg.txt',

    [Parameter(Mandatory = $false)]
    [switch]$GUI = $true,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = $PSScriptRoot,

    [Parameter(Mandatory = $false)]
    [string]$FileName = 'mouse-tracker.cfg',

    [Parameter(Mandatory = $false)]
    [int]$DPI = 0
)

# Add Windows API calls for mouse position
Add-Type @'
using System;
using System.Runtime.InteropServices;

public class MouseTracker {
    [DllImport("user32.dll")]
    public static extern bool GetCursorPos(out POINT lpPoint);

    [StructLayout(LayoutKind.Sequential)]
    public struct POINT {
        public int X;
        public int Y;
    }

    public static POINT GetMousePosition() {
        POINT pt;
        GetCursorPos(out pt);
        return pt;
    }
}
'@

# Display message about DPI calibration
Write-Host '═══════════════════════════════════════════' -ForegroundColor Cyan
Write-Host 'Mouse Distance Tracker' -ForegroundColor Cyan
Write-Host '═══════════════════════════════════════════' -ForegroundColor Cyan
Write-Host ''
Write-Host 'For accurate distance measurements, visit:' -ForegroundColor Yellow
Write-Host 'https://dpi.lv/' -ForegroundColor Green -NoNewline
Write-Host ' to get your real monitor DPI' -ForegroundColor Yellow
Write-Host ''

# Get DPI setting from system if not specified
if ($DPI -eq 0)
{
    try
    {
        $dpiValue = Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'LogPixels' -ErrorAction SilentlyContinue
        $DPI = if ($dpiValue) { $dpiValue.LogPixels } else { 96 }
    }
    catch
    {
        $DPI = 96  # Default Windows DPI
    }
}

# Configuration file functions
function Get-TrackerConfig
{
    param([string]$ConfigPath)
    
    $config = @{
        TotalDistance = 0
        DPI           = $DPI
    }
    
    if (Test-Path $ConfigPath)
    {
        $content = Get-Content $ConfigPath -Raw
        if ($content -match 'TotalDistancePixels=([\d.]+)')
        {
            $config.TotalDistance = [double]$matches[1]
        }
        if ($content -match 'CurrentDPI=([\d]+)')
        {
            $config.DPI = [int]$matches[1]
        }
    }
    
    return $config
}

function Set-TrackerConfig
{
    param(
        [string]$ConfigPath,
        [double]$TotalDistance,
        [int]$DPI
    )
    
    $configContent = @"
; Mouse Distance Tracker Configuration
; Last Updated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

[CONFIG]
TotalDistancePixels=$TotalDistance
CurrentDPI=$DPI
"@
    
    $configContent | Out-File -FilePath $ConfigPath -Encoding UTF8 -Force
}

# Load configuration
$loadedConfig = Get-TrackerConfig -ConfigPath $ConfigPath
if ($DPI -eq 0) { $DPI = $loadedConfig.DPI }

# Calculate conversion factors (1 inch = 2.54 cm) - use script scope for GUI updates
$script:pixelsPerInch = $DPI
$script:pixelsPerCm = $script:pixelsPerInch / 2.54
$script:pixelsPerMeter = $script:pixelsPerCm * 100

# Function to format distance in multiple units
function script:Format-Distance
{
    param([double]$Pixels)
    $cm = $Pixels / $script:pixelsPerCm
    $m = $cm / 100
    $inches = $Pixels / $script:pixelsPerInch
    
    return @{
        Pixels      = [Math]::Round($Pixels, 2)
        Centimeters = [Math]::Round($cm, 2)
        Meters      = [Math]::Round($m, 4)
        Inches      = [Math]::Round($inches, 2)
    }
}

# Create output directory if it doesn't exist
if (-not (Test-Path $OutputPath))
{
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$iniPath = Join-Path $OutputPath $FileName

# GUI Mode
if ($GUI)
{
    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName PresentationCore

    $xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="Mouse Distance Tracker" Width="650" Height="550"
    Background="#f0f0f0" Foreground="#333333"
    WindowStartupLocation="CenterScreen" ResizeMode="CanResize">
    <Window.Resources>
        <Style x:Key="ColoredButton" TargetType="Button">
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" 
                                CornerRadius="3" Padding="{TemplateBinding Padding}"
                                BorderThickness="1">
                            <Border.BorderBrush>
                                <SolidColorBrush Color="{Binding Background.Color, RelativeSource={RelativeSource TemplatedParent}}"/>
                            </Border.BorderBrush>
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Background" Value="Transparent"/>
                                <Setter Property="Foreground" Value="{Binding Tag, RelativeSource={RelativeSource Self}}"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>
    <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
        <Grid>
            <StackPanel Margin="20">
            <TextBlock Text="Mouse Distance Tracker" FontSize="24" FontWeight="Bold" 
                       Foreground="#667eea" Margin="0,0,0,20"/>
            
            <Border Background="White" BorderBrush="#ddd" BorderThickness="1" 
                    Padding="15" Margin="0,0,0,15" CornerRadius="5">
                <StackPanel>
                    <TextBlock Text="Real-time Statistics" FontSize="14" FontWeight="Bold" 
                               Margin="0,0,0,10"/>
                    
                    <Grid Margin="0,0,0,10">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        <StackPanel Grid.Column="0" Margin="0,0,10,0">
                            <TextBlock Text="Pixels" FontSize="11" Foreground="#999"/>
                            <TextBlock Name="TotalDistance" Text="0.00" FontSize="16" 
                                       FontWeight="Bold" Foreground="#667eea"/>
                        </StackPanel>
                        <StackPanel Grid.Column="1" Margin="0,0,10,0">
                            <TextBlock Text="Centimeters" FontSize="11" Foreground="#999"/>
                            <TextBlock Name="CentimeterValue" Text="0.00" FontSize="16" 
                                       FontWeight="Bold" Foreground="#764ba2"/>
                        </StackPanel>
                        <StackPanel Grid.Column="2">
                            <TextBlock Text="Meters" FontSize="11" Foreground="#999"/>
                            <TextBlock Name="MeterValue" Text="0.0000" FontSize="16" 
                                       FontWeight="Bold" Foreground="#764ba2"/>
                        </StackPanel>
                    </Grid>

                    <Grid>
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        <StackPanel Grid.Column="0" Margin="0,0,10,0">
                            <TextBlock Text="Total Samples" FontSize="11" Foreground="#999"/>
                            <TextBlock Name="SampleCount" Text="0" FontSize="14" 
                                       FontWeight="Bold" Foreground="#667eea"/>
                        </StackPanel>
                        <StackPanel Grid.Column="1">
                            <TextBlock Text="Elapsed Time" FontSize="11" Foreground="#999"/>
                            <TextBlock Name="ElapsedTime" Text="00:00:00" FontSize="14" 
                                       FontWeight="Bold" Foreground="#667eea"/>
                        </StackPanel>
                    </Grid>
                </StackPanel>
            </Border>

            <Border Background="White" BorderBrush="#ddd" BorderThickness="1" 
                    Padding="15" Margin="0,0,0,15" CornerRadius="5">
                <StackPanel>
                    <TextBlock Text="Performance Metrics" FontSize="14" FontWeight="Bold" 
                               Margin="0,0,0,10"/>
                    
                    <Grid Margin="0,0,0,8">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        <StackPanel Grid.Column="0" Margin="0,0,10,0">
                            <TextBlock Text="Average/Sample" FontSize="11" Foreground="#999"/>
                            <TextBlock Name="AverageDistance" Text="0.00 px" FontSize="12"/>
                        </StackPanel>
                        <StackPanel Grid.Column="1">
                            <TextBlock Text="Max/Sample" FontSize="11" Foreground="#999"/>
                            <TextBlock Name="MaxDistance" Text="0.00 px" FontSize="12"/>
                        </StackPanel>
                    </Grid>

                    <Grid Margin="0,0,0,8">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        <StackPanel Grid.Column="0" Margin="0,0,10,0">
                            <TextBlock Text="Min/Sample" FontSize="11" Foreground="#999"/>
                            <TextBlock Name="MinDistance" Text="0.00 px" FontSize="12"/>
                        </StackPanel>
                        <StackPanel Grid.Column="1">
                            <TextBlock Text="Pixels/Second" FontSize="11" Foreground="#999"/>
                            <TextBlock Name="PixelsPerSecond" Text="0.00" FontSize="12"/>
                        </StackPanel>
                    </Grid>

                    <Grid>
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        <StackPanel Grid.Column="0" Margin="0,0,10,0">
                            <TextBlock Text="CM/Second" FontSize="11" Foreground="#999"/>
                            <TextBlock Name="CmPerSecond" Text="0.00" FontSize="12"/>
                        </StackPanel>
                        <StackPanel Grid.Column="1">
                            <TextBlock Text="Meters/Second" FontSize="11" Foreground="#999"/>
                            <TextBlock Name="MPerSecond" Text="0.0000" FontSize="12"/>
                        </StackPanel>
                    </Grid>
                </StackPanel>
            </Border>

            <Border Background="White" BorderBrush="#ddd" BorderThickness="1" 
                    Padding="15" Margin="0,0,0,15" CornerRadius="5">
                <StackPanel>
                    <TextBlock Text="Lap Times" FontSize="14" FontWeight="Bold" 
                               Margin="0,0,0,10"/>
                    <ScrollViewer MaxHeight="150" VerticalScrollBarVisibility="Auto">
                        <TextBlock Name="LapList" Text="No laps recorded" FontSize="11" 
                                   Foreground="#666" TextWrapping="Wrap"/>
                    </ScrollViewer>
                </StackPanel>
            </Border>

            <Border Background="White" BorderBrush="#ddd" BorderThickness="1" 
                    Padding="15" Margin="0,0,0,15" CornerRadius="5">
                <StackPanel>
                    <TextBlock Text="DPI Settings" FontSize="14" FontWeight="Bold" 
                               Margin="0,0,0,10"/>
                    <StackPanel Orientation="Horizontal" Margin="0,0,0,10">
                        <TextBlock Text="Visit https://dpi.lv/ to get your real monitor DPI" 
                                   FontSize="10" Foreground="#666" Margin="0,5,10,0"/>
                        <Button Name="OpenDpiBtn" Content="Open DPI.LV" Background="#10b981" 
                                Foreground="White" Padding="8,3" FontSize="10" 
                                Cursor="Hand" MinWidth="80" Style="{StaticResource ColoredButton}" Tag="#10b981"/>
                    </StackPanel>
                    <StackPanel Orientation="Horizontal">
                        <TextBlock Text="DPI:" Margin="0,5,10,0" FontWeight="Bold"/>
                        <TextBox Name="DpiTextBox" Width="80" Padding="5" Margin="0,0,10,0"/>
                        <Button Name="UpdateDpiBtn" Content="Update DPI" Background="#667eea" 
                                Foreground="White" Padding="10,5" FontSize="11" 
                                Cursor="Hand" MinWidth="100" Style="{StaticResource ColoredButton}" Tag="#667eea"/>
                    </StackPanel>
                </StackPanel>
            </Border>

            <StackPanel Orientation="Horizontal" Margin="0,0,0,15">
                <TextBlock Text="Status:" Margin="0,5,10,0" FontWeight="Bold"/>
                <TextBlock Name="StatusText" Text="Ready" Foreground="#666" Margin="0,5,0,0"/>
            </StackPanel>

            <StackPanel Orientation="Horizontal" Margin="0,0,0,10">
                <Button Name="StartBtn" Content="Start Tracking" Background="#667eea" 
                        Foreground="White" Padding="15,10" FontSize="12" 
                        Cursor="Hand" MinWidth="130" Margin="0,0,10,0" Style="{StaticResource ColoredButton}" Tag="#667eea"/>
                <Button Name="StopBtn" Content="Stop &amp; Save" Background="#764ba2" 
                        Foreground="White" Padding="15,10" FontSize="12" IsEnabled="False"
                        Cursor="Hand" MinWidth="130" Margin="0,0,10,0" Style="{StaticResource ColoredButton}" Tag="#764ba2"/>
                <Button Name="ResetBtn" Content="Reset" Background="#999" 
                        Foreground="White" Padding="15,10" FontSize="12" IsEnabled="False"
                        Cursor="Hand" MinWidth="80" Style="{StaticResource ColoredButton}" Tag="#999"/>
            </StackPanel>

            <StackPanel Orientation="Horizontal">
                <Button Name="LapBtn" Content="Lap" Background="#f59e0b" 
                        Foreground="White" Padding="15,10" FontSize="12" IsEnabled="False"
                        Cursor="Hand" MinWidth="130" Style="{StaticResource ColoredButton}" Tag="#f59e0b"/>
            </StackPanel>
        </StackPanel>
    </Grid>
    </ScrollViewer>
</Window>
'@

    $reader = New-Object Xml.XmlNodeReader ([Xml]$xaml)
    $window = [Windows.Markup.XamlReader]::Load($reader)
    $reader.Close()

    $startBtn = $window.FindName('StartBtn')
    $stopBtn = $window.FindName('StopBtn')
    $resetBtn = $window.FindName('ResetBtn')
    $lapBtn = $window.FindName('LapBtn')
    $statusText = $window.FindName('StatusText')
    $totalDistanceText = $window.FindName('TotalDistance')
    $sampleCountText = $window.FindName('SampleCount')
    $elapsedTimeText = $window.FindName('ElapsedTime')
    $centimeterText = $window.FindName('CentimeterValue')
    $meterText = $window.FindName('MeterValue')
    $avgDistanceText = $window.FindName('AverageDistance')
    $maxDistanceText = $window.FindName('MaxDistance')
    $minDistanceText = $window.FindName('MinDistance')
    $pixPerSecText = $window.FindName('PixelsPerSecond')
    $cmPerSecText = $window.FindName('CmPerSecond')
    $mPerSecText = $window.FindName('MPerSecond')
    $dpiTextBox = $window.FindName('DpiTextBox')
    $updateDpiBtn = $window.FindName('UpdateDpiBtn')
    $openDpiBtn = $window.FindName('OpenDpiBtn')
    $lapListText = $window.FindName('LapList')

    # Initialize DPI field
    $dpiTextBox.Text = $DPI

    # Load total distance from config
    $script:tracking = $false
    $script:totalDistance = $loadedConfig.TotalDistance
    $script:sampleCount = 0
    $script:maxDistance = 0
    $script:minDistance = [double]::MaxValue
    $script:samples = @()
    $script:startTime = $null
    $script:lastPos = $null
    $script:laps = @()
    $script:lapStartDistance = 0
    $script:lapStartTime = $null
    $updateInterval = 50
    $script:timer = $null

    $startBtn.Add_Click({
            if (-not $script:tracking)
            {
                $script:tracking = $true
                # Don't reset totalDistance - it accumulates
                $script:sampleCount = 0
                $script:maxDistance = 0
                $script:minDistance = [double]::MaxValue
                $script:samples = @()
                $script:startTime = Get-Date
                $script:lastPos = [MouseTracker]::GetMousePosition()
            
                $startBtn.IsEnabled = $false
                $stopBtn.IsEnabled = $true
                $resetBtn.IsEnabled = $false
                $lapBtn.IsEnabled = $true
                $script:lapStartDistance = $script:totalDistance
                $script:lapStartTime = $script:startTime
                $statusText.Text = 'Tracking...'
                $statusText.Foreground = [Windows.Media.Brushes]::Green

                $script:timer = New-Object System.Windows.Threading.DispatcherTimer
                $script:timer.Interval = [TimeSpan]::FromMilliseconds($updateInterval)
            
                $script:timer.Add_Tick({
                        if ($script:tracking)
                        {
                            $currentPos = [MouseTracker]::GetMousePosition()
                            $deltaX = $currentPos.X - $script:lastPos.X
                            $deltaY = $currentPos.Y - $script:lastPos.Y
                            $distance = [Math]::Sqrt(($deltaX * $deltaX) + ($deltaY * $deltaY))
                    
                            if ($distance -gt 0)
                            {
                                $script:totalDistance += $distance
                                $script:sampleCount++
                                $script:samples += $distance
                        
                                if ($distance -gt $script:maxDistance) { $script:maxDistance = $distance }
                                if ($distance -lt $script:minDistance) { $script:minDistance = $distance }
                            }
                    
                            $script:lastPos = $currentPos
                    
                            # Update UI
                            $distanceFormatted = Format-Distance $script:totalDistance
                            $totalDistanceText.Text = $distanceFormatted.Pixels
                            $centimeterText.Text = $distanceFormatted.Centimeters
                            $meterText.Text = $distanceFormatted.Meters
                            $sampleCountText.Text = $script:sampleCount
                    
                            $elapsed = ((Get-Date) - $script:startTime)
                            $elapsedTimeText.Text = $elapsed.ToString('hh\:mm\:ss')
                    
                            if ($script:sampleCount -gt 0)
                            {
                                $avg = $script:totalDistance / $script:sampleCount
                                $avgDistanceText.Text = "$([Math]::Round($avg, 2)) px"
                                $maxDistanceText.Text = "$([Math]::Round($script:maxDistance, 2)) px"
                                $minDistanceText.Text = "$([Math]::Round($script:minDistance, 2)) px"
                            }
                    
                            if ($elapsed.TotalSeconds -gt 0)
                            {
                                $pixPerSec = $script:totalDistance / $elapsed.TotalSeconds
                                $pixPerSecText.Text = "$([Math]::Round($pixPerSec, 2))"
                                $cmPerSecText.Text = "$([Math]::Round($pixPerSec / $pixelsPerCm, 2))"
                                $mPerSecText.Text = "$([Math]::Round($pixPerSec / $pixelsPerMeter, 4))"
                            }
                        }
                    })
            
                $script:timer.Start()
            }
        })

    $stopBtn.Add_Click({
            if ($script:timer) { $script:timer.Stop() }
            $script:tracking = $false
            $startBtn.IsEnabled = $true
            $stopBtn.IsEnabled = $false
            $resetBtn.IsEnabled = $true
            $lapBtn.IsEnabled = $false
            $statusText.Text = 'Stopped'
            $statusText.Foreground = [Windows.Media.Brushes]::Orange
        })

    $resetBtn.Add_Click({
            if ($script:timer) { $script:timer.Stop() }
            $script:tracking = $false
            $script:totalDistance = 0
            $script:sampleCount = 0
            $script:maxDistance = 0
            $script:minDistance = [double]::MaxValue
            $script:samples = @()
            $script:laps = @()
            $script:lapStartDistance = 0
            $script:lapStartTime = $null
        
            $totalDistanceText.Text = '0.00'
            $centimeterText.Text = '0.00'
            $meterText.Text = '0.0000'
            $sampleCountText.Text = '0'
            $elapsedTimeText.Text = '00:00:00'
            $avgDistanceText.Text = '0.00 px'
            $maxDistanceText.Text = '0.00 px'
            $minDistanceText.Text = '0.00 px'
            $pixPerSecText.Text = '0.00'
            $cmPerSecText.Text = '0.00'
            $mPerSecText.Text = '0.0000'
            $lapListText.Text = 'No laps recorded'
        
            $startBtn.IsEnabled = $true
            $stopBtn.IsEnabled = $false
            $resetBtn.IsEnabled = $false
            $lapBtn.IsEnabled = $false
            $statusText.Text = 'Ready'
            $statusText.Foreground = [Windows.Media.Brushes]::Black
        })

    $lapBtn.Add_Click({
            if ($script:tracking)
            {
                $lapDistance = $script:totalDistance - $script:lapStartDistance
                $lapTime = (Get-Date) - $script:lapStartTime
                $lapNumber = $script:laps.Count + 1
                
                $lapFormatted = Format-Distance $lapDistance
                
                $lapInfo = [PSCustomObject]@{
                    Number   = $lapNumber
                    Distance = $lapFormatted
                    Time     = $lapTime
                }
                
                $script:laps += $lapInfo
                
                # Update lap display
                $lapText = ($script:laps | ForEach-Object {
                        $timeStr = $_.Time.ToString('hh\:mm\:ss\.ff')
                        "Lap $($_.Number): $($_.Distance.Pixels) px ($($_.Distance.Centimeters) cm, $($_.Distance.Meters) m) - Time: $timeStr"
                    }) -join "`n"
                
                $lapListText.Text = $lapText
                
                # Reset lap counters for next lap
                $script:lapStartDistance = $script:totalDistance
                $script:lapStartTime = Get-Date
            }
        })

    $updateDpiBtn.Add_Click({
            $newDpi = 0
            if ([int]::TryParse($dpiTextBox.Text, [ref]$newDpi) -and $newDpi -gt 0)
            {
                $script:DPI = $newDpi
                $script:pixelsPerInch = $newDpi
                $script:pixelsPerCm = $newDpi / 2.54
                $script:pixelsPerMeter = $script:pixelsPerCm * 100
                
                # Update display with new DPI
                if ($script:totalDistance -gt 0)
                {
                    $distanceFormatted = Format-Distance $script:totalDistance
                    $centimeterText.Text = $distanceFormatted.Centimeters
                    $meterText.Text = $distanceFormatted.Meters
                }
                
                [System.Windows.MessageBox]::Show("DPI updated to $newDpi`nConversions have been recalculated.", 'DPI Updated')
            }
            else
            {
                [System.Windows.MessageBox]::Show('Please enter a valid DPI value (positive integer)', 'Invalid DPI')
            }
        })

    $openDpiBtn.Add_Click({
            Start-Process 'https://dpi.lv/'
        })

    $window.Add_Closed({
            if ($script:timer) { $script:timer.Stop() }
            
            # Always save config with total distance
            Set-TrackerConfig -ConfigPath $ConfigPath -TotalDistance $script:totalDistance -DPI $DPI
            
            if ($script:sampleCount -gt 0)
            {
                $result = [System.Windows.MessageBox]::Show('Save tracking data to INI file?', 'Save Results', [System.Windows.MessageBoxButton]::YesNo)
                if ($result -eq 'Yes')
                {
                    $elapsed = ((Get-Date) - $script:startTime).TotalSeconds
                    $averageDistance = $script:totalDistance / $script:sampleCount
                    $pixelsPerSecond = $script:totalDistance / $elapsed
                
                    $distanceFormatted = Format-Distance $script:totalDistance
                    $iniContent = @"
; Mouse Distance Tracker Report - GUI Mode
; Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
; Duration: $([Math]::Round($elapsed, 2)) seconds
; DPI: $DPI

[SUMMARY]
TotalDistancePixels=$($distanceFormatted.Pixels)
TotalDistanceCentimeters=$($distanceFormatted.Centimeters)
TotalDistanceMeters=$($distanceFormatted.Meters)
TotalDistanceInches=$($distanceFormatted.Inches)
TotalSamples=$($script:sampleCount)
TrackingDurationSeconds=$([Math]::Round($elapsed, 2))
AverageDistancePerSample=$([Math]::Round($averageDistance, 2))
MaxDistanceInSample=$([Math]::Round($script:maxDistance, 2))
MinDistanceInSample=$([Math]::Round($script:minDistance, 2))
PixelsPerSecond=$([Math]::Round($pixelsPerSecond, 2))
CentimetersPerSecond=$([Math]::Round($pixelsPerSecond / $pixelsPerCm, 2))
MetersPerSecond=$([Math]::Round($pixelsPerSecond / $pixelsPerMeter, 4))
SamplingIntervalMilliseconds=$updateInterval

[TIMESTAMPS]
StartTime=$(Get-Date $script:startTime -Format 'yyyy-MM-dd HH:mm:ss.fff')
EndTime=$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff')

[SETTINGS]
DPI=$DPI
PixelsPerInch=$pixelsPerInch
PixelsPerCentimeter=$([Math]::Round($pixelsPerCm, 4))
PixelsPerMeter=$([Math]::Round($pixelsPerMeter, 2))
ScriptPath=$PSCommandPath
OutputFile=$ConfigPath
"@

                    if ($script:sampleCount -le 500)
                    {
                        $iniContent += "`r`n[SAMPLES]`r`n"
                        for ($i = 0; $i -lt $script:samples.Count; $i++)
                        {
                            $iniContent += "Sample$(($i + 1).ToString('D4'))=$([Math]::Round($script:samples[$i], 2))`r`n"
                        }
                    }

                    $iniContent | Out-File -FilePath $ConfigPath -Encoding UTF8 -Force
                    [System.Windows.MessageBox]::Show("Results saved to:`r`n$ConfigPath", 'Saved')
                }
            }
        })

    # Display loaded total distance
    if ($loadedConfig.TotalDistance -gt 0)
    {
        $distanceFormatted = Format-Distance $loadedConfig.TotalDistance
        $totalDistanceText.Text = $distanceFormatted.Pixels
        $centimeterText.Text = $distanceFormatted.Centimeters
        $meterText.Text = $distanceFormatted.Meters
    }

    $window.ShowDialog() | Out-Null
    exit
}

# Console Mode - Continuous tracking until Ctrl+C
Write-Host '════════════════════════════════════════' -ForegroundColor Cyan
Write-Host '   Mouse Distance Tracker' -ForegroundColor Cyan
Write-Host '════════════════════════════════════════' -ForegroundColor Cyan
Write-Host ''
Write-Host 'Mode: Continuous (press Ctrl+C to stop)' -ForegroundColor Yellow
Write-Host "DPI: $DPI" -ForegroundColor Yellow
Write-Host "Output File: $iniPath" -ForegroundColor Yellow
Write-Host ''
Write-Host 'Move your mouse to begin tracking...' -ForegroundColor Green
Write-Host 'Press Ctrl+C when finished.' -ForegroundColor Green
Write-Host ''

$startTime = Get-Date
$totalDistance = 0
$sampleCount = 0
$maxDistance = 0
$minDistance = [double]::MaxValue
$samples = @()
$lastPos = [MouseTracker]::GetMousePosition()
$updateInterval = 50

Write-Host "Tracking started at $(Get-Date -Format 'HH:mm:ss.fff')" -ForegroundColor Gray

try
{
    while ($true)
    {
        $currentPos = [MouseTracker]::GetMousePosition()
        $deltaX = $currentPos.X - $lastPos.X
        $deltaY = $currentPos.Y - $lastPos.Y
        $distance = [Math]::Sqrt(($deltaX * $deltaX) + ($deltaY * $deltaY))

        if ($distance -gt 0)
        {
            $totalDistance += $distance
            $sampleCount++
            $samples += $distance

            if ($distance -gt $maxDistance) { $maxDistance = $distance }
            if ($distance -lt $minDistance) { $minDistance = $distance }

            $elapsed = ((Get-Date) - $startTime).TotalSeconds
            $distFormatted = Format-Distance $totalDistance
            Write-Progress -Activity 'Tracking Mouse Movement' `
                -Status "Distance: $($distFormatted.Pixels) px / $($distFormatted.Centimeters) cm / $($distFormatted.Meters) m | Samples: $sampleCount | Elapsed: $([Math]::Round($elapsed, 1))s" `
                -PercentComplete 0
        }

        $lastPos = $currentPos
        Start-Sleep -Milliseconds $updateInterval
    }
}
catch
{
    Write-Progress -Activity 'Tracking Mouse Movement' -Completed
}

Write-Host ''
Write-Host "Tracking stopped at $(Get-Date -Format 'HH:mm:ss.fff')" -ForegroundColor Gray

$endTime = Get-Date
$elapsed = ($endTime - $startTime).TotalSeconds

# Calculate statistics
$averageDistance = if ($sampleCount -gt 0) { $totalDistance / $sampleCount } else { 0 }
$pixelsPerSecond = if ($elapsed -gt 0) { $totalDistance / $elapsed } else { 0 }

$distanceFormatted = Format-Distance $totalDistance

Write-Host ''
Write-Host '═══════════════════════════════════════════' -ForegroundColor Green
Write-Host '   Tracking Results' -ForegroundColor Green
Write-Host '═══════════════════════════════════════════' -ForegroundColor Green
Write-Host ''
Write-Host 'Total Distance:' -ForegroundColor White
Write-Host "  Pixels: $($distanceFormatted.Pixels)" -ForegroundColor Cyan
Write-Host "  Centimeters: $($distanceFormatted.Centimeters) cm" -ForegroundColor Cyan
Write-Host "  Meters: $($distanceFormatted.Meters) m" -ForegroundColor Cyan
Write-Host "  Inches: $($distanceFormatted.Inches) in" -ForegroundColor Cyan
Write-Host ''
Write-Host 'Statistics:' -ForegroundColor White
Write-Host "  Total Samples: $sampleCount" -ForegroundColor White
Write-Host "  Duration: $([Math]::Round($elapsed, 2)) seconds" -ForegroundColor White
Write-Host "  Average/Sample: $([Math]::Round($averageDistance, 2)) px" -ForegroundColor White
Write-Host "  Max/Sample: $([Math]::Round($maxDistance, 2)) px" -ForegroundColor White
Write-Host "  Min/Sample: $([Math]::Round($minDistance, 2)) px" -ForegroundColor White
Write-Host ''
Write-Host 'Velocity:' -ForegroundColor White
Write-Host "  Pixels/Second: $([Math]::Round($pixelsPerSecond, 2))" -ForegroundColor White
Write-Host "  CM/Second: $([Math]::Round($pixelsPerSecond / $script:pixelsPerCm, 2))" -ForegroundColor White
Write-Host "  Meters/Second: $([Math]::Round($pixelsPerSecond / $script:pixelsPerMeter, 4))" -ForegroundColor White
Write-Host ''

# Create INI file content
$iniContent = @"
; Mouse Distance Tracker Report - Console Mode
; Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
; Duration: $([Math]::Round($elapsed, 2)) seconds
; DPI: $DPI

[SUMMARY]
TotalDistancePixels=$($distanceFormatted.Pixels)
TotalDistanceCentimeters=$($distanceFormatted.Centimeters)
TotalDistanceMeters=$($distanceFormatted.Meters)
TotalDistanceInches=$($distanceFormatted.Inches)
TotalSamples=$sampleCount
TrackingDurationSeconds=$([Math]::Round($elapsed, 2))
AverageDistancePerSample=$([Math]::Round($averageDistance, 2))
MaxDistanceInSample=$([Math]::Round($maxDistance, 2))
MinDistanceInSample=$([Math]::Round($minDistance, 2))
PixelsPerSecond=$([Math]::Round($pixelsPerSecond, 2))
CentimetersPerSecond=$([Math]::Round($pixelsPerSecond / $script:pixelsPerCm, 2))
MetersPerSecond=$([Math]::Round($pixelsPerSecond / $script:pixelsPerMeter, 4))
SamplingIntervalMilliseconds=$updateInterval

[TIMESTAMPS]
StartTime=$(Get-Date $startTime -Format 'yyyy-MM-dd HH:mm:ss.fff')
EndTime=$(Get-Date $endTime -Format 'yyyy-MM-dd HH:mm:ss.fff')

[SETTINGS]
DPI=$DPI
PixelsPerInch=$script:pixelsPerInch
PixelsPerCentimeter=$([Math]::Round($script:pixelsPerCm, 4))
PixelsPerMeter=$([Math]::Round($script:pixelsPerMeter, 2))
ScriptPath=$PSCommandPath
OutputFile=$iniPath
"@

# Append detailed samples if there are relatively few
if ($sampleCount -le 500)
{
    $iniContent += "`r`n[SAMPLES]`r`n"
    for ($i = 0; $i -lt $samples.Count; $i++)
    {
        $iniContent += "Sample$(($i + 1).ToString('D4'))=$([Math]::Round($samples[$i], 2))`r`n"
    }
}

# Save to INI file
$iniContent | Out-File -FilePath $iniPath -Encoding UTF8 -Force

Write-Host "✓ Results saved to: $iniPath" -ForegroundColor Green
Write-Host ''
Write-Host 'To view the INI file:' -ForegroundColor Cyan
Write-Host "  notepad `"$iniPath`"" -ForegroundColor Gray
Write-Host ''
<#
.SYNOPSIS
    Measures and tracks mouse movement distance, saving results to an INI file.

.DESCRIPTION
    This script monitors mouse cursor position changes, calculates the total distance
    traveled in pixels, and saves the metrics to a configuration file.

.PARAMETER DurationSeconds
    How long to track mouse movement in seconds. If 0, runs continuously until stopped (default: 0)

.PARAMETER OutputPath
    Path to save the INI file (default: current directory)

.PARAMETER FileName
    Name of the INI file (default: mouse-tracker.cfg)

.PARAMETER GUI
    Display a GUI window for real-time tracking and control (default: $false)

.PARAMETER DPI
    Screen DPI for accurate pixel-to-distance conversion (default: auto-detect)

.EXAMPLE
    .\MouseDistanceTracker.ps1 -GUI

.EXAMPLE
    .\MouseDistanceTracker.ps1 -DurationSeconds 60 -OutputPath "C:\Logs"

.EXAMPLE
    .\MouseDistanceTracker.ps1 -GUI -DPI 96
#>
<#
.SYNOPSIS
    Measures and tracks mouse movement distance, saving results to an INI file.

.DESCRIPTION
    This script monitors mouse cursor position changes, calculates the total distance
    traveled in pixels, and saves the metrics to a configuration file.

.PARAMETER DurationSeconds
    How long to track mouse movement in seconds. If 0, runs continuously until stopped (default: 0)

.PARAMETER OutputPath
    Path to save the INI file (default: current directory)

.PARAMETER FileName
    Name of the INI file (default: mouse-tracker.cfg)

.PARAMETER GUI
    Display a GUI window for real-time tracking and control (default: $false)

.PARAMETER DPI
    Screen DPI for accurate pixel-to-distance conversion (default: auto-detect)

.EXAMPLE
    .\MouseDistanceTracker.ps1 -GUI

.EXAMPLE
    .\MouseDistanceTracker.ps1 -DurationSeconds 60 -OutputPath "C:\Logs"

.EXAMPLE
    .\MouseDistanceTracker.ps1 -GUI -DPI 96
#>

# SIG # Begin signature block
# MIInigYJKoZIhvcNAQcCoIInezCCJ3cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD2O5KBTns8rJ6s
# 1HoeAOa1MokLy+OAqscdVcEbK6/vQKCCIWQwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggavMIIFl6ADAgECAhNIAAABplIG96GlOv8jAAEAAAGmMA0G
# CSqGSIb3DQEBCwUAMGcxEjAQBgoJkiaJk/IsZAEZFgJhdTETMBEGCgmSJomT8ixk
# ARkWA2dvdjETMBEGCgmSJomT8ixkARkWA3FsZDETMBEGCgmSJomT8ixkARkWA2Rw
# dzESMBAGA1UEAxMJRFBXUk9PVENBMB4XDTIxMDIxMTA1NTY1MloXDTMxMDIwOTA1
# NTY1MlowgYcxEjAQBgoJkiaJk/IsZAEZFgJhdTETMBEGCgmSJomT8ixkARkWA2dv
# djETMBEGCgmSJomT8ixkARkWA3FsZDETMBEGCgmSJomT8ixkARkWA2RwdzEbMBkG
# CgmSJomT8ixkARkWC2Rwd3NlcnZpY2VzMRUwEwYDVQQDEwxIUFdJU1NVSU5HQ0Ew
# ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDGoeDZZzRbL+4vwyxj8xgY
# Ds5RXzPM3js6Qvpp6/xpB6eMx37u4Mblp2gJ151yTEb746uU7BSghipt6KyDqZOw
# kz92s32EDTrsBLDYLNyaFwcckZtNjWkAzUX5nQ4I/SZ4MVPMzYQlq/N8CVE+mcVO
# 8MtoD3AvkCVIO3hYegyu+b4d0u5a4cPAPRogyqakAJN9LpcDK6pPHwdZ+T7co9CB
# AUtVMf476V+eWjJ4rbBHlCLsx7vDYxjnmzrkQ0ruXNJ+nGaNKQ/tXdHcVVqwu62P
# nOIaKp4A7LrLhUrfWgyPgZb6p0vWT/s65qxsRcp8cHdZYcBBCpci9Ld5wtWHDN+B
# AgMBAAGjggMxMIIDLTASBgkrBgEEAYI3FQEEBQIDAgADMCMGCSsGAQQBgjcVAgQW
# BBRsfRdHHTZA5J4s4a+guPSXzZAqpzAdBgNVHQ4EFgQUfhDlENZ3Rj8fcpY+Rkp9
# 65wp3ZAwFQYDVR0gBA4wDDAKBggqAwSLL0NZBTA9BgkrBgEEAYI3FQcEMDAuBiYr
# BgEEAYI3FQiEmOo1gvPjOIOxmxSD1pwgg9LtHQeEhtAbhIKzbQIBZAIBBDAOBgNV
# HQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBQ76ORbVdUE
# D8CEe9E4CedUVM0UrTCCAREGA1UdHwSCAQgwggEEMIIBAKCB/aCB+oaBwGxkYXA6
# Ly8vQ049RFBXUk9PVENBKDEpLENOPXZibmVkcHdjYTAxLENOPUNEUCxDTj1QdWJs
# aWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9u
# LERDPWRwdyxEQz1xbGQsREM9Z292LERDPWF1P2NlcnRpZmljYXRlUmV2b2NhdGlv
# bkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludIY1aHR0
# cDovL3BraS5kcHcucWxkLmdvdi5hdS9DZXJ0RW5yb2xsL0RQV1JPT1RDQSgxKS5j
# cmwwggEkBggrBgEFBQcBAQSCARYwggESMIGxBggrBgEFBQcwAoaBpGxkYXA6Ly8v
# Q049RFBXUk9PVENBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxD
# Tj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWRwdyxEQz1xbGQsREM9Z292
# LERDPWF1P2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0
# aW9uQXV0aG9yaXR5MFwGCCsGAQUFBzAChlBodHRwOi8vcGtpLmRwdy5xbGQuZ292
# LmF1L0NlcnRFbnJvbGwvdmJuZWRwd2NhMDEuZHB3LnFsZC5nb3YuYXVfRFBXUk9P
# VENBKDEpLmNydDANBgkqhkiG9w0BAQsFAAOCAQEAPM02YpqG9n0spRBIB0e+KFHn
# seo1IrHGU9NqZzZUqybb61rHXCE+jLa2B2plR8VWPMFxXUrWYrLohcnHwAAitCNS
# OhvV6Gz9rj4orOx0E7BJZoCaDHiQhDhTzQIB7FrZyW8xFap/G3Lwu2KXJa4J0JHg
# pxRqGkTSyCTw2364lEr3K5Lkukr6YxnBOrI/Zh4kBg2obrpD/7PUPF8dwk8PmWOa
# dcY3cxLlLzjY59IPli3YWtjyoawbnP09a00QwuFgWT91hbE5JMbqX+7I5e843eL9
# FLfDZvCKuYXqOM8oHyWxUyHmz5GKgnkvjIwM0b9bGJjvWvRX1hlFqOj5yVLeETCC
# BrQwggScoAMCAQICEA3HrFcF/yGZLkBDIgw6SYYwDQYJKoZIhvcNAQELBQAwYjEL
# MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3
# LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0
# MB4XDTI1MDUwNzAwMDAwMFoXDTM4MDExNDIzNTk1OVowaTELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVz
# dGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALR4MdMKmEFyvjxGwBysddujRmh0
# tFEXnU2tjQ2UtZmWgyxU7UNqEY81FzJsQqr5G7A6c+Gh/qm8Xi4aPCOo2N8S9SLr
# C6Kbltqn7SWCWgzbNfiR+2fkHUiljNOqnIVD/gG3SYDEAd4dg2dDGpeZGKe+42DF
# UF0mR/vtLa4+gKPsYfwEu7EEbkC9+0F2w4QJLVSTEG8yAR2CQWIM1iI5PHg62IVw
# xKSpO0XaF9DPfNBKS7Zazch8NF5vp7eaZ2CVNxpqumzTCNSOxm+SAWSuIr21Qomb
# +zzQWKhxKTVVgtmUPAW35xUUFREmDrMxSNlr/NsJyUXzdtFUUt4aS4CEeIY8y9Ia
# aGBpPNXKFifinT7zL2gdFpBP9qh8SdLnEut/GcalNeJQ55IuwnKCgs+nrpuQNfVm
# UB5KlCX3ZA4x5HHKS+rqBvKWxdCyQEEGcbLe1b8Aw4wJkhU1JrPsFfxW1gaou30y
# Z46t4Y9F20HHfIY4/6vHespYMQmUiote8ladjS/nJ0+k6MvqzfpzPDOy5y6gqzti
# T96Fv/9bH7mQyogxG9QEPHrPV6/7umw052AkyiLA6tQbZl1KhBtTasySkuJDpsZG
# Kdlsjg4u70EwgWbVRSX1Wd4+zoFpp4Ra+MlKM2baoD6x0VR4RjSpWM8o5a6D8bpf
# m4CLKczsG7ZrIGNTAgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0G
# A1UdDgQWBBTvb1NK6eQGfHrK4pBW9i/USezLTjAfBgNVHSMEGDAWgBTs1+OC0nFd
# ZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUH
# AwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0
# dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3Js
# MCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsF
# AAOCAgEAF877FoAc/gc9EXZxML2+C8i1NKZ/zdCHxYgaMH9Pw5tcBnPw6O6FTGNp
# oV2V4wzSUGvI9NAzaoQk97frPBtIj+ZLzdp+yXdhOP4hCFATuNT+ReOPK0mCefSG
# +tXqGpYZ3essBS3q8nL2UwM+NMvEuBd/2vmdYxDCvwzJv2sRUoKEfJ+nN57mQfQX
# wcAEGCvRR2qKtntujB71WPYAgwPyWLKu6RnaID/B0ba2H3LUiwDRAXx1Neq9ydOa
# l95CHfmTnM4I+ZI2rVQfjXQA1WSjjf4J2a7jLzWGNqNX+DF0SQzHU0pTi4dBwp9n
# EC8EAqoxW6q17r0z0noDjs6+BFo+z7bKSBwZXTRNivYuve3L2oiKNqetRHdqfMTC
# W/NmKLJ9M+MtucVGyOxiDf06VXxyKkOirv6o02OoXN4bFzK0vlNMsvhlqgF2puE6
# FndlENSmE+9JGYxOGLS/D284NHNboDGcmWXfwXRy4kbu4QFhOm0xJuF2EZAOk5eC
# khSxZON3rGlHqhpB/8MluDezooIs8CVnrpHMiD2wL40mm53+/j7tFaxYKIqL0Q4s
# sd8xHZnIn/7GELH3IdvG2XlM9q7WP/UwgOkw/HQtyRN62JK4S1C8uw3PdBunvAZa
# psiI5YKdvlarEvf8EA+8hcpSM9LHJmyrxaFtoza2zNaQ9k+5t1wwggbtMIIE1aAD
# AgECAhAKgO8YS43xBYLRxHanlXRoMA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYT
# AlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQg
# VHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEw
# HhcNMjUwNjA0MDAwMDAwWhcNMzYwOTAzMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFNIQTI1
# NiBSU0E0MDk2IFRpbWVzdGFtcCBSZXNwb25kZXIgMjAyNSAxMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEA0EasLRLGntDqrmBWsytXum9R/4ZwCgHfyjfM
# GUIwYzKomd8U1nH7C8Dr0cVMF3BsfAFI54um8+dnxk36+jx0Tb+k+87H9WPxNyFP
# JIDZHhAqlUPt281mHrBbZHqRK71Em3/hCGC5KyyneqiZ7syvFXJ9A72wzHpkBaMU
# Ng7MOLxI6E9RaUueHTQKWXymOtRwJXcrcTTPPT2V1D/+cFllESviH8YjoPFvZSjK
# s3SKO1QNUdFd2adw44wDcKgH+JRJE5Qg0NP3yiSyi5MxgU6cehGHr7zou1znOM8o
# dbkqoK+lJ25LCHBSai25CFyD23DZgPfDrJJJK77epTwMP6eKA0kWa3osAe8fcpK4
# 0uhktzUd/Yk0xUvhDU6lvJukx7jphx40DQt82yepyekl4i0r8OEps/FNO4ahfvAk
# 12hE5FVs9HVVWcO5J4dVmVzix4A77p3awLbr89A90/nWGjXMGn7FQhmSlIUDy9Z2
# hSgctaepZTd0ILIUbWuhKuAeNIeWrzHKYueMJtItnj2Q+aTyLLKLM0MheP/9w6Ct
# juuVHJOVoIJ/DtpJRE7Ce7vMRHoRon4CWIvuiNN1Lk9Y+xZ66lazs2kKFSTnnkrT
# 3pXWETTJkhd76CIDBbTRofOsNyEhzZtCGmnQigpFHti58CSmvEyJcAlDVcKacJ+A
# 9/z7eacCAwEAAaOCAZUwggGRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFOQ7/PIx
# 7f391/ORcWMZUEPPYYzoMB8GA1UdIwQYMBaAFO9vU0rp5AZ8esrikFb2L9RJ7MtO
# MA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCBlQYIKwYB
# BQUHAQEEgYgwgYUwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNv
# bTBdBggrBgEFBQcwAoZRaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3J0
# MF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNy
# bDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQEL
# BQADggIBAGUqrfEcJwS5rmBB7NEIRJ5jQHIh+OT2Ik/bNYulCrVvhREafBYF0RkP
# 2AGr181o2YWPoSHz9iZEN/FPsLSTwVQWo2H62yGBvg7ouCODwrx6ULj6hYKqdT8w
# v2UV+Kbz/3ImZlJ7YXwBD9R0oU62PtgxOao872bOySCILdBghQ/ZLcdC8cbUUO75
# ZSpbh1oipOhcUT8lD8QAGB9lctZTTOJM3pHfKBAEcxQFoHlt2s9sXoxFizTeHihs
# QyfFg5fxUFEp7W42fNBVN4ueLaceRf9Cq9ec1v5iQMWTFQa0xNqItH3CPFTG7aEQ
# JmmrJTV3Qhtfparz+BW60OiMEgV5GWoBy4RVPRwqxv7Mk0Sy4QHs7v9y69NBqycz
# 0BZwhB9WOfOu/CIJnzkQTwtSSpGGhLdjnQ4eBpjtP+XB3pQCtv4E5UCSDag6+iX8
# MmB10nfldPF9SVD7weCC3yXZi/uuhqdwkgVxuiMFzGVFwYbQsiGnoa9F5AaAyBjF
# BtXVLcKtapnMG3VH3EmAp/jsJ3FVF3+d1SVDTmjFjLbNFZUWMXuZyvgLfgyPehwJ
# VxwC+UpX2MSey2ueIu9THFVkT+um1vshETaWyQo8gmBto/m3acaP9QsuLj3FNwFl
# Txq25+T4QwX9xa6ILs84ZPvmpovq90K8eWyG2N01c4IhSOxqt81nMIIHczCCBlug
# AwIBAgITZQABS1kNRvNjT2MyywADAAFLWTANBgkqhkiG9w0BAQsFADCBhzESMBAG
# CgmSJomT8ixkARkWAmF1MRMwEQYKCZImiZPyLGQBGRYDZ292MRMwEQYKCZImiZPy
# LGQBGRYDcWxkMRMwEQYKCZImiZPyLGQBGRYDZHB3MRswGQYKCZImiZPyLGQBGRYL
# ZHB3c2VydmljZXMxFTATBgNVBAMTDEhQV0lTU1VJTkdDQTAeFw0yNjAyMTMwNDQ3
# MTRaFw0yNzAyMTMwNDQ3MTRaMIHKMRIwEAYKCZImiZPyLGQBGRYCYXUxEzARBgoJ
# kiaJk/IsZAEZFgNnb3YxEzARBgoJkiaJk/IsZAEZFgNxbGQxEzARBgoJkiaJk/Is
# ZAEZFgNkcHcxGzAZBgoJkiaJk/IsZAEZFgtkcHdzZXJ2aWNlczETMBEGA1UECxMK
# RGVwYXJ0bWVudDEQMA4GA1UECxMHU3VwcG9ydDEWMBQGA1UECxMNQWRtaW5BY2Nv
# dW50czEZMBcGA1UEAxMQRlJBTkNJUyBBYXJvbiBOQTCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAOnoOYo3V4sL/5Czw/EGcmPtww3ESR15DPE5y/tjvHPk
# ykAx8mCDOSNQJkKnyRHfQG3DGkCvEvkCSSGVc3zhyYqj3e5IYqOiExHIwakD7EF+
# oVakT8GHXopz5cYdl+2zZhig9WxEh2tecJqXXI1pAcjCittk26fo4Xsas36aQTo4
# bhkyZLEZWwTRBCKuv+EMxYbsFnw85/TmPEILjd4QtJnPZTBq9pVmjnnn3tZR2m2e
# GYCAvgGSmxg+6NW4B68znY6D4ZUivV2vsj+0zDxAnmsixGpogY+UaThHRaCrgAok
# 4VSisf4sVbErWf9YfpRDM7FKkc6W7cbrZBEa5sh/4KUCAwEAAaOCA5EwggONMCUG
# CSsGAQQBgjcUAgQYHhYAQwBvAGQAZQBTAGkAZwBuAGkAbgBnMBMGA1UdJQQMMAoG
# CCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUAy8Quuw6AvCSFQpM
# ASdimHMG0SgwHwYDVR0jBBgwFoAUfhDlENZ3Rj8fcpY+Rkp965wp3ZAwggEoBgNV
# HR8EggEfMIIBGzCCARegggEToIIBD4aBw2xkYXA6Ly8vQ049SFBXSVNTVUlOR0NB
# KDIpLENOPVZCTkVIUFdDQTAyLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2
# aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWRwdyxEQz1xbGQs
# REM9Z292LERDPWF1P2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmpl
# Y3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludIZHaHR0cDovL2hwd3BraS5kcHdz
# ZXJ2aWNlcy5kcHcucWxkLmdvdi5hdS9DZXJ0RW5yb2xsL0hQV0lTU1VJTkdDQSgy
# KS5jcmwwggFFBggrBgEFBQcBAQSCATcwggEzMIG0BggrBgEFBQcwAoaBp2xkYXA6
# Ly8vQ049SFBXSVNTVUlOR0NBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2
# aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWRwdyxEQz1xbGQs
# REM9Z292LERDPWF1P2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0
# aWZpY2F0aW9uQXV0aG9yaXR5MHoGCCsGAQUFBzAChm5odHRwOi8vaHB3cGtpLmRw
# d3NlcnZpY2VzLmRwdy5xbGQuZ292LmF1L0NlcnRFbnJvbGwvVkJORUhQV0NBMDIu
# ZHB3c2VydmljZXMuZHB3LnFsZC5nb3YuYXVfSFBXSVNTVUlOR0NBKDMpLmNydDA6
# BgNVHREEMzAxoC8GCisGAQQBgjcUAgOgIQwfYWFyb24uZnJhbmNpcy5uYUBlcHcu
# cWxkLmdvdi5hdTBOBgkrBgEEAYI3GQIEQTA/oD0GCisGAQQBgjcZAgGgLwQtUy0x
# LTUtMjEtNTgzOTA3MjUyLTI5OTUwMjI2Ny02ODIwMDMzMzAtMTMzNDAxMA0GCSqG
# SIb3DQEBCwUAA4IBAQAI0wAK680UtJzs+l5L7Peq0SgNxXtX0RHOEl4++NQ+DB35
# jSVs2Bh6gqTbFh3NyYebqI9WZ7tSRzB44eDzuzsmBGCw3fe07+YUMvuFF7nfKxQw
# ATrVMefwZ2ePddVh+oi+1lzGtxv56GPLN9vRxj5LpFcORCAI9tvWSiLfW+0BKcRz
# bhTqhQ2tbnYACBIiCgcgKSxPO/tjGVsTAl7B+6X6rshHdiLk7rTt0OWVkHJaUsWC
# SdoY544Aw5LIhQFfStJ0Ms3PJPw8J1R4i5VcYHeGbA1sLI7EVJ0CJhPh77rf+iuY
# 9zLYtGd3iqtHJOJSWb8OqGRD0J/ASYMXorRauSDZMYIFfDCCBXgCAQEwgZ8wgYcx
# EjAQBgoJkiaJk/IsZAEZFgJhdTETMBEGCgmSJomT8ixkARkWA2dvdjETMBEGCgmS
# JomT8ixkARkWA3FsZDETMBEGCgmSJomT8ixkARkWA2RwdzEbMBkGCgmSJomT8ixk
# ARkWC2Rwd3NlcnZpY2VzMRUwEwYDVQQDEwxIUFdJU1NVSU5HQ0ECE2UAAUtZDUbz
# Y09jMssAAwABS1kwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAig
# AoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgEL
# MQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgFovRqqmrJJiVb1jGKbbW
# bq9uPNnZ8DnEUNHyz+Wqi9MwDQYJKoZIhvcNAQEBBQAEggEAMaYINoFNS2Rj1Xl6
# 2KSXrIHP8cP5H52S1BBN3svzhR6HNW5Pd57YvJ7WGOGDTFWOR3tMt9LFq83knjuC
# jvEPx5HzUWGoXMXo/NrfKNf8eu7RBsZVe+FHh8FPsYMxz9rhUqHAy/8ftuiy3x6T
# 6oQC16SxO5ZDiCK43xqD0LVI65tv/qzwer9DP2gEkPdzscqEQfGuOWWGb/axAYLB
# ptnYiJMZw78CoQq+T6pRNdwiNpyXBWmiLTxiJTIr6x1waVhIZAO6UtrXkbHva8aS
# lFtz4hUVyh5HI9NOtPI2/nGuP0OqCf/fuyzBg0nDtGZ1qO+PLYXeUIUEMcl5xzNL
# uxsD0qGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYT
# AlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQg
# VHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEC
# EAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMx
# CwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMTUyMzU4NDFaMC8GCSqG
# SIb3DQEJBDEiBCCDSlGQdBpml2yGavnRVcLc6jQwsRjJlbt14ydhbnhVCzANBgkq
# hkiG9w0BAQEFAASCAgCPVZPn7ik+BGC6DBKaI8EddWUxTb+p+B/KbN1KhzBjyxA1
# czsqskr88cSduK8Z9UTPVByawYp5KYeslz6Uvq2JOjsYY0K1zxdaoUQI4My1dDJk
# vs/2LdjOsC3RnvDKTsj/8ERX6g6dl+qy6UkpuNwczH3K3mQ2pdvWIe2iIYIQBbAd
# DXs2kDtsoeFtu0RFNdANkjDts5vVklNJu2odJjom/UXW8fjMkenNLftGr1UgEbR7
# RITyLuhftR1c6Dbj4w0VDgxY5jMNJr6urVAoyYhLa+5GqmGi2ZWG55AnjEvLawXl
# kADUlZv5gzrolw8/mBywJcMIm4BS1UIKn1w/kzhF06yigews7XsWshdO3xKz5Ds3
# 1QBcus+Dmiyy+MVkAOcur0N1llRNXqtW5gBrf7NRZ2ZgKyJ+3z+bi23cdq5FR8va
# 7RCrqiVNarSfbAbM6p8XIarc7NmczZIFldRYxNZhOYaWQ5mdKHSw2YhaCRYQM45L
# 7DFJEvqubjJ5H4ucUCeht7dVv7p5523y4/AkJuUoVNqePF9ZfA6+sLIK006z8hzj
# zmn9wBaBOr4VbnEfeM6GsNi8fCt6+Rd6TjnFG5L2Hfj4lP+qQCph27mtTrIVrGbr
# c1XkGnR8AF8pRkJAq9iPvA/h7vivUrQ5tfvsZsOe6/o1Ls3zA/b/wkhiPyAXnA==
# SIG # End signature block

