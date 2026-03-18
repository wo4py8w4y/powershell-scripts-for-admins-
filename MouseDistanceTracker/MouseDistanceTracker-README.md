# Mouse Distance Tracker

A PowerShell script that tracks mouse cursor movement in real time, calculates total distance traveled in multiple units (pixels, centimeters, meters, inches), and saves metrics to a configuration file. Supports both an interactive WPF GUI and a console mode.

## Features

- **GUI Mode**: WPF window with live statistics, lap timing, and DPI control (default)
- **Console Mode**: Continuous tracking in the terminal — press Ctrl+C to stop and save
- **Multi-Unit Distance**: Reports distance in pixels, centimeters, meters, and inches
- **Multi-Unit Velocity**: Reports speed in pixels/sec, cm/sec, and m/sec
- **DPI Auto-Detection**: Reads DPI from the Windows registry; manually overridable
- **Lap Timing**: Record lap distances and times during a GUI tracking session
- **Persistent Totals**: Accumulates total distance across sessions via a persistent config file
- **Distance Calculation**: Uses Euclidean distance formula for accurate pixel measurements
- **Statistical Analysis**: Calculates average, min, max, and per-second metrics
- **INI Output**: Saves all data in a structured INI format for easy parsing
- **Sample Details**: Optional detailed per-sample data (up to 500 samples)

## Usage

### Launch GUI (default)

```powershell
.\MouseDistanceTracker.ps1
```

### GUI with a specific DPI

```powershell
.\MouseDistanceTracker.ps1 -GUI -DPI 144
```

### Console mode — runs until Ctrl+C

```powershell
.\MouseDistanceTracker.ps1 -GUI:$false
```

### Console mode with a fixed duration

```powershell
.\MouseDistanceTracker.ps1 -GUI:$false -DurationSeconds 60
```

### Save output to a custom location

```powershell
.\MouseDistanceTracker.ps1 -GUI:$false -OutputPath "C:\Reports" -FileName "tracking-results.cfg"
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `GUI` | switch | `$true` | Launch the WPF GUI window |
| `DurationSeconds` | int | `0` (continuous) | Tracking duration in seconds. `0` runs until Ctrl+C (console mode only) |
| `OutputPath` | string | `$PSScriptRoot` | Directory for the output INI/CFG file |
| `FileName` | string | `mouse-tracker.cfg` | Name of the output file |
| `DPI` | int | `0` (auto-detect) | Screen DPI for pixel-to-distance conversion. `0` reads from the Windows registry (falls back to 96) |
| `ConfigPath` | string | *(hardcoded path)* | Path to the persistent config file used to accumulate total distance across sessions |

## GUI Mode

The GUI window (WPF) displays the following in real time:

### Real-time Statistics panel
- **Pixels** — total distance in pixels (current session + persisted total)
- **Centimeters** — converted using the current DPI
- **Meters**
- **Total Samples** — number of movement events recorded
- **Elapsed Time** — session clock (hh:mm:ss)

### Performance Metrics panel
- **Average/Sample** — mean pixels per movement event
- **Max/Sample** — largest single movement
- **Min/Sample** — smallest single movement
- **Pixels/Second**, **CM/Second**, **Meters/Second**

### Lap Times panel
Displays all recorded laps with distance (px, cm, m) and elapsed time per lap.

### DPI Settings panel
- Displays the current DPI value
- Provides a link to [https://dpi.lv/](https://dpi.lv/) for real-world DPI measurement
- Allows updating DPI on the fly; all unit conversions recalculate immediately

### Buttons
| Button | Behaviour |
|--------|-----------|
| **Start Tracking** | Begins polling and updating statistics |
| **Stop & Save** | Stops polling; prompts to save results to the output file |
| **Reset** | Clears all session data (does not affect the persistent total) |
| **Lap** | Records a lap marker with current distance and time |

When the window is closed, the current total distance is always saved to the persistent config file. If there are unsaved samples, a prompt asks whether to write the full INI report.

## Console Mode

Runs continuously until Ctrl+C (or until `DurationSeconds` is reached if specified). A `Write-Progress` bar updates in real time showing distance in all units, sample count, and elapsed seconds.

On exit, a full summary is printed and the results file is saved automatically — no prompt.

## Persistent Config File

A lightweight INI-style config file (`[CONFIG]` section) is read at startup and written on exit to persist the cumulative total across sessions:

```ini
; Mouse Distance Tracker Configuration
; Last Updated: 2025-06-01 09:45:00

[CONFIG]
TotalDistancePixels=482931.57
CurrentDPI=96
```

## Output File Format

The output file contains the following sections:

### [SUMMARY]

| Key | Description |
|-----|-------------|
| `TotalDistancePixels` | Total pixels traveled |
| `TotalDistanceCentimeters` | Converted using DPI |
| `TotalDistanceMeters` | Converted using DPI |
| `TotalDistanceInches` | Converted using DPI |
| `TotalSamples` | Number of movement samples recorded |
| `TrackingDurationSeconds` | Duration of tracking session |
| `AverageDistancePerSample` | Mean pixels per sample |
| `MaxDistanceInSample` | Largest single movement |
| `MinDistanceInSample` | Smallest single movement |
| `PixelsPerSecond` | Average velocity (px/s) |
| `CentimetersPerSecond` | Average velocity (cm/s) |
| `MetersPerSecond` | Average velocity (m/s) |
| `SamplingIntervalMilliseconds` | Polling interval (50 ms) |

### [TIMESTAMPS]

- **StartTime**: When tracking started (precise to millisecond)
- **EndTime**: When tracking ended

### [SETTINGS]

| Key | Description |
|-----|-------------|
| `DPI` | DPI value used for conversions |
| `PixelsPerInch` | Same as DPI |
| `PixelsPerCentimeter` | Derived from DPI |
| `PixelsPerMeter` | Derived from DPI |
| `ScriptPath` | Path to the tracking script |
| `OutputFile` | Path to the output file |

### [SAMPLES]

Individual sample data (only written when 500 or fewer samples):

```ini
Sample0001=2.45
Sample0002=4.12
...
```

## How It Works

1. Uses Windows API (`GetCursorPos` via P/Invoke) to poll mouse position every 50 ms
2. Calculates Euclidean distance between consecutive positions (only counts non-zero movement)
3. Accumulates total distance, sample statistics, and velocity metrics
4. In GUI mode, updates WPF controls via a `DispatcherTimer`; in console mode, updates `Write-Progress`
5. On stop/exit, writes results to an INI-style output file and updates the persistent config

## Mathematical Details

**Distance per sample (Euclidean):**

```
distance = √((x₂ - x₁)² + (y₂ - y₁)²)
```

**Unit conversions:**

```
cm  = pixels ÷ (DPI ÷ 2.54)
m   = cm ÷ 100
in  = pixels ÷ DPI
```

**Velocity:**

```
pixels/sec = TotalDistance ÷ ElapsedSeconds
cm/sec     = pixels/sec ÷ pixelsPerCm
m/sec      = pixels/sec ÷ pixelsPerMeter
```

**Average Distance per Sample:**

```
average = TotalDistance ÷ TotalSamples
```

## Example Console Output

```
═══════════════════════════════════════════
Mouse Distance Tracker
═══════════════════════════════════════════

Mode: Continuous (press Ctrl+C to stop)
DPI: 96
Output File: C:\Scripts\mouse-tracker.cfg

Move your mouse to begin tracking...
Press Ctrl+C when finished.

Tracking started at 09:45:12.003

Tracking stopped at 09:45:42.891

═══════════════════════════════════════════
   Tracking Results
═══════════════════════════════════════════

Total Distance:
  Pixels: 1847.52
  Centimeters: 48.87 cm
  Meters: 0.4887 m
  Inches: 19.25 in

Statistics:
  Total Samples: 287
  Duration: 30.89 seconds
  Average/Sample: 6.44 px
  Max/Sample: 45.32 px
  Min/Sample: 0.14 px

Velocity:
  Pixels/Second: 59.81
  CM/Second: 1.58
  Meters/Second: 0.0158

✓ Results saved to: C:\Scripts\mouse-tracker.cfg
```

## Requirements

- PowerShell 5.0 or later
- Windows OS (uses `user32.dll` and WPF)
- .NET Framework / WPF assemblies (for GUI mode; pre-installed on Windows)
- No administrator privileges required

## Performance Considerations

- **Sampling Interval**: 50 ms (20 samples per second)
- **Accuracy**: Pixel-level precision
- **CPU Impact**: Minimal (light polling via DispatcherTimer / sleep loop)
- **Sample Storage**: Limited to 500 samples in the output file to prevent bloat
- **GUI overhead**: Negligible — WPF UI updates are dispatched on the UI thread

## DPI Calibration

Accurate cm/m/inch conversions depend on the correct DPI value for your monitor.

1. Visit [https://dpi.lv/](https://dpi.lv/) and measure your real DPI
2. In the GUI, enter the value in the **DPI Settings** box and click **Update DPI**
3. Or pass it as a parameter: `.\MouseDistanceTracker.ps1 -DPI 144`

The updated DPI is saved to the persistent config file and reloaded next session.

## Troubleshooting

### Script won't run

- Check execution policy: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`
- Ensure .NET / WPF assemblies are present (standard on Windows 10/11)

### No movement detected

- Ensure you are moving the mouse during a tracking session
- Check that the mouse pointer is visible and responding
- Some remote-desktop or virtual machine configurations may interfere with `GetCursorPos`

### Output file not created

- Verify the output directory exists and you have write permissions
- Check disk space availability
- Review error messages in the console

## Use Cases

- Measure user activity levels
- Test mouse sensitivity settings
- Analyze workflow patterns
- Record interaction metrics
- Accessibility testing
- User behavior analysis

## Notes

- The script measures absolute mouse displacement, not relative velocity
- Only samples where the mouse actually moved (distance > 0) are counted toward statistics; zero-movement ticks do not increment `TotalSamples`
- Timestamps use local machine time
- The persistent config total accumulates indefinitely until manually reset (use the **Reset** button in the GUI, which clears the session but not the persisted file total)
- INI/CFG format allows easy parsing by other tools and scripts
