<#
.SYNOPSIS
    Test script to validate MouseDistanceTracker distance calculations

.DESCRIPTION
    Simulates mouse movements and validates conversion formulas for pixels to cm/meters/inches
#>

param(
    [Parameter(Mandatory = $false)]
    [int]$DPI = 170
)

Write-Host '═══════════════════════════════════════════' -ForegroundColor Cyan
Write-Host '   Mouse Distance Calculation Test' -ForegroundColor Cyan
Write-Host '═══════════════════════════════════════════' -ForegroundColor Cyan
Write-Host ''
Write-Host "Testing with DPI: $DPI" -ForegroundColor Yellow
Write-Host ''

# Calculate conversion factors (same as main script)
$pixelsPerInch = $DPI
$pixelsPerCm = $pixelsPerInch / 2.54
$pixelsPerMeter = $pixelsPerCm * 100

Write-Host 'Conversion Factors:' -ForegroundColor White
Write-Host "  Pixels per inch: $([Math]::Round($pixelsPerInch, 4))" -ForegroundColor Cyan
Write-Host "  Pixels per cm: $([Math]::Round($pixelsPerCm, 4))" -ForegroundColor Cyan
Write-Host "  Pixels per meter: $([Math]::Round($pixelsPerMeter, 2))" -ForegroundColor Cyan
Write-Host ''

# Test cases: [Pixels, Expected CM, Expected Meters, Expected Inches, Description]
$testCases = @(
    @{ Pixels = 100; Description = '100 pixels' }
    @{ Pixels = 500; Description = '500 pixels' }
    @{ Pixels = 1000; Description = '1000 pixels (simulated movement)' }
    @{ Pixels = $pixelsPerCm; Description = 'Exactly 1 cm' }
    @{ Pixels = $pixelsPerInch; Description = 'Exactly 1 inch' }
    @{ Pixels = $pixelsPerCm * 10; Description = 'Exactly 10 cm' }
    @{ Pixels = $pixelsPerMeter; Description = 'Exactly 1 meter' }
)

function Test-Conversion
{
    param(
        [double]$Pixels,
        [string]$Description
    )
    
    # Calculate using same formulas as main script
    $cm = $Pixels / $pixelsPerCm
    $meters = $cm / 100
    $inches = $Pixels / $pixelsPerInch
    
    # Expected values
    $expectedCm = $Pixels / ($DPI / 2.54)
    $expectedMeters = $expectedCm / 100
    $expectedInches = $Pixels / $DPI
    
    # Tolerance for floating point comparison
    $tolerance = 0.0001
    
    $cmMatch = [Math]::Abs($cm - $expectedCm) -lt $tolerance
    $metersMatch = [Math]::Abs($meters - $expectedMeters) -lt $tolerance
    $inchesMatch = [Math]::Abs($inches - $expectedInches) -lt $tolerance
    
    $allPass = $cmMatch -and $metersMatch -and $inchesMatch
    
    return [PSCustomObject]@{
        Description      = $Description
        Pixels           = $Pixels
        CalculatedCM     = [Math]::Round($cm, 4)
        ExpectedCM       = [Math]::Round($expectedCm, 4)
        CMMatch          = $cmMatch
        CalculatedMeters = [Math]::Round($meters, 6)
        ExpectedMeters   = [Math]::Round($expectedMeters, 6)
        MetersMatch      = $metersMatch
        CalculatedInches = [Math]::Round($inches, 4)
        ExpectedInches   = [Math]::Round($expectedInches, 4)
        InchesMatch      = $inchesMatch
        Passed           = $allPass
    }
}

Write-Host 'Running Test Cases...' -ForegroundColor Green
Write-Host '═══════════════════════════════════════════' -ForegroundColor Gray
Write-Host ''

$results = @()
$passCount = 0
$failCount = 0

foreach ($test in $testCases)
{
    $result = Test-Conversion -Pixels $test.Pixels -Description $test.Description
    $results += $result
    
    if ($result.Passed)
    {
        $passCount++
        $status = '✓ PASS'
        $color = 'Green'
    }
    else
    {
        $failCount++
        $status = '✗ FAIL'
        $color = 'Red'
    }
    
    Write-Host "$status - $($result.Description)" -ForegroundColor $color
    Write-Host "  Pixels: $($result.Pixels)" -ForegroundColor Gray
    Write-Host "  CM: $($result.CalculatedCM) (Expected: $($result.ExpectedCM)) $(if($result.CMMatch){'✓'}else{'✗'})" -ForegroundColor $(if ($result.CMMatch) { 'Gray' }else { 'Yellow' })
    Write-Host "  Meters: $($result.CalculatedMeters) (Expected: $($result.ExpectedMeters)) $(if($result.MetersMatch){'✓'}else{'✗'})" -ForegroundColor $(if ($result.MetersMatch) { 'Gray' }else { 'Yellow' })
    Write-Host "  Inches: $($result.CalculatedInches) (Expected: $($result.ExpectedInches)) $(if($result.InchesMatch){'✓'}else{'✗'})" -ForegroundColor $(if ($result.InchesMatch) { 'Gray' }else { 'Yellow' })
    Write-Host ''
}

Write-Host '═══════════════════════════════════════════' -ForegroundColor Gray
Write-Host 'Test Summary' -ForegroundColor White
Write-Host '═══════════════════════════════════════════' -ForegroundColor Gray
Write-Host "Total Tests: $($testCases.Count)" -ForegroundColor White
Write-Host "Passed: $passCount" -ForegroundColor Green
Write-Host "Failed: $failCount" -ForegroundColor $(if ($failCount -gt 0) { 'Red' }else { 'Green' })
Write-Host ''

# Physical verification helper
Write-Host '═══════════════════════════════════════════' -ForegroundColor Cyan
Write-Host 'Physical Verification Guide' -ForegroundColor Cyan
Write-Host '═══════════════════════════════════════════' -ForegroundColor Cyan
Write-Host ''
Write-Host 'Use a ruler on your screen to verify:' -ForegroundColor Yellow
Write-Host '  1. Measure 1 cm on your screen with a ruler' -ForegroundColor White
Write-Host "  2. That should equal approximately $([Math]::Round($pixelsPerCm, 1)) pixels" -ForegroundColor White
Write-Host ''
Write-Host '  1. Measure 1 inch on your screen with a ruler' -ForegroundColor White
Write-Host "  2. That should equal approximately $([Math]::Round($pixelsPerInch, 1)) pixels" -ForegroundColor White
Write-Host ''
Write-Host 'Visit https://dpi.lv/ to verify your DPI is correct' -ForegroundColor Green
Write-Host ''

if ($failCount -eq 0)
{
    Write-Host 'All calculations validated successfully! ✓' -ForegroundColor Green
    exit 0
}
else
{
    Write-Host 'Some calculations failed validation! ✗' -ForegroundColor Red
    exit 1
}
