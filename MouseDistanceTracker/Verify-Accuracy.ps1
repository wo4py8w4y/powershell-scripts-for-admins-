# Quick accuracy verification script
# This simulates a known pixel distance and shows what it converts to

param(
    [int]$DPI = 170
)

Write-Host '═══════════════════════════════════════════' -ForegroundColor Cyan
Write-Host '   Accuracy Verification Test' -ForegroundColor Cyan
Write-Host '═══════════════════════════════════════════' -ForegroundColor Cyan
Write-Host ''

# Calculate conversion factors (same as main script)
$pixelsPerInch = $DPI
$pixelsPerCm = $pixelsPerInch / 2.54
$pixelsPerMeter = $pixelsPerCm * 100

Write-Host "DPI: $DPI" -ForegroundColor Yellow
Write-Host "Pixels per cm: $([Math]::Round($pixelsPerCm, 2))" -ForegroundColor Yellow
Write-Host ''

# Test with actual pixel distances you might see
$testDistances = @(
    @{ Pixels = 650; Description = 'Across a 650px window' }
    @{ Pixels = 1000; Description = '1000 pixels' }
    @{ Pixels = 5000; Description = '5000 pixels' }
    @{ Pixels = 30261.12; Description = 'Your current total from screenshot' }
)

Write-Host 'Expected Conversions:' -ForegroundColor Green
Write-Host '═══════════════════════════════════════════' -ForegroundColor Gray

foreach ($test in $testDistances)
{
    $pixels = $test.Pixels
    $cm = $pixels / $pixelsPerCm
    $meters = $cm / 100
    $inches = $pixels / $pixelsPerInch
    
    Write-Host ''
    Write-Host "$($test.Description):" -ForegroundColor White
    Write-Host "  $([Math]::Round($pixels, 2)) px" -ForegroundColor Cyan
    Write-Host "  = $([Math]::Round($cm, 2)) cm" -ForegroundColor Cyan
    Write-Host "  = $([Math]::Round($meters, 4)) m" -ForegroundColor Cyan
    Write-Host "  = $([Math]::Round($inches, 2)) inches" -ForegroundColor Cyan
}

Write-Host ''
Write-Host '═══════════════════════════════════════════' -ForegroundColor Gray
Write-Host 'Physical Reference:' -ForegroundColor Yellow
Write-Host '  10 cm (width of credit card) = ~669 pixels' -ForegroundColor White
Write-Host '  1 meter = ~6693 pixels' -ForegroundColor White
Write-Host '  1 inch = 170 pixels' -ForegroundColor White
Write-Host ''
Write-Host 'To verify: Move your mouse exactly 10cm on screen' -ForegroundColor Green
Write-Host 'The tracker should show approximately 669 pixels' -ForegroundColor Green
Write-Host ''
