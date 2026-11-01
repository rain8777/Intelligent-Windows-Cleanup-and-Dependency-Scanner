# Main.ps1 - interactive menu. Default mode is scan-only; nothing changes unless you use option 9 or 11.
$ErrorActionPreference = 'Continue'
if ($PSVersionTable.PSVersion.Major -lt 5) { Write-Host 'Windows PowerShell 5.1 or newer is required.'; exit 2 }
foreach ($f in 'Lib.Common', 'Lib.Apps', 'Lib.Deps', 'Lib.Scan', 'Lib.Classify', 'Lib.Report', 'Lib.Quarantine') {
    . (Join-Path $PSScriptRoot ($f + '.ps1'))
}
Initialize-Environment
Restore-LastScan
$pending = Repair-PendingQuarantine

function Show-Menu {
    Write-Title ("{0}  v{1}" -f $Script:AppName, $Script:AppVersion)
    $adm = if ($Script:IsAdmin) { 'Administrator' } else { 'standard user (limited: some locations/keys unreadable)' }
    Write-Host ("Windows : {0}" -f $Script:OsCaption)
    Write-Host ("Running : {0}   Mode: SCAN-ONLY unless you choose 9 or 11" -f $adm)
    if ($Script:Scan -and $Script:Scan.Started) {
        $t = $Script:Scan.Totals
        Write-Host ("Last scan: {0} '{1}'  safe={2} review={3} protected={4}" -f $Script:Scan.Started, $Script:Scan.Mode, $t.Safe.Count, $t.Review.Count, $t.Protected.Count) -ForegroundColor Gray
    } else { Write-Host 'No scan results yet.' -ForegroundColor Gray }
    Write-Host ''
    Write-Host '  1. Scan all supported locations'
    Write-Host '  2. Scan potential leftovers from uninstalled applications'
    Write-Host ('  3. Scan files of installed applications inactive for more than {0} days' -f $Script:Settings.InactiveDays)
    Write-Host '  4. Scan uncertain application data and investigate dependencies'
    Write-Host '  5. Scan recognized temporary and cache files'
    Write-Host '  6. View detailed results grouped by outcome'
    Write-Host '  7. View an individual candidate''s dependency report'
    Write-Host '  8. Export a scan report (.txt and .csv)'
    Write-Host '  9. Select and quarantine approved SAFE CANDIDATE items'
    Write-Host ' 10. Review quarantined files'
    Write-Host ' 11. Restore quarantined files'
    Write-Host ' 12. Exit'
    Write-Host ''
}

function Start-ScanSafely { param([string]$Mode)
    if (-not $Script:IsAdmin) { Write-Host 'Tip: without administrator rights some locations/registry keys are unreadable; affected items become NEEDS REVIEW.' -ForegroundColor Yellow }
    try { Invoke-Scan -Mode $Mode } catch { Write-Host ("Scan aborted: " + $_.Exception.Message) -ForegroundColor Red; Write-ActionLog 'ERROR' ("Scan aborted: " + $_.Exception.ToString()) }
}

if ($pending -gt 0) { Wait-Key }
while ($true) {
    Show-Menu
    $choice = Read-Host 'Select an option (1-12)'
    switch ($choice.Trim()) {
        '1'  { Start-ScanSafely 'All';               Wait-Key }
        '2'  { Start-ScanSafely 'Leftovers';         Wait-Key }
        '3'  { Start-ScanSafely 'InstalledInactive'; Wait-Key }
        '4'  { Start-ScanSafely 'Uncertain';         Wait-Key }
        '5'  { Start-ScanSafely 'TempCache';         Wait-Key }
        '6'  { Show-ResultsByOutcome; Wait-Key }
        '7'  { if (Test-ScanLoaded) { $id = Read-Host 'Candidate Id'; if ($id -match '^\d+$') { Show-CandidateReport ([int]$id) } else { Write-Host 'Enter a number.' } }; Wait-Key }
        '8'  { Export-ScanReport; Wait-Key }
        '9'  { Invoke-QuarantineWorkflow; Wait-Key }
        '10' { Show-Quarantine; Wait-Key }
        '11' { Invoke-Restore; Wait-Key }
        '12' { Write-ActionLog 'INFO' 'Session ended'; exit 0 }
        default { Write-Host 'Please enter a number from 1 to 12.' -ForegroundColor Yellow }
    }
}
