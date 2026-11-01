# Lib.Report.ps1 - on-screen results, per-candidate dependency reports, TXT/CSV export.

function Get-CandidateReportLines {
    param($C)
    $L = New-Object System.Collections.Generic.List[string]
    $L.Add(("Candidate #{0}   OUTCOME: {1}" -f $C.Id, $C.Outcome))
    $L.Add(("  Path            : {0}" -f $C.Path))
    $L.Add(("  Type / category : {0} / {1}   (root: {2}, scope: {3})" -f $C.Kind, $C.Category, $C.Root, $C.Scope))
    $L.Add(("  Size            : {0}  ({1:N0} files, {2:N0} folders)" -f (Format-Size ([int64]$C.SizeBytes)), $C.Files, $C.Dirs))
    $L.Add(("  Application     : {0}   Status: {1}" -f $C.App, $C.AppStatus))
    foreach ($e in @($C.AppEvidence)) { $L.Add("      app evidence: $e") }
    $L.Add(("  Activity        : newest {0} ({1} days ago), oldest write {2}; timestamps reliable: {3}" -f $C.Newest, $C.ActivityDays, $C.Oldest, $C.TimestampReliable))
    $L.Add('  Reasons for classification:')
    foreach ($r in @($C.Reasons)) { $L.Add("      - $r") }
    $fl = @($C.FindingSummary)
    if ($fl.Count -gt 0) { $L.Add('  Content findings:'); foreach ($f in $fl) { $L.Add("      * $f") } }
    $L.Add(("  References found: {0}" -f $C.RefCount))
    foreach ($r in $C.Refs) { $L.Add(("      [{0}/{1}] {2} -> {3}" -f $r.Strength, $r.Type, $r.Source, $r.Detail)) }
    if (@($C.Risks).Count -gt 0) { $L.Add('  Risks:'); foreach ($r in @($C.Risks)) { $L.Add("      ! $r") } }
    $L.Add(("  Investigation complete: {0}" -f $C.InvestigationComplete))
    foreach ($m in @($C.IncompleteChecks)) { $L.Add("      not done/partial: $m") }
    $L.Add('  Limitations:')
    foreach ($m in @($C.Limitations)) { $L.Add("      ~ $m") }
    $L.Add(("  Confidence      : {0}" -f $C.Confidence))
    return @($L)
}

function Show-CandidateReport {
    param([int]$Id)
    $c = @($Script:Scan.Candidates | Where-Object { $_.Id -eq $Id }) | Select-Object -First 1
    if (-not $c) { Write-Host "No candidate with id $Id." -ForegroundColor Yellow; return }
    Write-Title ("DEPENDENCY REPORT - candidate #{0}" -f $Id)
    $col = Get-OutcomeColor $c.Outcome
    foreach ($line in (Get-CandidateReportLines $c)) { Write-Host $line -ForegroundColor $(if ($line -like 'Candidate #*') { $col } else { 'Gray' }) }
}

function Show-CandidateList {
    param($Items, [int]$PageSize = 25)
    $arr = @($Items | Sort-Object -Property @{Expression = 'SizeBytes'; Descending = $true})
    if ($arr.Count -eq 0) { Write-Host '  (none)'; return }
    $i = 0
    foreach ($c in $arr) {
        $i++
        $col = Get-OutcomeColor $c.Outcome
        $app = if ($c.App.Length -gt 22) { $c.App.Substring(0, 22) } else { $c.App }
        Write-Host ('{0,5} {1,10}  {2,-17} {3,-22} {4}' -f $c.Id, (Format-Size ([int64]$c.SizeBytes)), $c.Category, $app, $c.Path) -ForegroundColor $col
        if (($i % $PageSize) -eq 0 -and $i -lt $arr.Count) {
            $a = Read-Host ("  -- {0}/{1} shown. Enter = next page, q = stop" -f $i, $arr.Count)
            if ($a -eq 'q') { break }
        }
    }
}

function Test-ScanLoaded {
    if (-not $Script:Scan) {
        Write-Host 'No scan results available. Run a scan first (options 1-5).' -ForegroundColor Yellow; return $false
    }
    return $true
}

function Show-ResultsByOutcome {
    if (-not (Test-ScanLoaded)) { return }
    $s = $Script:Scan
    Write-Title ("RESULTS - scan '{0}' started {1}" -f $s.Mode, $s.Started)
    $cands = @($s.Candidates)
    $t = Get-ScanTotals $cands
    Write-Host ("[S] SAFE CANDIDATE {0,5}  {1}" -f $t.Safe.Count, (Format-Size $t.Safe.Bytes)) -ForegroundColor Green
    Write-Host ("[R] NEEDS REVIEW   {0,5}  {1}" -f $t.Review.Count, (Format-Size $t.Review.Bytes)) -ForegroundColor Yellow
    Write-Host ("[P] PROTECTED      {0,5}  {1}" -f $t.Protected.Count, (Format-Size $t.Protected.Bytes)) -ForegroundColor Red
    $a = (Read-Host 'List which group? [S]afe / [R]eview / [P]rotected / [A]ll / Enter = back').ToUpperInvariant()
    $map = @{ 'S' = 'SAFE CANDIDATE'; 'R' = 'NEEDS REVIEW'; 'P' = 'PROTECTED' }
    if ($map.ContainsKey($a)) {
        Write-Host ("`n{0} (largest first)   Id        Size  Category          Application            Path" -f $map[$a]) -ForegroundColor Cyan
        Show-CandidateList ($cands | Where-Object { $_.Outcome -eq $map[$a] })
    } elseif ($a -eq 'A') {
        foreach ($o in @('SAFE CANDIDATE', 'NEEDS REVIEW', 'PROTECTED')) {
            Write-Host ("`n{0}" -f $o) -ForegroundColor Cyan
            Show-CandidateList ($cands | Where-Object { $_.Outcome -eq $o })
        }
    }
    Write-Host "`nUse option 7 to see the full dependency report for any Id." -ForegroundColor Gray
}

function Get-QuarantineTotals {
    $moved = [int64]0; $n = 0
    foreach ($b in (Read-AllManifests)) { foreach ($it in @($b.Manifest.Items)) { if ($it.Status -eq 'Moved') { $moved += [int64]$it.SizeBytes; $n++ } } }
    return [pscustomobject]@{ Items = $n; Bytes = $moved }
}

function Export-ScanReport {
    if (-not (Test-ScanLoaded)) { return }
    $s = $Script:Scan; $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $txt = Join-Path $Script:Dirs.Reports ("WinCleanup_Report_{0}.txt" -f $stamp)
    $csv = Join-Path $Script:Dirs.Reports ("WinCleanup_Report_{0}.csv" -f $stamp)
    $cands = @($s.Candidates); $t = Get-ScanTotals $cands; $q = Get-QuarantineTotals
    $L = New-Object System.Collections.Generic.List[string]
    $L.Add($Script:AppName + ' v' + $Script:AppVersion); $L.Add(('=' * 78))
    $L.Add("Report generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $L.Add("Scan mode        : $($s.Mode)   started $($s.Started)   finished $($s.Finished)")
    $L.Add("Windows          : $($s.OS)")
    $L.Add("User / elevated  : $($s.User) / $($s.IsAdmin)")
    $L.Add("Last-access times reliable: $($s.LastAccessReliable)")
    $L.Add(("Settings         : InactiveDays={0} TempAgeDays={1} UninstalledRecentDays={2} RegistryMode={3} ScanAllProfiles={4}" -f $s.Settings.InactiveDays, $s.Settings.TempAgeDays, $s.Settings.UninstalledRecentDays, $s.Settings.RegistryMode, $s.Settings.ScanAllProfiles))
    $L.Add(''); $L.Add('LOCATIONS SCANNED'); foreach ($r in @($s.Roots)) { $L.Add("  $r") }
    $L.Add(''); $L.Add(("LOCATIONS / ITEMS SKIPPED ({0})" -f @($s.Skipped).Count))
    foreach ($k in @($s.Skipped)) { $L.Add(("  {0}  --  {1}" -f $k.Path, $k.Reason)) }
    $L.Add(''); $L.Add('TOTALS')
    $L.Add(("  Files examined: {0:N0}   Folders examined: {1:N0}   Not selected (active/below threshold): {2}" -f $s.ExaminedFiles, $s.ExaminedDirs, $s.NotSelected))
    $L.Add(("  SAFE CANDIDATE : {0,5}  potential size {1}" -f $t.Safe.Count, (Format-Size $t.Safe.Bytes)))
    $L.Add(("  NEEDS REVIEW   : {0,5}  size {1}" -f $t.Review.Count, (Format-Size $t.Review.Bytes)))
    $L.Add(("  PROTECTED      : {0,5}  size {1}" -f $t.Protected.Count, (Format-Size $t.Protected.Bytes)))
    $L.Add("  (Nested items are counted once. 'Potential size' is NOT space reclaimed.)")
    $L.Add(("  Actual data currently held in quarantine: {0} in {1} item(s). Quarantine MOVES data on the same volume, so free disk space does not increase until you manually delete quarantine content." -f (Format-Size $q.Bytes), $q.Items))
    $L.Add(''); $L.Add('INVESTIGATION CHECKS (global)')
    foreach ($g in $s.GlobalChecks) { $L.Add(("  [{0,-7}] {1} {2}" -f $g.Status, $g.Name, $g.Detail)) }
    if ($s.InventoryCounts) { $L.Add('  Inventory counts: ' + (($s.InventoryCounts.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ', ')) }
    foreach ($f in @($s.InventoryFailures)) { $L.Add("  Inventory failure: $f") }
    $L.Add(''); $L.Add(("ERRORS ({0})" -f @($s.Errors).Count)); foreach ($e in @($s.Errors)) { $L.Add("  $e") }
    foreach ($o in @('SAFE CANDIDATE', 'NEEDS REVIEW', 'PROTECTED')) {
        $grp = @($cands | Where-Object { $_.Outcome -eq $o } | Sort-Object -Property @{Expression = 'SizeBytes'; Descending = $true})
        $L.Add(''); $L.Add(('#' * 78)); $L.Add(("{0}  ({1})" -f $o, $grp.Count)); $L.Add(('#' * 78))
        foreach ($c in $grp) { $L.Add(''); foreach ($line in (Get-CandidateReportLines $c)) { $L.Add($line) } }
    }
    $L.Add(''); $L.Add('This report describes the checks that were performed. It does not prove that any file is unused.')
    try {
        $L | Set-Content -LiteralPath $txt -Encoding UTF8
        $cands | ForEach-Object {
            [pscustomobject]@{
                Id = $_.Id; Outcome = $_.Outcome; Path = $_.Path; Category = $_.Category; Application = $_.App; AppStatus = $_.AppStatus
                SizeBytes = $_.SizeBytes; Files = $_.Files; Folders = $_.Dirs; NewestActivity = $_.Newest; InactiveDays = $_.ActivityDays
                References = $_.RefCount; Reasons = (@($_.Reasons) -join ' | '); Risks = (@($_.Risks) -join ' | ')
                InvestigationComplete = $_.InvestigationComplete; Limitations = (@($_.Limitations) -join ' | ')
            }
        } | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
        Write-Host "Report written:" -ForegroundColor Green; Write-Host "  $txt"; Write-Host "  $csv"
        Write-ActionLog 'INFO' "Report exported: $txt"
    } catch { Write-Host ("Could not write report: " + $_.Exception.Message) -ForegroundColor Red; Add-ScanError 'Report' $_.Exception.Message }
}
