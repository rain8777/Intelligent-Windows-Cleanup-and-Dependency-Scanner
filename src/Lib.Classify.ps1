# Lib.Classify.ps1 - mandatory three-outcome classification.
# Order: PROTECTED (confirmed dependency / important data) > NEEDS REVIEW (incomplete/conflicting) > SAFE CANDIDATE.

function Get-FindingSeverity {
    param([string]$Kind, [string]$Category, [string]$DispKind, [string]$AppStatus)
    $disp = [bool]$DispKind -and ($Category -ne 'TempRoot'); $temp = ($Category -eq 'TempRoot')
    $installed = @('ConfirmedInstalled', 'ProbablyInstalled') -contains $AppStatus
    switch ($Kind) {
        { $_ -in @('Credential', 'Mail', 'VirtualDisk') } { return 'Protect' }
        { $_ -in @('Backup', 'SaveData', 'UserDocument', 'Database') } { if ($disp -or $temp) { return 'Review' } else { return 'Protect' } }
        'UserData' { if ($disp) { return 'Ignore' } elseif ($temp) { return 'Review' } else { return 'Protect' } }
        'SharedComponent' { if ($disp -or $temp) { return 'Ignore' } elseif ($installed) { return 'Protect' } else { return 'Review' } }
        'Config' { if ($disp -or $temp) { return 'Ignore' } elseif ($installed) { return 'Protect' } elseif ($AppStatus -eq 'ConfirmedUninstalled') { return 'Info' } else { return 'Review' } }
        { $_ -in @('Executable', 'Script') } {
            if ($temp) { return 'Ignore' }
            if ($disp) { if ($DispKind -eq 'Update') { return 'Review' } else { return 'Ignore' } }
            if ($AppStatus -eq 'ConfirmedUninstalled') { return 'Info' }
            return 'Review'
        }
        'Shortcut' { if ($disp -or $temp) { return 'Ignore' } else { return 'Review' } }
        default { return 'Review' }
    }
}

function Get-FindingText {
    param($Cand)
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($k in ($Cand.KindCounts.Keys | Sort-Object)) {
        $sev = Get-FindingSeverity $k $Cand.Category $Cand.DisposableKind $Cand.AppStatus
        if ($sev -eq 'Ignore') { continue }
        $smp = ''
        if ($Cand.Samples.ContainsKey($k)) { $smp = ' e.g. ' + ((@($Cand.Samples[$k]) | Select-Object -First 2) -join ' | ') }
        $lines.Add(("{0} x{1} [{2}]{3}" -f $k, $Cand.KindCounts[$k], $sev, $smp))
    }
    return @($lines)
}

function Set-Classification {
    param($C, $Inv)
    $protect = New-Object System.Collections.Generic.List[string]
    $review  = New-Object System.Collections.Generic.List[string]
    $risks   = New-Object System.Collections.Generic.List[string]
    $limits  = New-Object System.Collections.Generic.List[string]

    # ---- confirmed dependencies
    foreach ($r in $C.Refs) {
        if ($r.Strength -eq 'Confirmed') { $protect.Add(("Confirmed dependency [{0}] {1} -> {2}" -f $r.Type, $r.Source, $r.Detail)) }
    }
    if ($C.RefCount -gt $C.Refs.Count) { $limits.Add(("{0} additional reference(s) were found but not stored." -f ($C.RefCount - $C.Refs.Count))) }
    foreach ($r in $C.Refs) {
        if ($r.Strength -eq 'Direct') { $review.Add(("Direct reference (unresolved) [{0}] {1} -> {2}" -f $r.Type, $r.Source, $r.Detail)) }
        elseif ($r.Strength -eq 'Self') { $risks.Add(("Own-application reference [{0}] {1}" -f $r.Type, $r.Source)) }
    }
    # ---- important data / shared components
    foreach ($k in $C.KindCounts.Keys) {
        $sev = Get-FindingSeverity $k $C.Category $C.DisposableKind $C.AppStatus
        $txt = "{0} x{1}" -f $k, $C.KindCounts[$k]
        if ($C.Samples.ContainsKey($k)) { $txt += ' (e.g. ' + ((@($C.Samples[$k]) | Select-Object -First 2) -join ' | ') + ')' }
        switch ($sev) {
            'Protect' { $protect.Add("Contains important data or components: $txt") }
            'Review'  { $review.Add("Contains items that cannot be ruled out as important: $txt") }
            'Info'    { $risks.Add("Contains $txt - acceptable only because the application is confirmed uninstalled; reinstalling may need it.") }
        }
    }
    # ---- investigation completeness
    $incomplete = New-Object System.Collections.Generic.List[string]
    foreach ($g in $Script:Scan.GlobalChecks) {
        if ($g.Status -eq 'Done') { continue }
        if ($g.Name -in @('Loaded modules', 'Cache folder search')) { $limits.Add(("{0} partial: {1}" -f $g.Name, $g.Detail)) }
        else { $incomplete.Add(("{0}: {1} {2}" -f $g.Name, $g.Status, $g.Detail)) }
    }
    if ($C.StatErrors -gt 0) {
        $errTxt = (@($C.StatErrorSamples) | Select-Object -First 2) -join ' | '
        $incomplete.Add(("Candidate could not be fully read ({0} error(s)): {1}" -f $C.StatErrors, $errTxt))
    }
    if ($C.ReparseSkipped -gt 0) { $limits.Add(("{0} junction/symlink(s) inside were not followed." -f $C.ReparseSkipped)) }
    if (-not $C.TimestampReliable) { $incomplete.Add('Timestamps look unreliable (future or pre-1980 dates).') }
    $limits.Add('Activity is judged from write/creation times; last-access time is not used (unreliable, altered by scanners).')
    $limits.Add('Absence of references is not proof of absence of dependencies: paths built dynamically, 8.3 short names and rarely used features cannot be detected.')
    if ($C.Scope -ne 'Current') { $incomplete.Add("Profile '$($C.Scope)': that user's registry hive and per-user state were not inspected.") }
    $C.InvestigationComplete = ($incomplete.Count -eq 0)
    $C.IncompleteChecks = @($incomplete)
    foreach ($m in $incomplete) { $review.Add("Investigation incomplete: $m") }

    # ---- positive rules required for SAFE
    $pos = New-Object System.Collections.Generic.List[string]
    $inst = @('ConfirmedInstalled', 'ProbablyInstalled') -contains $C.AppStatus
    switch ($C.Category) {
        'Leftover' {
            if ($C.AppStatus -eq 'ConfirmedUninstalled') { $pos.Add('Application confirmed uninstalled by multiple absence checks plus positive uninstall residue (or user rule).') }
            else { $review.Add("Application is only '$($C.AppStatus)' - uninstall is not confirmed.") }
        }
        'InstalledInactive' {
            $review.Add('Data folder of an installed application: it is never auto-qualified as disposable. Review manually or look at its cache/log sub-folders.')
        }
        'CacheSub' {
            if ($C.AppStatus -eq 'Unknown' -or $C.AppStatus -eq 'NeedStats') { $review.Add('Owning application could not be identified.') }
            elseif ($C.ActivityDays -ge [int]$Script:Settings.InactiveDays) { $pos.Add(("Recognized {0} folder, no activity for {1} days, owning application status: {2}." -f $C.DisposableKind, $C.ActivityDays, $C.AppStatus)) }
            else { $review.Add('Below the inactivity threshold.') }
        }
        'TempRoot' {
            if ($C.ActivityDays -ge [int]$Script:Settings.TempAgeDays) { $pos.Add(("Item in a recognized temporary folder, untouched for {0} days." -f $C.ActivityDays)) }
            else { $review.Add('Below the temp-age threshold.') }
        }
        default { $review.Add("Application association is uncertain ($($C.AppStatus)); uncertainty is never proof that the files are unnecessary.") }
    }
    if ($Script:Settings.RegistryMode -eq 'Quick') { $review.Add('Registry search ran in Quick mode; SAFE is not possible.') }

    # ---- decide
    if ($protect.Count -gt 0) {
        $C.Outcome = 'PROTECTED'; $C.Reasons = @($protect) + @($review | Select-Object -First 3)
        $C.Confidence = 'High - dependency or important-data evidence was found.'
    } elseif ($review.Count -gt 0) {
        $C.Outcome = 'NEEDS REVIEW'; $C.Reasons = @($review)
        $C.Confidence = 'Low - evidence is incomplete, conflicting or insufficient; retained for manual review.'
    } else {
        $C.Outcome = 'SAFE CANDIDATE'; $C.Reasons = @($pos)
        $C.Confidence = 'Moderate - no dependency was found by the checks performed; this is not proof the files are unused.'
    }
    $C.FindingSummary = Get-FindingText $C
    $C.Risks = @($risks); $C.Limitations = @($limits | Select-Object -Unique)
}
