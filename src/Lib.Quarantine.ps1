# Lib.Quarantine.ps1 - approval, quarantine (move, never delete), review and restore.
# The tool has NO permanent-delete code path. Quarantine lives at <drive>:\WinCleanup_Quarantine
# on the SAME volume as the item, so a move is an atomic rename that preserves ACLs and timestamps.

function Get-QuarantineRootFor { param([string]$Path)
    return (Join-Path ([IO.Path]::GetPathRoot($Path)) $Script:QuarantineDirName)
}
function Get-AllQuarantineRoots {
    $roots = @()
    foreach ($d in [IO.DriveInfo]::GetDrives()) {
        if ($d.DriveType -eq 'Fixed' -and $d.IsReady) {
            $r = Join-Path $d.Name $Script:QuarantineDirName
            if (Test-Path -LiteralPath $r) { $roots += $r }
        }
    }
    return $roots
}
function Initialize-QuarantineRoot { param([string]$Root)
    if (Test-Path -LiteralPath $Root) { return $true }
    try {
        New-Item -ItemType Directory -Path $Root -Force -ErrorAction Stop | Out-Null
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        $me  = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $adm = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
        $sys = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
        foreach ($sid in @($me, $adm, $sys)) {
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        }
        Set-Acl -LiteralPath $Root -AclObject $acl
        Write-ActionLog 'INFO' "Quarantine root created with restricted ACL: $Root"
        return $true
    } catch {
        Write-Host ("Cannot create/secure quarantine folder {0}: {1}" -f $Root, $_.Exception.Message) -ForegroundColor Red
        Write-ActionLog 'ERROR' "Quarantine root failed: $Root $($_.Exception.Message)"
        return $false
    }
}

function Read-AllManifests {
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in (Get-AllQuarantineRoots)) {
        foreach ($b in (Get-ChildItem -LiteralPath $r -Directory -ErrorAction SilentlyContinue)) {
            $mp = Join-Path $b.FullName 'manifest.json'
            $m = Read-Json $mp
            if ($m) { $out.Add([pscustomobject]@{ Root = $r; BatchDir = $b.FullName; ManifestPath = $mp; Manifest = $m }) }
        }
    }
    return ,$out
}
function Save-Manifest { param($Batch)
    $Batch.Manifest.Items = @($Batch.Manifest.Items)
    Save-Json -Object $Batch.Manifest -Path $Batch.ManifestPath -Depth 6
}

function Repair-PendingQuarantine {
    # Reconcile operations that were interrupted (power loss, Ctrl+C, closed window).
    $fixed = 0
    foreach ($b in (Read-AllManifests)) {
        $dirty = $false
        foreach ($it in @($b.Manifest.Items)) {
            if ($it.Status -ne 'Pending') { continue }
            $src = Test-Path -LiteralPath $it.OriginalPath; $dst = Test-Path -LiteralPath $it.QuarantinePath
            if ($dst -and -not $src) { $it.Status = 'Moved'; $it.Note = 'Recovered after interruption: item is in quarantine.' }
            elseif ($src -and -not $dst) { $it.Status = 'Failed'; $it.Note = 'Interrupted before the move; item is still in its original place.' }
            else { $it.Status = 'Inconsistent'; $it.Note = 'Interrupted; manual check needed (both or neither location exist).' }
            $it.StatusTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            Write-ActionLog 'WARN' ("Reconciled pending quarantine item {0} -> {1}" -f $it.OriginalPath, $it.Status)
            Write-Host ("Reconciled interrupted quarantine item: {0} -> {1}" -f $it.OriginalPath, $it.Status) -ForegroundColor Yellow
            $dirty = $true; $fixed++
        }
        if ($dirty) { Save-Manifest $b }
    }
    return $fixed
}

function Get-FilesNoReparse { param([string]$Path, [int]$Max)
    $files = New-Object System.Collections.Generic.List[string]
    $st = New-Object 'System.Collections.Generic.Stack[string]'; $st.Push($Path)
    while ($st.Count -gt 0 -and $files.Count -lt $Max) {
        $d = $st.Pop()
        try {
            foreach ($e in (New-Object IO.DirectoryInfo $d).EnumerateFileSystemInfos()) {
                if ($e.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
                if ($e.Attributes -band [IO.FileAttributes]::Directory) { $st.Push($e.FullName) }
                else { $files.Add($e.FullName); if ($files.Count -ge $Max) { break } }
            }
        } catch {}
    }
    return ,$files
}

function Test-QuarantinePreflight {
    param($C)
    $fail = New-Object System.Collections.Generic.List[string]
    if ($C.Outcome -ne 'SAFE CANDIDATE') { $fail.Add("Outcome is $($C.Outcome); only SAFE CANDIDATE items may be quarantined.") }
    if ($C.Scope -ne 'Current') { $fail.Add('Item belongs to another user profile.') }
    if (-not (Test-Path -LiteralPath $C.Path)) { $fail.Add('Path no longer exists (possibly already covered by a parent that was quarantined).'); return @($fail) }
    $item = Get-Item -LiteralPath $C.Path -Force -ErrorAction SilentlyContinue
    if (-not $item) { $fail.Add('Cannot access item.'); return @($fail) }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { $fail.Add('Item is a junction/symlink.') }
    $np = ConvertTo-NormPath $C.Path
    if ((Get-QuarantineRootFor $C.Path) -and (Test-IsUnder (ConvertTo-NormPath (Get-QuarantineRootFor $C.Path)) $np)) { $fail.Add('Item would contain the quarantine folder.') }
    # Did it change since the scan?
    $Script:FileCounter = 0
    $isFile = -not ($item.Attributes -band [IO.FileAttributes]::Directory)
    $now = Get-TreeStats $C.Path $isFile (Test-LastAccessReliable)
    Write-Host ''
    if ($now.Files -ne [int]$C.Files -or [int64]$now.Size -ne [int64]$C.SizeBytes) { $fail.Add('Contents changed since the scan (file count/size differ). Re-scan first.') }
    if ($now.Newest -gt [datetime]::Parse($C.Newest).AddSeconds(2)) { $fail.Add('Item was modified/accessed after the scan. Re-scan first.') }
    if ($now.Errors -gt 0) { $fail.Add('Item could not be read completely.') }
    # Is anything running from / using it right now?
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
        try { if ($p.Path -and (Test-IsUnder (ConvertTo-NormPath $p.Path) $np)) { $fail.Add("Process $($p.ProcessName) (PID $($p.Id)) is running from this item."); continue } } catch {}
        try { foreach ($m in $p.Modules) { if (Test-IsUnder (ConvertTo-NormPath $m.FileName) $np) { $fail.Add("Process $($p.ProcessName) has loaded $($m.FileName)."); break } } } catch {}
    }
    # Locked files? (open without sharing; closed immediately; nothing is read or written)
    $targets = if ($isFile) { @($C.Path) } else { Get-FilesNoReparse $C.Path 3000 }
    $locked = 0
    foreach ($f in $targets) {
        try { $fs = [IO.File]::Open($f, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None); $fs.Dispose() }
        catch [System.IO.IOException] { $locked++ } catch { $locked++ }
    }
    if ($locked -gt 0) { $fail.Add("$locked file(s) are locked or inaccessible; locked files are never forced.") }
    $root = Get-QuarantineRootFor $C.Path
    if (($root.Length + $C.Path.Length + 40) -gt 255) { $fail.Add('Resulting quarantine path would be too long.') }
    return @($fail)
}

function Show-QuarantineApproval {
    param($C)
    Write-Host ''
    Write-Host ('-' * 78) -ForegroundColor DarkGray
    Write-Host ("#{0}  {1}" -f $C.Id, $C.Path) -ForegroundColor Green
    Write-Host ("   Size        : {0} ({1:N0} files)" -f (Format-Size ([int64]$C.SizeBytes)), $C.Files)
    Write-Host ("   Application : {0}  [{1}]" -f $C.App, $C.AppStatus)
    Write-Host ("   Last activity: {0} ({1} days ago)" -f $C.Newest, $C.ActivityDays)
    Write-Host '   Evidence:'; foreach ($r in @($C.Reasons)) { Write-Host "     + $r" }
    foreach ($r in @($C.AppEvidence | Select-Object -First 3)) { Write-Host "     . $r" -ForegroundColor Gray }
    Write-Host ("   References found: {0} (none confirmed)" -f $C.RefCount)
    if (@($C.Risks).Count -gt 0) { Write-Host '   Risks:' -ForegroundColor Yellow; foreach ($r in @($C.Risks)) { Write-Host "     ! $r" -ForegroundColor Yellow } }
    Write-Host '   Limitation: no dependency was DETECTED; that does not prove the item is unused.' -ForegroundColor Gray
}

function Invoke-QuarantineWorkflow {
    if (-not (Test-ScanLoaded)) { return }
    $age = $null; try { $age = ([datetime]::Now - [datetime]::Parse($Script:Scan.Started)).TotalHours } catch {}
    $safe = @($Script:Scan.Candidates | Where-Object { $_.Outcome -eq 'SAFE CANDIDATE' -and $_.Scope -eq 'Current' -and -not $_.Quarantined })
    Write-Title 'QUARANTINE APPROVED SAFE CANDIDATES'
    if ($safe.Count -eq 0) { Write-Host 'There are no SAFE CANDIDATE items in the current results. NEEDS REVIEW and PROTECTED items can never be quarantined by this tool.' -ForegroundColor Yellow; return }
    if ($age -ne $null -and $age -gt 24) { Write-Host ("Warning: these results are {0:N0} hours old. Each item is re-verified before moving." -f $age) -ForegroundColor Yellow }
    Write-Host 'SAFE CANDIDATES (largest first):' -ForegroundColor Cyan
    Show-CandidateList $safe
    Write-Host ''
    $sel = Read-Host 'Enter Ids to review (e.g. 1,4,7-9), or Enter to cancel'
    if (-not $sel) { Write-Host 'Cancelled. Nothing was changed.'; return }
    $ids = Resolve-IdList $sel
    $chosen = @($safe | Where-Object { $ids -contains $_.Id } | Sort-Object { $_.Path.Length })
    if ($chosen.Count -eq 0) { Write-Host 'No valid SAFE CANDIDATE ids selected.' -ForegroundColor Yellow; return }

    $approved = New-Object System.Collections.Generic.List[object]; $keptPaths = New-Object System.Collections.Generic.List[string]
    foreach ($c in $chosen) {
        $n = ConvertTo-NormPath $c.Path
        $covered = $false; foreach ($k in $keptPaths) { if (Test-IsUnder $n $k) { $covered = $true; break } }
        if ($covered) { Write-Host ("#{0} is inside an item already selected; skipped." -f $c.Id) -ForegroundColor Gray; continue }
        Show-QuarantineApproval $c
        $a = (Read-Host '   Quarantine this item? [Y]es / [N]o / [Q]uit selection').ToUpperInvariant()
        if ($a -eq 'Q') { break }
        if ($a -eq 'Y') { $approved.Add($c); $keptPaths.Add($n) }
    }
    if ($approved.Count -eq 0) { Write-Host 'Nothing approved. Nothing was changed.'; return }

    Write-Host ''
    Write-Host ("{0} item(s) approved, total {1}." -f $approved.Count, (Format-Size (Get-UniqueSize $approved))) -ForegroundColor Green
    Write-Host 'Items are MOVED (not deleted) into a protected quarantine folder on the same drive; they can be restored with option 11.' -ForegroundColor Gray
    Write-Host 'Moving does NOT free disk space. Space is only freed if you later delete the quarantine content yourself.' -ForegroundColor Gray
    if (-not (Confirm-Typed 'Proceed with quarantine' 'QUARANTINE')) { Write-Host 'Cancelled. Nothing was changed.'; return }

    $batchId = 'Q-{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), (Get-Random -Minimum 1000 -Maximum 9999)
    $results = @{ Moved = 0; Failed = 0; Bytes = [int64]0 }
    $batches = @{}   # one batch/manifest per drive root
    foreach ($c in $approved) {
        Write-Host ("`n#{0} {1}" -f $c.Id, $c.Path) -ForegroundColor Cyan
        $fails = Test-QuarantinePreflight $c
        if ($fails.Count -gt 0) {
            Write-Host '   NOT moved - left in place:' -ForegroundColor Yellow; foreach ($f in $fails) { Write-Host "     - $f" -ForegroundColor Yellow }
            Write-ActionLog 'WARN' ("Quarantine skipped #{0} {1}: {2}" -f $c.Id, $c.Path, ($fails -join ' | '))
            $results.Failed++; continue
        }
        $root = Get-QuarantineRootFor $c.Path
        if (-not (Initialize-QuarantineRoot $root)) { $results.Failed++; continue }
        if (-not $batches.ContainsKey($root)) {
            $bd = Join-Path $root $batchId; New-Item -ItemType Directory -Path $bd -Force | Out-Null
            $batches[$root] = [pscustomobject]@{ Root = $root; BatchDir = $bd; ManifestPath = (Join-Path $bd 'manifest.json')
                Manifest = [pscustomobject]@{ BatchId = $batchId; Created = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); User = $env:USERNAME; Machine = $env:COMPUTERNAME; Items = @() } }
        }
        $b = $batches[$root]
        $drive = ([IO.Path]::GetPathRoot($c.Path)).Substring(0, 1)
        $rel = $c.Path.Substring([IO.Path]::GetPathRoot($c.Path).Length)
        $dest = Join-Path (Join-Path (Join-Path $b.BatchDir 'files') $drive) $rel
        $isDir = (Get-Item -LiteralPath $c.Path -Force).PSIsContainer
        $item = [pscustomobject]@{
            ScanId = $c.Id; OriginalPath = $c.Path; QuarantinePath = $dest; IsDirectory = $isDir; SizeBytes = [int64]$c.SizeBytes; Files = $c.Files
            App = $c.App; AppStatus = $c.AppStatus; Evidence = (@($c.Reasons) -join ' | '); Status = 'Pending'
            StatusTime = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); Note = ''
        }
        $b.Manifest.Items = @($b.Manifest.Items) + @($item)
        Save-Manifest $b                       # journal BEFORE touching anything
        Write-ActionLog 'INFO' ("Quarantine START {0} -> {1}" -f $c.Path, $dest)
        try {
            New-Item -ItemType Directory -Path (Split-Path -Parent $dest) -Force -ErrorAction Stop | Out-Null
            if ($isDir) { [IO.Directory]::Move($c.Path, $dest) } else { [IO.File]::Move($c.Path, $dest) }
            $okMoved = (Test-Path -LiteralPath $dest) -and -not (Test-Path -LiteralPath $c.Path)
            if (-not $okMoved) { throw 'Verification failed: destination missing or source still present.' }
            $Script:FileCounter = 0
            $v = Get-TreeStats $dest (-not $isDir) $false; Write-Host ''
            if ($v.Files -ne [int]$c.Files -or [int64]$v.Size -ne [int64]$c.SizeBytes) { $item.Note = 'Moved, but post-move count/size differ from the scan - please inspect.' }
            $item.Status = 'Moved'; $item.StatusTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            Save-Manifest $b
            $results.Moved++; $results.Bytes += [int64]$c.SizeBytes
            $c.Quarantined = $true
            Write-Host '   Quarantined and verified.' -ForegroundColor Green
            if ($item.Note) { Write-Host "   $($item.Note)" -ForegroundColor Yellow }
            Write-ActionLog 'INFO' ("Quarantine OK {0} ({1} bytes) restore-info: manifest {2}" -f $c.Path, $c.SizeBytes, $b.ManifestPath)
        } catch {
            $item.Status = 'Failed'; $item.Note = $_.Exception.Message; $item.StatusTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            Save-Manifest $b
            $results.Failed++
            Write-Host ("   Move failed - item left in place: " + $_.Exception.Message) -ForegroundColor Yellow
            Write-ActionLog 'ERROR' ("Quarantine FAILED {0}: {1}" -f $c.Path, $_.Exception.Message)
        }
    }
    Write-Title 'QUARANTINE RESULT'
    Write-Host ("Moved: {0}   Left in place/failed: {1}   Data now in quarantine: {2}" -f $results.Moved, $results.Failed, (Format-Size $results.Bytes))
    Write-Host 'Disk space actually reclaimed so far: 0 B (items were moved, not deleted).' -ForegroundColor Yellow
    foreach ($b in $batches.Values) { Write-Host ("Batch folder / restore manifest: {0}" -f $b.BatchDir) }
    if ($results.Moved -gt 0) { try { Save-LastScan } catch {} }
    Write-Host 'Re-run a scan before further cleanup; results of this scan are now partly out of date.' -ForegroundColor Gray
}

function Show-Quarantine {
    Write-Title 'QUARANTINED ITEMS'
    $batches = Read-AllManifests
    if ($batches.Count -eq 0) { Write-Host 'Quarantine is empty (no batches found on any fixed drive).'; return }
    $n = 0; $bytes = [int64]0
    foreach ($b in $batches) {
        Write-Host ("`nBatch {0}  created {1}  ({2})" -f $b.Manifest.BatchId, $b.Manifest.Created, $b.BatchDir) -ForegroundColor Cyan
        foreach ($it in @($b.Manifest.Items)) {
            $n++
            $col = switch ($it.Status) { 'Moved' { 'Green' } 'Restored' { 'Gray' } 'Failed' { 'Yellow' } default { 'Red' } }
            Write-Host ("  [{0,-12}] {1,10}  {2}" -f $it.Status, (Format-Size ([int64]$it.SizeBytes)), $it.OriginalPath) -ForegroundColor $col
            if ($it.Note) { Write-Host ("      note: {0}" -f $it.Note) -ForegroundColor Gray }
            if ($it.Status -eq 'Moved') { $bytes += [int64]$it.SizeBytes }
        }
    }
    Write-Host ("`n{0} item(s) listed. Currently held in quarantine: {1}" -f $n, (Format-Size $bytes)) -ForegroundColor Green
    Write-Host 'Limitations: quarantine cannot guarantee a perfect application restore (registry state, permissions or related files may have changed).' -ForegroundColor Gray
    Write-Host 'This tool never permanently deletes. To free space, delete batch folders yourself after you are confident nothing is missing.' -ForegroundColor Gray
    if ((Read-Host 'Open quarantine folder(s) in Explorer? [y/N]') -match '^[yY]') { foreach ($r in (Get-AllQuarantineRoots)) { Start-Process explorer.exe -ArgumentList ('"{0}"' -f $r) } }
}

function Invoke-Restore {
    Write-Title 'RESTORE QUARANTINED ITEMS'
    $rows = New-Object System.Collections.Generic.List[object]; $i = 0
    foreach ($b in (Read-AllManifests)) { foreach ($it in @($b.Manifest.Items)) { if ($it.Status -eq 'Moved') { $i++; $rows.Add([pscustomobject]@{ N = $i; Batch = $b; Item = $it }) } } }
    if ($rows.Count -eq 0) { Write-Host 'Nothing to restore.'; return }
    foreach ($r in $rows) { Write-Host ("{0,4}  {1,10}  {2}   (batch {3})" -f $r.N, (Format-Size ([int64]$r.Item.SizeBytes)), $r.Item.OriginalPath, $r.Batch.Manifest.BatchId) }
    $sel = Read-Host "`nEnter numbers to restore (e.g. 1,3-4), or Enter to cancel"
    if (-not $sel) { Write-Host 'Cancelled.'; return }
    foreach ($n in (Resolve-IdList $sel)) {
        $r = $rows | Where-Object { $_.N -eq $n } | Select-Object -First 1
        if (-not $r) { continue }
        $it = $r.Item; $orig = $it.OriginalPath
        Write-Host ("`nRestoring {0}" -f $orig) -ForegroundColor Cyan
        try {
            if (-not (Test-Path -LiteralPath $it.QuarantinePath)) { throw 'Quarantined data not found at its recorded location.' }
            $target = $orig
            if (Test-Path -LiteralPath $orig) {
                Write-Host '   Something already exists at the original location (possibly newer data).' -ForegroundColor Yellow
                $a = (Read-Host '   [R]estore beside it under a new name / [S]kip (nothing is overwritten)').ToUpperInvariant()
                if ($a -ne 'R') { Write-Host '   Skipped.'; continue }
                $target = '{0}.restored-{1}' -f $orig, (Get-Date -Format 'yyyyMMdd-HHmmss')
            }
            $parent = Split-Path -Parent $target
            if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null }
            Write-ActionLog 'INFO' ("Restore START {0} -> {1}" -f $it.QuarantinePath, $target)
            if ($it.IsDirectory) { [IO.Directory]::Move($it.QuarantinePath, $target) } else { [IO.File]::Move($it.QuarantinePath, $target) }
            if (-not (Test-Path -LiteralPath $target)) { throw 'Verification failed after restore.' }
            $it.Status = 'Restored'; $it.StatusTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; $it.Note = "Restored to $target"
            Save-Manifest $r.Batch
            Write-Host "   Restored to: $target" -ForegroundColor Green
            Write-ActionLog 'INFO' ("Restore OK {0}" -f $target)
        } catch {
            Write-Host ("   Restore failed: " + $_.Exception.Message) -ForegroundColor Red
            Write-ActionLog 'ERROR' ("Restore FAILED {0}: {1}" -f $orig, $_.Exception.Message)
        }
    }
}
