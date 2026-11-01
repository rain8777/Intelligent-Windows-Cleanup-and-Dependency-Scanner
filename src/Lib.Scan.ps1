# Lib.Scan.ps1 - candidate discovery and metadata collection. Strictly read-only.

$Script:ExtKind = @{
    '.kdbx'='Credential'; '.pfx'='Credential'; '.p12'='Credential'; '.pem'='Credential'; '.key'='Credential'; '.ppk'='Credential'
    '.gpg'='Credential'; '.jks'='Credential'; '.keystore'='Credential'; '.wallet'='Credential'
    '.db'='Database'; '.sqlite'='Database'; '.sqlite3'='Database'; '.mdb'='Database'; '.accdb'='Database'; '.mdf'='Database'
    '.ldf'='Database'; '.ndf'='Database'; '.edb'='Database'; '.sdf'='Database'; '.realm'='Database'; '.fdb'='Database'; '.dbf'='Database'
    '.pst'='Mail'; '.ost'='Mail'; '.eml'='Mail'; '.mbox'='Mail'; '.msg'='Mail'
    '.doc'='UserDocument'; '.docx'='UserDocument'; '.xls'='UserDocument'; '.xlsx'='UserDocument'; '.xlsm'='UserDocument'; '.ppt'='UserDocument'
    '.pptx'='UserDocument'; '.pdf'='UserDocument'; '.odt'='UserDocument'; '.ods'='UserDocument'; '.odp'='UserDocument'; '.rtf'='UserDocument'
    '.csv'='UserDocument'; '.one'='UserDocument'; '.vsd'='UserDocument'; '.vsdx'='UserDocument'
    '.bak'='Backup'; '.bkp'='Backup'; '.backup'='Backup'; '.sql'='Backup'; '.dump'='Backup'
    '.vhd'='VirtualDisk'; '.vhdx'='VirtualDisk'; '.vmdk'='VirtualDisk'; '.vdi'='VirtualDisk'; '.ova'='VirtualDisk'; '.qcow2'='VirtualDisk'
    '.sav'='SaveData'; '.save'='SaveData'
    '.exe'='Executable'; '.dll'='Executable'; '.sys'='Executable'; '.ocx'='Executable'; '.msi'='Executable'
    '.ini'='Config'; '.cfg'='Config'; '.conf'='Config'; '.config'='Config'; '.toml'='Config'; '.yaml'='Config'; '.yml'='Config'; '.plist'='Config'; '.reg'='Config'
    '.ps1'='Script'; '.bat'='Script'; '.cmd'='Script'; '.vbs'='Script'; '.wsf'='Script'
    '.lnk'='Shortcut'
}
$Script:CredNameRx   = [regex]'(?i)^(login data|cookies|web data|local state|logins\.json|key[34]\.db|signons.*|credentials?(\..*)?|id_rsa.*|id_ed25519.*|known_hosts|authorized_keys|wallet\.dat|.*password.*|.*secret.*)$'
$Script:CfgNameRx    = [regex]'(?i)^(settings|config|configuration|preferences|prefs|options|profile|user)[^\\]*\.(json|xml|dat|txt)$'
$Script:DirUserRx    = [regex]'(?i)^(profiles?|user data|backups?|saves?|savegames?|documents|projects?|wallets?|keys|certificates?|databases?|indexeddb|local storage|session storage|sync data|workspaces?)$'
$Script:DirSharedRx  = [regex]'(?i)^(plugins?|extensions?|add-?ins?|modules?|lib|libs|runtimes?|redist|redistributables?|shared|common|drivers?|components?)$'

# Recognized disposable directory names (regenerable cache / log / crash / temp / update data).
$Script:DisposableNames = @{
    'cache'='Cache'; 'caches'='Cache'; 'code cache'='Cache'; 'gpucache'='Cache'; 'shadercache'='Cache'; 'grshadercache'='Cache'
    'dawncache'='Cache'; 'dawngraphitecache'='Cache'; 'dawnwebgpucache'='Cache'; 'd3dscache'='Cache'; 'media cache'='Cache'
    'logs'='Log'; 'log'='Log'
    'crashpad'='Crash'; 'crash reports'='Crash'; 'crashdumps'='Crash'; 'crashes'='Crash'
    'temp'='Temp'; 'tmp'='Temp'
    'updates'='Update'; 'update cache'='Update'
}

# Top-level names that are never evaluated (Windows components, active installation data, installer caches).
$Script:SkipRules = @{
    'Local'       = @('Microsoft','Packages','Programs','Temp','Application Data','History','TempState','ConnectedDevices','PlaceholderTileLogoFolder','VirtualStore','Comms','Apps','Publishers','Diagnostics')
    'Roaming'     = @('Microsoft','Application Data')
    'LocalLow'    = @('Microsoft')
    'ProgramData' = @('Microsoft','Package Cache','Packages','SoftwareDistribution','USOPrivate','USOShared','ssh','Application Data','Desktop','Documents','Start Menu','Templates','chocolatey','Windows','WindowsHolographicDevices','Microsoft OneDrive','Comms')
}

function Get-ScanRoots {
    $roots = New-Object System.Collections.Generic.List[object]
    function Add-Root($label, $path, $scope, $type, $skipKey) {
        if ($path -and (Test-Path -LiteralPath $path)) {
            $roots.Add([pscustomobject]@{ Label = $label; Path = $path; Scope = $scope; Type = $type; SkipKey = $skipKey })
        } elseif ($path) { Add-Skip $path 'Location does not exist' }
    }
    Add-Root 'AppData\Local'    $env:LOCALAPPDATA 'Current' 'AppData' 'Local'
    Add-Root 'AppData\Roaming'  $env:APPDATA 'Current' 'AppData' 'Roaming'
    Add-Root 'AppData\LocalLow' (Join-Path $env:USERPROFILE 'AppData\LocalLow') 'Current' 'AppData' 'LocalLow'
    Add-Root 'ProgramData'      $env:ProgramData 'Current' 'AppData' 'ProgramData'
    $userTemp = $env:TEMP
    if ($userTemp -like '*~*') { $alt = Join-Path $env:LOCALAPPDATA 'Temp'; if (Test-Path -LiteralPath $alt) { $userTemp = $alt } }   # avoid 8.3 short names
    Add-Root 'User TEMP'        $userTemp 'Current' 'Temp' $null
    Add-Root 'Windows TEMP'     (Join-Path $env:WINDIR 'Temp') 'Current' 'Temp' $null
    if ($Script:Settings.ScanAllProfiles) {
        if (-not $Script:IsAdmin) { Add-Skip 'Other user profiles' 'ScanAllProfiles is enabled but the tool is not running as administrator' }
        else {
            $usersDir = Split-Path -Parent $env:USERPROFILE
            foreach ($u in (Get-ChildItem -LiteralPath $usersDir -Directory -Force -ErrorAction SilentlyContinue)) {
                if ($u.FullName -eq $env:USERPROFILE -or @('Public', 'Default', 'Default User', 'All Users') -contains $u.Name) { continue }
                if ($u.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
                $scope = 'Other:' + $u.Name
                Add-Root ("[{0}] AppData\Local" -f $u.Name)    (Join-Path $u.FullName 'AppData\Local') $scope 'AppData' 'Local'
                Add-Root ("[{0}] AppData\Roaming" -f $u.Name)  (Join-Path $u.FullName 'AppData\Roaming') $scope 'AppData' 'Roaming'
                Add-Root ("[{0}] AppData\LocalLow" -f $u.Name) (Join-Path $u.FullName 'AppData\LocalLow') $scope 'AppData' 'LocalLow'
                Add-Root ("[{0}] TEMP" -f $u.Name)             (Join-Path $u.FullName 'AppData\Local\Temp') $scope 'Temp' $null
            }
        }
    }
    return $roots
}

function Test-ProtectedSelf { param([string]$Path)
    $n = ConvertTo-NormPath $Path
    if (Test-IsUnder $n (ConvertTo-NormPath $Script:Root)) { return $true }
    return ($n -like '*\winCleanup_quarantine*'.ToLowerInvariant())
}

function Get-RootEntries {
    param($Root, [bool]$IncludeFiles)
    $res = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($e in (New-Object IO.DirectoryInfo $Root.Path).EnumerateFileSystemInfos()) {
            $isDir = [bool]($e.Attributes -band [IO.FileAttributes]::Directory)
            if ($e.Attributes -band [IO.FileAttributes]::ReparsePoint) { Add-Skip $e.FullName 'Junction/symlink - never followed'; continue }
            if (Test-ProtectedSelf $e.FullName) { Add-Skip $e.FullName 'This tool or its quarantine'; continue }
            if ($Root.SkipKey) {
                $skip = $Script:SkipRules[$Root.SkipKey]
                if (($skip -contains $e.Name) -or ($e.Name -like 'regid.*')) { Add-Skip $e.FullName 'Protected by rule: Windows/system component, installer cache or active installation data'; continue }
            }
            if (-not $isDir -and -not $IncludeFiles) { Add-Skip $e.FullName 'Loose file at application-data root (not evaluated)'; continue }
            $res.Add($e)
        }
    } catch {
        Add-Skip $Root.Path ('Cannot enumerate: ' + $_.Exception.Message)
        Add-ScanError 'Enumerate' ("{0}: {1}" -f $Root.Path, $_.Exception.Message)
    }
    return ,$res
}

function Find-DisposableDirs {
    param([string]$TopPath)
    $found = New-Object System.Collections.Generic.List[object]
    $maxDepth = [int]$Script:Settings.CacheSearchDepth; $cap = [int]$Script:Settings.MaxDirsForCacheSearch
    $q = New-Object 'System.Collections.Generic.Queue[object]'
    $q.Enqueue(@($TopPath, 1))
    while ($q.Count -gt 0) {
        $item = $q.Dequeue(); $dir = $item[0]; $depth = $item[1]
        try {
            foreach ($e in (New-Object IO.DirectoryInfo $dir).EnumerateDirectories()) {
                if ($e.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
                $Script:CacheDirCount++
                if ($Script:CacheDirCount -gt $cap) { $Script:CacheSearchCapped = $true; return ,$found }
                $k = $Script:DisposableNames[$e.Name.ToLowerInvariant()]
                if ($k) { $found.Add([pscustomobject]@{ Path = $e.FullName; Name = $e.Name; Kind = $k }) }
                elseif ($depth -lt $maxDepth) { $q.Enqueue(@($e.FullName, ($depth + 1))) }
            }
        } catch {}
    }
    return ,$found
}

function Get-TreeStats {
    param([string]$Path, [bool]$IsFile = $false, [bool]$AccessReliable = $false)
    $now = [datetime]::Now
    $s = [pscustomobject]@{
        Size = [int64]0; Files = 0; Dirs = 0; Newest = [datetime]::MinValue; Oldest = [datetime]::MaxValue
        FutureStamps = 0; AncientStamps = 0; ReparseSkipped = 0; Errors = 0
        ErrorSamples = (New-Object System.Collections.Generic.List[string])
        KindCounts = @{}; Samples = @{}; ExeCount = 0
        ChildNames = (New-Object System.Collections.Generic.List[string]); ActivityDays = 0
    }
    $touch = {
        param($e)
        $t = $e.LastWriteTime; if ($e.CreationTime -gt $t) { $t = $e.CreationTime }
        # Last-access time is deliberately NOT used: it may be disabled/delayed and is altered by scanners.
        if ($t -gt $now.AddDays(1)) { $s.FutureStamps++; return }
        if ($e.LastWriteTime.Year -lt 1980) { $s.AncientStamps++ }
        if ($t -gt $s.Newest) { $s.Newest = $t }
        if ($e.LastWriteTime -lt $s.Oldest) { $s.Oldest = $e.LastWriteTime }
    }
    $addFinding = {
        param($kind, $rel)
        if ($s.KindCounts.ContainsKey($kind)) { $s.KindCounts[$kind]++ }
        else { $s.KindCounts[$kind] = 1; $s.Samples[$kind] = New-Object System.Collections.Generic.List[string] }
        if ($s.Samples[$kind].Count -lt 3) { $s.Samples[$kind].Add($rel) }
        if ($kind -eq 'Executable') { $s.ExeCount++ }
    }
    if ($IsFile) {
        try {
            $fi = New-Object IO.FileInfo $Path
            $s.Files = 1; $s.Size = $fi.Length; & $touch $fi
            $k = $Script:ExtKind[$fi.Extension.ToLowerInvariant()]
            if ($Script:CredNameRx.IsMatch($fi.Name)) { $k = 'Credential' }
            if ($k) { & $addFinding $k $fi.Name }
        } catch { $s.Errors++; $s.ErrorSamples.Add($_.Exception.Message) }
    } else {
        $stack = New-Object 'System.Collections.Generic.Stack[string]'
        $stack.Push($Path)
        $rootLen = $Path.Length
        try { & $touch (New-Object IO.DirectoryInfo $Path) } catch {}
        while ($stack.Count -gt 0) {
            $d = $stack.Pop(); $s.Dirs++
            $isTop = ($d -eq $Path)
            try {
                foreach ($e in (New-Object IO.DirectoryInfo $d).EnumerateFileSystemInfos()) {
                    $Script:FileCounter++
                    if (($Script:FileCounter % 5000) -eq 0) { Write-Host ("`r  ...{0:N0} items examined" -f $Script:FileCounter) -NoNewline }
                    if ($e.Attributes -band [IO.FileAttributes]::ReparsePoint) { $s.ReparseSkipped++; continue }
                    if ($e.Attributes -band [IO.FileAttributes]::Directory) {
                        & $touch $e
                        $stack.Push($e.FullName)
                        if ($isTop) { $s.ChildNames.Add($e.Name) }
                        $kind = $null
                        if ($Script:DirUserRx.IsMatch($e.Name)) { $kind = 'UserData' } elseif ($Script:DirSharedRx.IsMatch($e.Name)) { $kind = 'SharedComponent' }
                        if ($kind) { & $addFinding $kind $e.FullName.Substring($rootLen).TrimStart('\') }
                        continue
                    }
                    $s.Files++; $s.Size += $e.Length; & $touch $e
                    $k = $null
                    if ($Script:CredNameRx.IsMatch($e.Name)) { $k = 'Credential' }
                    else {
                        $k = $Script:ExtKind[$e.Extension.ToLowerInvariant()]
                        if (-not $k -and $Script:CfgNameRx.IsMatch($e.Name)) { $k = 'Config' }
                    }
                    if ($k) { & $addFinding $k $e.FullName.Substring($rootLen).TrimStart('\') }
                }
            } catch { $s.Errors++; if ($s.ErrorSamples.Count -lt 5) { $s.ErrorSamples.Add(("{0}: {1}" -f $d, $_.Exception.Message)) } }
        }
    }
    if ($s.Newest -eq [datetime]::MinValue) { $s.Newest = [datetime]::Now; $s.Errors++; $s.ErrorSamples.Add('No usable timestamps found') }
    if ($s.Oldest -eq [datetime]::MaxValue) { $s.Oldest = $s.Newest }
    $s.ActivityDays = Get-DaysSince $s.Newest
    $Script:Examined.Files += $s.Files; $Script:Examined.Dirs += $s.Dirs
    return $s
}

function New-Candidate {
    param([string]$Path, [string]$Name, $Root, [string]$Kind, [string]$Category, [string]$AppName, $Stats,
          [string]$AppStatus, $AppEvidence, [string]$DispKind)
    $kc = @{}; foreach ($k in $Stats.KindCounts.Keys) { $kc[$k] = $Stats.KindCounts[$k] }
    $sm = @{}; foreach ($k in $Stats.Samples.Keys) { $sm[$k] = @($Stats.Samples[$k]) }
    [pscustomobject]@{
        Id = 0; Path = $Path; Name = $Name; Root = $Root.Label; Scope = $Root.Scope
        Kind = $Kind; Category = $Category; DisposableKind = $DispKind
        App = $AppName; AppKey = (Get-NameKey $AppName); AppStatus = $AppStatus; AppEvidence = @($AppEvidence)
        SizeBytes = [int64]$Stats.Size; Files = $Stats.Files; Dirs = $Stats.Dirs
        Newest = $Stats.Newest.ToString('yyyy-MM-dd HH:mm:ss'); Oldest = $Stats.Oldest.ToString('yyyy-MM-dd HH:mm:ss')
        ActivityDays = $Stats.ActivityDays
        TimestampReliable = (($Stats.FutureStamps -eq 0) -and ($Stats.AncientStamps -eq 0))
        TimestampNotes = @()
        KindCounts = $kc; Samples = $sm; ExeCount = $Stats.ExeCount; ChildNames = @($Stats.ChildNames)
        StatErrors = $Stats.Errors; StatErrorSamples = @($Stats.ErrorSamples); ReparseSkipped = $Stats.ReparseSkipped
        Refs = (New-Object System.Collections.Generic.List[object]); RefCount = 0
        InvestigationComplete = $false; IncompleteChecks = @(); Limitations = @()
        Outcome = ''; Reasons = @(); Risks = @(); Confidence = ''; FindingSummary = @(); Quarantined = $false
    }
}

function Invoke-Scan {
    param([ValidateSet('All', 'Leftovers', 'InstalledInactive', 'Uncertain', 'TempCache')][string]$Mode)
    Write-Title ("SCAN: " + $Mode + "   (read-only - nothing will be changed)")
    Write-ActionLog 'INFO' ("Scan started. Mode={0} Admin={1}" -f $Mode, $Script:IsAdmin)
    $Script:ErrorLog.Clear(); $Script:SkipLog.Clear()
    $Script:Examined = @{ Files = 0; Dirs = 0 }; $Script:FileCounter = 0; $Script:CacheDirCount = 0; $Script:CacheSearchCapped = $false
    $accessOk = Test-LastAccessReliable
    $settingsOut = [pscustomobject]@{}; foreach ($k in $Script:Settings.Keys) { $settingsOut | Add-Member -NotePropertyName $k -NotePropertyValue $Script:Settings[$k] }
    $Script:Scan = [pscustomobject]@{
        Mode = $Mode; Started = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); Finished = ''; OS = $Script:OsCaption
        IsAdmin = $Script:IsAdmin; User = $env:USERNAME; Settings = $settingsOut; LastAccessReliable = $accessOk
        Roots = @(); GlobalChecks = (New-Object System.Collections.Generic.List[object]); Candidates = @(); Skipped = @(); Errors = @()
        NotSelected = 0; ExaminedFiles = 0; ExaminedDirs = 0; InventoryCounts = $null; InventoryFailures = @(); Totals = $null; SavedAt = ''
    }
    Write-Host 'Note: activity is judged from write/creation times; last-access time is not used as evidence.' -ForegroundColor Gray

    $inv = Get-AppInventory
    $Script:Scan.InventoryCounts = $inv.Counts; $Script:Scan.InventoryFailures = @($inv.Failures)
    Add-Check 'Application inventory' $(if ($inv.Failures.Count -eq 0) { 'Done' } else { 'Partial' }) ("({0} collector failure(s))" -f $inv.Failures.Count)

    $roots = Get-ScanRoots
    $Script:Scan.Roots = @($roots | ForEach-Object { '{0}  [{1}]' -f $_.Path, $_.Scope })
    $inactive = [int]$Script:Settings.InactiveDays; $tempAge = [int]$Script:Settings.TempAgeDays
    $cands = New-Object System.Collections.Generic.List[object]
    $notSel = 0

    # ---------------- application-data roots
    foreach ($root in ($roots | Where-Object { $_.Type -eq 'AppData' })) {
        Write-Host ("Examining {0} ..." -f $root.Path) -ForegroundColor Cyan
        foreach ($e in (Get-RootEntries $root $false)) {
            $name = $e.Name
            $pre = Get-AppStatus $name $inv $null $root.Scope
            $isInst = @('ConfirmedInstalled', 'ProbablyInstalled') -contains $pre.Status
            $wantParent = switch ($Mode) { 'All' { $true } 'Leftovers' { -not $isInst } 'InstalledInactive' { $isInst } 'Uncertain' { -not $isInst } default { $false } }
            $caches = @()
            if (($Mode -in @('All', 'TempCache')) -or ($Mode -eq 'InstalledInactive' -and $isInst)) { $caches = Find-DisposableDirs $e.FullName }
            $stats = $null; $status = $pre
            if ($wantParent -or (($caches.Count -gt 0) -and -not $isInst)) {
                $stats = Get-TreeStats $e.FullName $false $accessOk
                if ($pre.Status -eq 'NeedStats') { $status = Get-AppStatus $name $inv $stats $root.Scope }
            } elseif ($pre.Status -eq 'NeedStats') { $status = [pscustomobject]@{ Status = 'Unknown'; Evidence = @('Not investigated further in this mode.') } }
            $st = $status.Status
            $category = if (@('ConfirmedInstalled', 'ProbablyInstalled') -contains $st) { 'InstalledInactive' }
                        elseif (@('ConfirmedUninstalled', 'ProbablyUninstalled') -contains $st) { 'Leftover' } else { 'Uncertain' }
            $parentAdded = $false
            if ($wantParent -and $stats) {
                $modeOk = switch ($Mode) { 'All' { $true } 'Leftovers' { $category -eq 'Leftover' } 'InstalledInactive' { $category -eq 'InstalledInactive' }
                                           'Uncertain' { $category -eq 'Uncertain' } default { $false } }
                if ($modeOk) {
                    if ($category -eq 'InstalledInactive' -and $stats.ActivityDays -lt $inactive) { $notSel++ }
                    else {
                        $cands.Add((New-Candidate $e.FullName $name $root 'Directory' $category $name $stats $st $status.Evidence ''))
                        $parentAdded = $true
                    }
                } else { $notSel++ }
            }
            foreach ($cd in $caches) {
                if ($parentAdded -and $category -eq 'Leftover') { continue }   # the whole leftover folder is evaluated instead
                $cs = Get-TreeStats $cd.Path $false $accessOk
                if ($cs.ActivityDays -lt $inactive) { $notSel++; continue }
                $cands.Add((New-Candidate $cd.Path ($name + '\...\' + $cd.Name) $root 'Directory' 'CacheSub' $name $cs $st $status.Evidence $cd.Kind))
            }
        }
    }
    if ($Script:CacheSearchCapped) { Add-Check 'Cache folder search' 'Partial' '(directory limit reached; some cache folders may not have been found)' }

    # ---------------- temporary folders
    if ($Mode -in @('All', 'TempCache')) {
        foreach ($root in ($roots | Where-Object { $_.Type -eq 'Temp' })) {
            Write-Host ("Examining {0} ..." -f $root.Path) -ForegroundColor Cyan
            foreach ($e in (Get-RootEntries $root $true)) {
                $isDir = [bool]($e.Attributes -band [IO.FileAttributes]::Directory)
                $stats = Get-TreeStats $e.FullName (-not $isDir) $accessOk
                if ($stats.ActivityDays -lt $tempAge) { $notSel++; continue }
                $kind = if ($isDir) { 'Directory' } else { 'File' }
                $cands.Add((New-Candidate $e.FullName $e.Name $root $kind 'TempRoot' '(temporary item)' $stats 'Unknown' @('Temporary-folder rule: application association is not required.') 'Temp'))
            }
        }
    }
    Write-Host ''
    $Script:Scan.NotSelected = $notSel

    # ---------------- number, investigate, classify
    $i = 0; foreach ($c in $cands) { $i++; $c.Id = $i }
    Write-Host ("{0} candidate(s) selected for investigation." -f $cands.Count) -ForegroundColor Green
    if ($cands.Count -gt 0) {
        Initialize-CandidateIndex $cands
        Write-Host 'Investigating dependencies...' -ForegroundColor Cyan
        Invoke-LiveSourceCollectors $inv
        Search-RegistryReferences
        Search-FileReferences $inv
        Test-StructuralDependencies $inv $cands
        foreach ($c in $cands) { Set-Classification $c $inv }
    }
    $Script:Scan.Candidates = $cands.ToArray()
    $Script:Scan.Skipped = $Script:SkipLog.ToArray()
    $Script:Scan.Errors = @($Script:ErrorLog)
    $Script:Scan.ExaminedFiles = $Script:Examined.Files; $Script:Scan.ExaminedDirs = $Script:Examined.Dirs
    $Script:Scan.Finished = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $Script:Scan.Totals = Get-ScanTotals $Script:Scan.Candidates
    foreach ($c in $Script:Scan.Candidates) { $c.PSObject.Properties.Remove('NormPath') }
    Save-LastScan
    Write-ActionLog 'INFO' ("Scan finished. Candidates={0} Safe={1} Review={2} Protected={3}" -f $cands.Count, $Script:Scan.Totals.Safe.Count, $Script:Scan.Totals.Review.Count, $Script:Scan.Totals.Protected.Count)
    Show-ScanSummary
}

function Get-UniqueSize {
    # Sum sizes without double counting nested paths.
    param($Items)
    $total = [int64]0; $kept = New-Object System.Collections.Generic.List[string]
    foreach ($c in ($Items | Sort-Object { $_.Path.Length })) {
        $n = ConvertTo-NormPath $c.Path; $nested = $false
        foreach ($k in $kept) { if (Test-IsUnder $n $k) { $nested = $true; break } }
        if (-not $nested) { $kept.Add($n); $total += [int64]$c.SizeBytes }
    }
    return $total
}
function Get-ScanTotals {
    param($Candidates)
    $safe = @($Candidates | Where-Object { $_.Outcome -eq 'SAFE CANDIDATE' })
    $rev  = @($Candidates | Where-Object { $_.Outcome -eq 'NEEDS REVIEW' })
    $prot = @($Candidates | Where-Object { $_.Outcome -eq 'PROTECTED' })
    [pscustomobject]@{
        Safe = [pscustomobject]@{ Count = $safe.Count; Bytes = (Get-UniqueSize $safe) }
        Review = [pscustomobject]@{ Count = $rev.Count; Bytes = (Get-UniqueSize $rev) }
        Protected = [pscustomobject]@{ Count = $prot.Count; Bytes = (Get-UniqueSize $prot) }
    }
}
function Show-ScanSummary {
    $s = $Script:Scan; $t = $s.Totals
    Write-Title 'SCAN SUMMARY'
    Write-Host ("Examined: {0:N0} files, {1:N0} folders.  Not selected (active / below age threshold): {2}" -f $s.ExaminedFiles, $s.ExaminedDirs, $s.NotSelected)
    Write-Host ("SAFE CANDIDATE : {0,5}   potential size {1}" -f $t.Safe.Count, (Format-Size $t.Safe.Bytes)) -ForegroundColor Green
    Write-Host ("NEEDS REVIEW   : {0,5}   size {1}" -f $t.Review.Count, (Format-Size $t.Review.Bytes)) -ForegroundColor Yellow
    Write-Host ("PROTECTED      : {0,5}   size {1}" -f $t.Protected.Count, (Format-Size $t.Protected.Bytes)) -ForegroundColor Red
    Write-Host ("Skipped locations/items: {0}    Errors: {1}" -f @($s.Skipped).Count, @($s.Errors).Count)
    Write-Host 'Sizes are potential candidate sizes (nested items counted once). Nothing has been moved or deleted.' -ForegroundColor Gray
    $bad = @($s.GlobalChecks | Where-Object { $_.Status -ne 'Done' })
    if ($bad.Count -gt 0) { Write-Host ("{0} investigation check(s) were partial/failed - affected candidates cannot be SAFE." -f $bad.Count) -ForegroundColor Yellow }
}
