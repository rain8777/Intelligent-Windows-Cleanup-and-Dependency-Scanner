# Lib.Deps.ps1 - dependency investigation engine. Strictly read-only.
# Strategy: collect every path-like string from every relevant source ONCE, and match it
# against the set of candidate paths by walking up the path's ancestors.

$Script:PathTokenRegex = [regex]'(?i)(?:[a-z]:\\|%[a-z0-9_()]+%\\)[^"''<>|*?\r\n\t;,]*'

# Registry key paths that denote ACTIVE registrations (a path stored here is a confirmed dependency).
$Script:ActiveKeyRx = [regex]('(?i)\\(Run|RunOnce|RunServices|RunOnceEx)(\\|$)|\\App Paths\\|\\Services\\[^\\]+(\\Parameters)?$|' +
    '\\shell\\[^\\]+\\command|\\shellex\\|\\CLSID\\\{[^}]+\}\\(InprocServer32|LocalServer32|InprocHandler32|LocalServer)|' +
    '\\Classes\\Applications\\|\\Image File Execution Options\\|\\Winlogon|\\Windows NT\\CurrentVersion\\Windows$|\\Drivers32|' +
    '\\ShellIconOverlayIdentifiers|\\Shell Extensions\\|\\NativeMessagingHosts\\|\\TypeLib\\|\\Environment$|' +
    '\\CurrentVersion\\Uninstall\\|\\Installer\\Folders|\\Installer\\UserData|\\Explorer\\StartupApproved|\\Browser Helper Objects\\')
# Cheap pre-filter: candidates only live under AppData / ProgramData / TEMP folders.
$Script:PrefilterRx = [regex]'(?i)appdata|programdata|allusersprofile|%te?mp%|[\\/]te?mp([\\/]|$)'
$Script:RegSkipFull  = [regex]'(?i)\\Classes\\Interface$|\\Classes\\WOW6432Node\\Interface$'
$Script:RegSkipQuick = [regex]'(?i)\\Classes\\(CLSID|Interface|TypeLib|AppID|WOW6432Node)$|\\Installer\\(UserData|Products|Components)$'

function Find-PathTokens {
    param([string]$Text)
    $out = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrEmpty($Text)) { return ,$out }
    $t = $Text.Replace('\\', '\').Replace('/', '\')
    foreach ($m in $Script:PathTokenRegex.Matches($t)) { $out.Add($m.Value.Trim()) }
    return ,$out
}

function Initialize-CandidateIndex {
    param($Candidates)
    $Script:CandIndex = New-Object 'System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[object]]'
    $Script:RefSeen = @{}
    foreach ($c in $Candidates) {
        $np = ConvertTo-NormPath $c.Path
        $c | Add-Member -NotePropertyName NormPath -NotePropertyValue $np -Force
        if (-not $Script:CandIndex.ContainsKey($np)) { $Script:CandIndex[$np] = New-Object System.Collections.Generic.List[object] }
        $Script:CandIndex[$np].Add($c)
        $Script:RefSeen[[string]$c.Id] = New-Object 'System.Collections.Generic.HashSet[string]'
    }
}

function Add-Reference {
    param($Cand, [string]$Type, [string]$Source, [string]$Detail, [bool]$Active, [string]$Context)
    $strength = 'Direct'
    if ($Active) { $strength = 'Confirmed' }
    elseif ($Context -and $Cand.AppKey.Length -ge 4) {
        if ((Get-NameKey $Context).Contains($Cand.AppKey)) { $strength = 'Self' }
    }
    $sig = "$Type|$Source|$Detail"
    if (-not $Script:RefSeen[[string]$Cand.Id].Add($sig)) { return }
    $Cand.RefCount++
    if ($Cand.Refs.Count -lt 60) {
        $Cand.Refs.Add([pscustomobject]@{ Type = $Type; Strength = $strength; Source = $Source; Detail = $Detail })
    }
}

function Get-CandidateHits {
    # Returns pairs of (candidate, token) for every path token in Text that lies inside a candidate.
    param([string]$Text)
    $hits = New-Object System.Collections.Generic.List[object]
    foreach ($tok in (Find-PathTokens $Text)) {
        $cur = ConvertTo-NormPath $tok
        if (-not $cur) { continue }
        while ($true) {
            if ($Script:CandIndex.ContainsKey($cur)) { foreach ($c in $Script:CandIndex[$cur]) { $hits.Add([pscustomobject]@{ Cand = $c; Token = $tok }) } }
            $i = $cur.LastIndexOf('\')
            if ($i -lt 3) { break }
            $cur = $cur.Substring(0, $i)
        }
    }
    return ,$hits
}

function Register-Text {
    param([string]$Text, [string]$Type, [string]$Source, [bool]$Active, [string]$Context, [string]$SourceNorm)
    if ([string]::IsNullOrEmpty($Text) -or -not $Script:PrefilterRx.IsMatch($Text)) { return }
    foreach ($h in (Get-CandidateHits $Text)) {
        if ($SourceNorm -and (Test-IsUnder $SourceNorm $h.Cand.NormPath)) { continue }   # reference from inside itself
        Add-Reference $h.Cand $Type $Source $h.Token $Active $Context
    }
}

function Add-Check { param([string]$Name, [string]$Status, [string]$Detail = '')
    $Script:Scan.GlobalChecks.Add([pscustomobject]@{ Name = $Name; Status = $Status; Detail = $Detail })
    $col = switch ($Status) { 'Done' { 'Green' } 'Partial' { 'Yellow' } default { 'Red' } }
    Write-Host ('  [{0,-7}] {1} {2}' -f $Status, $Name, $Detail) -ForegroundColor $col
}

# ---------------------------------------------------------------- collectors
function Invoke-LiveSourceCollectors {
    param($Inv)
    # Running processes
    foreach ($p in $Inv.Procs) { if ($p.Path) { Register-Text $p.Path 'RunningProcess' ("Process {0} (PID {1})" -f $p.Name, $p.Id) $true $null $null } }
    Add-Check 'Running processes' 'Done' ("({0} processes)" -f $Inv.Procs.Count)

    # Loaded modules (partial without admin: other users'/protected processes refuse)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'; $denied = 0; $total = 0
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
        try {
            foreach ($m in $p.Modules) {
                $total++
                if ($seen.Add($m.FileName)) { Register-Text $m.FileName 'LoadedModule' ("Module loaded by {0} (PID {1})" -f $p.ProcessName, $p.Id) $true $null $null }
            }
        } catch { $denied++ }
    }
    if ($denied -gt 0) { Add-Check 'Loaded modules' 'Partial' ("($denied processes could not be inspected; run as administrator for fuller coverage)") }
    else { Add-Check 'Loaded modules' 'Done' ("($total modules)") }

    # Services
    foreach ($s in $Inv.Services) { Register-Text $s.Command 'Service' ("Service '{0}' ({1})" -f $s.Name, $s.State) $true $null $null }
    Add-Check 'Windows services' 'Done' ("({0} services)" -f $Inv.Services.Count)

    # Scheduled tasks
    foreach ($t in $Inv.Tasks) { Register-Text $t.Text 'ScheduledTask' ("Task " + $t.Name) $true $null $null }
    Add-Check 'Scheduled tasks' 'Done' ("({0} tasks)" -f $Inv.Tasks.Count)

    # Startup entries
    foreach ($s in $Inv.Startup) { Register-Text $s.Text 'StartupEntry' $s.Source $true $null $null }
    Add-Check 'Startup entries (Run/RunOnce)' 'Done' ("({0} entries)" -f $Inv.Startup.Count)

    # Shortcuts
    foreach ($s in $Inv.Shortcuts) { Register-Text ($s.Target + ' ' + $s.Args + ' ' + $s.WorkDir) 'Shortcut' $s.Lnk $true $null $null }
    Add-Check 'Shortcuts (Start Menu/Desktop)' 'Done' ("({0} shortcuts)" -f $Inv.Shortcuts.Count)

    # PATH
    foreach ($e in $Inv.PathEntries) { Register-Text $e 'PathEnvironment' 'PATH variable' $true $null $null }
    Add-Check 'PATH environment variable' 'Done'
}

function Search-RegistryReferences {
    $mode = $Script:Settings.RegistryMode
    $skipRx = if ($mode -eq 'Quick') { $Script:RegSkipQuick } else { $Script:RegSkipFull }
    $Script:RegKeyCount = 0; $Script:RegErrors = 0; $Script:RegTruncated = $false
    $roots = @(
        @{ H = 'LocalMachine'; P = 'SOFTWARE';                                  L = 'HKLM\SOFTWARE' },
        @{ H = 'LocalMachine'; P = 'SYSTEM\CurrentControlSet\Services';         L = 'HKLM\SYSTEM\CurrentControlSet\Services' },
        @{ H = 'LocalMachine'; P = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'; L = 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' },
        @{ H = 'CurrentUser';  P = 'Software';                                  L = 'HKCU\Software' },
        @{ H = 'CurrentUser';  P = 'Environment';                               L = 'HKCU\Environment' })
    Write-Host ("Searching registry ({0} mode). This can take several minutes..." -f $mode) -ForegroundColor Cyan
    foreach ($r in $roots) {
        $base = $null
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]$r.H, [Microsoft.Win32.RegistryView]::Registry64)
            $k = $base.OpenSubKey($r.P)
            if ($k) { try { Walk-RegKey $k $r.L $skipRx } finally { $k.Close() } }
        } catch { $Script:RegErrors++; Add-ScanError 'Registry' ("{0}: {1}" -f $r.L, $_.Exception.Message) }
        finally { if ($base) { $base.Close() } }
    }
    Write-Host ''
    $ratio = 0; if ($Script:RegKeyCount -gt 0) { $ratio = $Script:RegErrors / $Script:RegKeyCount }
    $detail = ("({0:N0} keys read, {1} unreadable)" -f $Script:RegKeyCount, $Script:RegErrors)
    if ($mode -eq 'Quick') { Add-Check 'Registry reference search' 'Partial' ("QUICK mode: CLSID/TypeLib/Installer data not searched " + $detail) }
    elseif ($Script:RegTruncated) { Add-Check 'Registry reference search' 'Partial' ("key limit reached " + $detail) }
    elseif ($ratio -gt 0.02) { Add-Check 'Registry reference search' 'Partial' ("too many unreadable keys; run as administrator " + $detail) }
    else { Add-Check 'Registry reference search' 'Done' $detail }
}

function Walk-RegKey {
    param($Key, [string]$Path, $SkipRx)
    if ($Script:RegKeyCount -ge [int]$Script:Settings.MaxRegistryKeys) { $Script:RegTruncated = $true; return }
    $Script:RegKeyCount++
    if (($Script:RegKeyCount % 25000) -eq 0) { Write-Host ("`r  ...{0:N0} registry keys read" -f $Script:RegKeyCount) -NoNewline }
    try {
        foreach ($vn in $Key.GetValueNames()) {
            $kind = $Key.GetValueKind($vn)
            if ($kind -ne 'String' -and $kind -ne 'ExpandString' -and $kind -ne 'MultiString') { continue }
            $v = $Key.GetValue($vn, $null, 'DoNotExpandEnvironmentNames')
            if ($v -is [array]) { $v = ($v -join ' ; ') }
            if ($v -is [string] -and $v.Length -gt 3 -and ($v.IndexOf(':\') -ge 0 -or $v.IndexOf('%') -ge 0)) {
                $active = $Script:ActiveKeyRx.IsMatch($Path)
                $type = if ($active) { 'RegistryActive' } else { 'Registry' }
                Register-Text $v $type ("{0} [{1}]" -f $Path, $vn) $active $Path $null
            }
        }
    } catch { $Script:RegErrors++ }
    try {
        foreach ($sn in $Key.GetSubKeyNames()) {
            $cp = $Path + '\' + $sn
            if ($SkipRx.IsMatch($cp)) { continue }
            $sub = $null
            try { $sub = $Key.OpenSubKey($sn) } catch { $Script:RegErrors++ }
            if ($sub) { try { Walk-RegKey $sub $cp $SkipRx } finally { $sub.Close() } }
        }
    } catch { $Script:RegErrors++ }
}

function Test-UnderInstalledRoot {
    param($Inv, [string]$NormPath)
    foreach ($r in $Inv.InstallRoots) { if (Test-IsUnder $NormPath $r.Path) { return $r } }
    return $null
}

function Search-FileReferences {
    param($Inv)
    $exts = @('.json', '.xml', '.ini', '.cfg', '.conf', '.config', '.manifest', '.settings', '.toml', '.yaml', '.yml',
              '.ps1', '.bat', '.cmd', '.vbs', '.reg', '.props', '.targets', '.properties', '.plist', '.url', '.pth')
    $extSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($x in $exts) { [void]$extSet.Add($x) }
    $skipDirs = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($x in @('node_modules', '.git', 'temp', 'tmp', 'cache', 'code cache', 'gpucache', 'shadercache', 'logs', 'winsxs', 'servicing', 'crashpad', 'crashdumps')) { [void]$skipDirs.Add($x) }
    $roots = @($env:APPDATA, $env:LOCALAPPDATA, $env:ProgramData, $env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique
    $maxDepth = [int]$Script:Settings.FileRefDepth; $maxFiles = [int]$Script:Settings.MaxFileRefFiles; $maxBytes = [int64]$Script:Settings.MaxFileRefBytes
    $examined = 0; $unreadable = 0; $capped = $false
    Write-Host 'Searching configuration files, manifests and scripts for references...' -ForegroundColor Cyan
    foreach ($root in $roots) {
        $q = New-Object 'System.Collections.Generic.Queue[object]'
        $q.Enqueue(@($root, 0))
        while ($q.Count -gt 0 -and -not $capped) {
            $item = $q.Dequeue(); $dir = $item[0]; $depth = $item[1]
            try {
                foreach ($e in (New-Object IO.DirectoryInfo $dir).EnumerateFileSystemInfos()) {
                    if ($e.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
                    if ($e.Attributes -band [IO.FileAttributes]::Directory) {
                        if ($depth -lt $maxDepth -and -not $skipDirs.Contains($e.Name)) { $q.Enqueue(@($e.FullName, ($depth + 1))) }
                        continue
                    }
                    if (-not $extSet.Contains($e.Extension) -or $e.Length -gt $maxBytes -or $e.Length -eq 0) { continue }
                    $examined++
                    if ($examined -gt $maxFiles) { $capped = $true; break }
                    if (($examined % 2000) -eq 0) { Write-Host ("`r  ...{0:N0} files read" -f $examined) -NoNewline }
                    $text = $null
                    try {
                        $fs = New-Object IO.FileStream($e.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
                        try { $sr = New-Object IO.StreamReader($fs, [Text.Encoding]::Default, $true); $text = $sr.ReadToEnd() } finally { $fs.Dispose() }
                    } catch { $unreadable++; continue }
                    $hits = Get-CandidateHits $text
                    if ($hits.Count -eq 0) { continue }
                    $srcN = ConvertTo-NormPath $e.FullName
                    $ir = Test-UnderInstalledRoot $Inv $srcN
                    foreach ($h in $hits) {
                        if (Test-IsUnder $srcN $h.Cand.NormPath) { continue }
                        if ($ir) { Add-Reference $h.Cand 'InstalledAppConfig' ("File {0} (installation of {1})" -f $e.FullName, $ir.App) $h.Token $true $null }
                        else     { Add-Reference $h.Cand 'FileReference' $e.FullName $h.Token $false $e.FullName }
                    }
                }
            } catch { $unreadable++ }
        }
        if ($capped) { break }
    }
    Write-Host ''
    $detail = ("({0:N0} files read, {1} unreadable)" -f $examined, $unreadable)
    if ($capped) { Add-Check 'Config/manifest/script reference search' 'Partial' ("file limit reached " + $detail) }
    else { Add-Check 'Config/manifest/script reference search' 'Done' $detail }
}

function Test-StructuralDependencies {
    # Install directories, shared-folder relationships, child folders belonging to other installed applications.
    param($Inv, $Candidates)
    foreach ($c in $Candidates) {
        if ($c.Category -ne 'TempRoot') {
            foreach ($r in $Inv.InstallRoots) {
                if (Test-IsUnder $c.NormPath $r.Path) { Add-Reference $c 'InstallDirectory' ("Inside installation directory of '{0}' ({1})" -f $r.App, $r.Source) $r.Path $true $null; break }
                if ($r.Path.StartsWith($c.NormPath + '\')) { Add-Reference $c 'InstallDirectory' ("Contains installation directory of '{0}' ({1})" -f $r.App, $r.Source) $r.Path $true $null; break }
            }
        }
        if ($c.Kind -eq 'Directory' -and $c.Category -notin @('TempRoot', 'CacheSub')) {
            foreach ($child in @($c.ChildNames)) {
                $ck = Get-NameKey $child
                if ($ck -eq $c.AppKey) { continue }
                if ($Inv.Installed.ContainsKey($ck)) {
                    $strong = @($Inv.Installed[$ck] | Where-Object { $_.Strength -ne 'Weak' }).Count
                    if ($strong -gt 0) { Add-Reference $c 'SharedFolder' ("Contains folder '$child' that matches an installed application") $child $false $null }
                }
            }
        }
    }
    Add-Check 'Install-directory / shared-folder relationships' 'Done'
}
