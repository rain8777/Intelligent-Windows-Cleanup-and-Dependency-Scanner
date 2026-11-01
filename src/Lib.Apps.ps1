# Lib.Apps.ps1 - application inventory (read-only) and installed/uninstalled status inference.

$Script:GenericTokens = @('bin','app','apps','application','applications','data','temp','tmp','cache','local','user','users','program','programs',
    'windows','system','system32','common','shared','lib','libs','x64','x86','win32','win64','resources','release','debug','updates','update',
    'installer','setup','launcher','client','server','service','services','tools','default','files','settings','config','logs','log','crash',
    'reports','packages','microsoft','windowsapps','sdk','runtime','core','main','new','old','backup')

function New-Evidence { param([string]$Kind, [string]$Strength, [string]$Detail)
    [pscustomobject]@{ Kind = $Kind; Strength = $Strength; Detail = $Detail }
}
function Add-Token {
    param([hashtable]$Table, [string]$Token, $Evidence)
    $k = Get-NameKey $Token
    if ($k.Length -lt 3 -or ($Script:GenericTokens -contains $k)) { return }
    if ($k -match '^[0-9a-f]{32}$') { return }
    if (-not $Table.ContainsKey($k)) { $Table[$k] = New-Object System.Collections.Generic.List[object] }
    if ($Table[$k].Count -lt 12) { $Table[$k].Add($Evidence) }
}
function Get-Leaf { param([string]$Path)
    if (-not $Path) { return $null }
    try { return (Split-Path -Leaf $Path.TrimEnd('\')) } catch { return $null }
}
function Test-PathSafe { param([string]$Path)
    if (-not $Path) { return $false }
    if ($Path.StartsWith('\\')) { return $true }   # never touch network paths; assume present (conservative)
    try { return (Test-Path -LiteralPath $Path -ErrorAction Stop) } catch { return $false }
}
function Get-ExePathFromCommand {
    param([string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }
    try {
        $c = [Environment]::ExpandEnvironmentVariables($Command.Trim())
        $m = [regex]::Match($c, '^"([^"]+)"')
        if ($m.Success) { $p = $m.Groups[1].Value }
        else {
            $m = [regex]::Match($c, '^(?i)([a-z]:\\.*?\.(exe|dll|bat|cmd|com|msc|cpl|scr|sys))(\s|$|,)')
            if ($m.Success) { $p = $m.Groups[1].Value } else { $p = ($c -split '\s+')[0] }
        }
        $p = ($p -replace ',\s*-?\d+$', '').Trim()
        if ([IO.Path]::IsPathRooted($p) -and $p.Length -gt 3) { return $p }
    } catch {}
    return $null
}
function Test-WindowsDir { param([string]$NormPath)
    $w = ConvertTo-NormPath $env:WINDIR
    return (Test-IsUnder $NormPath $w)
}

function Get-AppInventory {
    Write-Host 'Building application inventory (read-only)...' -ForegroundColor Cyan
    $inv = [pscustomobject]@{
        Installed    = @{}
        Residue      = @{}
        InstallRoots = (New-Object System.Collections.Generic.List[object])
        Procs        = (New-Object System.Collections.Generic.List[object])
        Services     = (New-Object System.Collections.Generic.List[object])
        Tasks        = (New-Object System.Collections.Generic.List[object])
        Startup      = (New-Object System.Collections.Generic.List[object])
        Shortcuts    = (New-Object System.Collections.Generic.List[object])
        PathEntries  = (New-Object System.Collections.Generic.List[string])
        Failures     = (New-Object System.Collections.Generic.List[string])
        Notes        = (New-Object System.Collections.Generic.List[string])
        Counts       = @{}
    }
    $HKLM = [Microsoft.Win32.RegistryHive]::LocalMachine
    $HKCU = [Microsoft.Win32.RegistryHive]::CurrentUser
    $V64  = [Microsoft.Win32.RegistryView]::Registry64
    $V32  = [Microsoft.Win32.RegistryView]::Registry32

    # ---- 1. Uninstall registry (HKLM/HKCU, 64 and 32 bit views)
    Write-Host '  [1/10] Uninstall registry entries'
    $n = 0
    foreach ($h in @(@{H = $HKLM; L = 'HKLM'}, @{H = $HKCU; L = 'HKCU'})) {
        foreach ($view in @($V64, $V32)) {
            $base = $null
            try {
                $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($h.H, $view)
                $uk = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
                if ($uk) {
                    foreach ($name in $uk.GetSubKeyNames()) {
                        $k = $null
                        try {
                            $k = $uk.OpenSubKey($name); if (-not $k) { continue }
                            $dn = [string]$k.GetValue('DisplayName'); $pub = [string]$k.GetValue('Publisher')
                            $loc = [string]$k.GetValue('InstallLocation')
                            $exes = @((Get-ExePathFromCommand ([string]$k.GetValue('DisplayIcon'))), (Get-ExePathFromCommand ([string]$k.GetValue('UninstallString')))) | Where-Object { $_ }
                            $locN = $null; if ($loc) { $locN = ConvertTo-NormPath $loc }
                            $present = $false; $missing = $false
                            if ($locN) { if (Test-PathSafe $locN) { $present = $true } else { $missing = $true } }
                            foreach ($e in $exes) { if (Test-PathSafe $e) { $present = $true } else { $missing = $true } }
                            $tag = '{0}\{1}' -f $h.L, $name
                            if ($present -or (-not $missing)) {
                                $ev = New-Evidence 'UninstallRegistry' 'Strong' ("Uninstall entry '$dn' ($tag)")
                                Add-Token $inv.Installed $dn $ev
                                if ($name -notmatch '^\{?[0-9a-fA-F-]{36}\}?$') { Add-Token $inv.Installed $name $ev }
                                if ($locN) { Add-Token $inv.Installed (Get-Leaf $locN) $ev
                                    if (Test-PathSafe $locN) { $inv.InstallRoots.Add([pscustomobject]@{ Path = $locN; App = $dn; Source = 'Uninstall registry' }) } }
                                foreach ($e in $exes) { $ed = Split-Path -Parent $e
                                    if ($ed -and -not (Test-WindowsDir (ConvertTo-NormPath $ed))) { Add-Token $inv.Installed (Get-Leaf $ed) (New-Evidence 'UninstallRegistry' 'Medium' "Uninstall entry '$dn' executable folder") } }
                                if ($pub) { Add-Token $inv.Installed $pub (New-Evidence 'Publisher' 'Weak' "Publisher of '$dn'") }
                            } else {
                                $ev = New-Evidence 'StaleUninstallEntry' 'Strong' ("Uninstall entry '$dn' ($tag) points to missing files")
                                Add-Token $inv.Residue $dn $ev
                                if ($locN) { Add-Token $inv.Residue (Get-Leaf $locN) $ev }
                            }
                            $n++
                        } catch {} finally { if ($k) { $k.Close() } }
                    }
                    $uk.Close()
                }
            } catch { $inv.Failures.Add(("Uninstall registry {0}/{1}: {2}" -f $h.L, $view, $_.Exception.Message)) }
            finally { if ($base) { $base.Close() } }
        }
    }
    $inv.Counts['UninstallEntries'] = $n

    # ---- 2. Program directories
    Write-Host '  [2/10] Application directories'
    $pd = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432, (Join-Path $env:LOCALAPPDATA 'Programs')) | Where-Object { $_ } | Select-Object -Unique
    $n = 0
    foreach ($b in $pd) {
        try {
            if (-not (Test-Path -LiteralPath $b)) { continue }
            foreach ($d in [IO.Directory]::EnumerateDirectories($b)) {
                $leaf = Get-Leaf $d
                Add-Token $inv.Installed $leaf (New-Evidence 'ProgramDir' 'Medium' "Folder exists: $d")
                $inv.InstallRoots.Add([pscustomobject]@{ Path = (ConvertTo-NormPath $d); App = $leaf; Source = 'Program directory' })
                $n++
            }
        } catch { $inv.Failures.Add("Program directory ${b}: $($_.Exception.Message)") }
    }
    $inv.Counts['ProgramDirs'] = $n

    # ---- 3. Store (AppX) packages
    Write-Host '  [3/10] Store (AppX) packages'
    try {
        $pk = @(Get-AppxPackage -ErrorAction Stop)
        foreach ($p in $pk) {
            $ev = New-Evidence 'AppX' 'Medium' ("AppX package " + $p.Name)
            Add-Token $inv.Installed $p.Name $ev
            foreach ($part in ($p.Name -split '\.')) { if ($part.Length -ge 4) { Add-Token $inv.Installed $part $ev } }
        }
        $inv.Counts['AppX'] = $pk.Count
    } catch { $inv.Failures.Add("AppX packages: $($_.Exception.Message)") }

    # ---- 4. Running processes
    Write-Host '  [4/10] Running processes'
    try {
        foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
            $path = $null; try { $path = $p.Path } catch {}
            $inv.Procs.Add([pscustomobject]@{ Name = $p.ProcessName; Path = $path; Id = $p.Id })
            $ev = New-Evidence 'RunningProcess' 'Medium' ("Process {0} (PID {1}) {2}" -f $p.ProcessName, $p.Id, $path)
            Add-Token $inv.Installed $p.ProcessName $ev
            if ($path) { $dir = Split-Path -Parent $path
                if ($dir -and -not (Test-WindowsDir (ConvertTo-NormPath $dir))) { Add-Token $inv.Installed (Get-Leaf $dir) $ev } }
        }
        $inv.Counts['Processes'] = $inv.Procs.Count
    } catch { $inv.Failures.Add("Processes: $($_.Exception.Message)") }

    # ---- 5. Services
    Write-Host '  [5/10] Windows services'
    try {
        foreach ($s in (Get-CimInstance Win32_Service -ErrorAction Stop)) {
            $exe = Get-ExePathFromCommand $s.PathName
            $inv.Services.Add([pscustomobject]@{ Name = $s.Name; Display = $s.DisplayName; Command = $s.PathName; State = $s.State })
            if (-not $exe) { continue }
            $nexe = ConvertTo-NormPath $exe
            if (Test-WindowsDir $nexe) { continue }
            $dir = Split-Path -Parent $exe
            if (Test-PathSafe $exe) {
                $ev = New-Evidence 'Service' 'Medium' ("Service '{0}' runs {1}" -f $s.Name, $exe)
                Add-Token $inv.Installed $s.Name $ev; Add-Token $inv.Installed $s.DisplayName $ev
                Add-Token $inv.Installed ([IO.Path]::GetFileNameWithoutExtension($exe)) $ev
                if ($dir) { Add-Token $inv.Installed (Get-Leaf $dir) $ev }
            } else {
                $ev = New-Evidence 'OrphanService' 'Strong' ("Service '{0}' points to missing {1}" -f $s.Name, $exe)
                Add-Token $inv.Residue $s.Name $ev; if ($dir) { Add-Token $inv.Residue (Get-Leaf $dir) $ev }
            }
        }
        $inv.Counts['Services'] = $inv.Services.Count
    } catch { $inv.Failures.Add("Services: $($_.Exception.Message)") }

    # ---- 6. Scheduled tasks
    Write-Host '  [6/10] Scheduled tasks'
    try {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop)
        foreach ($t in $tasks) {
            $texts = @()
            foreach ($a in @($t.Actions)) { if ($a.Execute) { $texts += ("{0} {1} {2}" -f $a.Execute, $a.Arguments, $a.WorkingDirectory) } }
            $full = ($t.TaskPath + $t.TaskName)
            $inv.Tasks.Add([pscustomobject]@{ Name = $full; Text = ($texts -join ' ; ') })
            foreach ($a in @($t.Actions)) {
                $exe = Get-ExePathFromCommand $a.Execute
                if (-not $exe -or (Test-WindowsDir (ConvertTo-NormPath $exe))) { continue }
                $dir = Split-Path -Parent $exe
                if (Test-PathSafe $exe) {
                    $ev = New-Evidence 'ScheduledTask' 'Medium' ("Task '$full' runs $exe")
                    Add-Token $inv.Installed $t.TaskName $ev
                    Add-Token $inv.Installed ([IO.Path]::GetFileNameWithoutExtension($exe)) $ev
                    if ($dir) { Add-Token $inv.Installed (Get-Leaf $dir) $ev }
                } else {
                    $ev = New-Evidence 'OrphanTask' 'Strong' ("Task '$full' points to missing $exe")
                    Add-Token $inv.Residue $t.TaskName $ev; if ($dir) { Add-Token $inv.Residue (Get-Leaf $dir) $ev }
                }
            }
        }
        $inv.Counts['Tasks'] = $tasks.Count
    } catch { $inv.Failures.Add("Scheduled tasks: $($_.Exception.Message)") }

    # ---- 7. Startup entries (Run keys) + App Paths
    Write-Host '  [7/10] Startup entries and App Paths'
    $n = 0
    foreach ($h in @(@{H = $HKLM; L = 'HKLM'}, @{H = $HKCU; L = 'HKCU'})) {
        foreach ($view in @($V64, $V32)) {
            $base = $null
            try {
                $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($h.H, $view)
                foreach ($sub in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')) {
                    $rk = $base.OpenSubKey($sub); if (-not $rk) { continue }
                    foreach ($vn in $rk.GetValueNames()) {
                        $cmd = [string]$rk.GetValue($vn, $null, 'DoNotExpandEnvironmentNames')
                        $inv.Startup.Add([pscustomobject]@{ Source = ("{0}\{1}\{2}" -f $h.L, $sub, $vn); Text = $cmd }); $n++
                        $exe = Get-ExePathFromCommand $cmd
                        if ($exe -and -not (Test-WindowsDir (ConvertTo-NormPath $exe))) {
                            $dir = Split-Path -Parent $exe
                            if (Test-PathSafe $exe) {
                                $ev = New-Evidence 'StartupEntry' 'Medium' ("Run entry '$vn' starts $exe")
                                Add-Token $inv.Installed $vn $ev; if ($dir) { Add-Token $inv.Installed (Get-Leaf $dir) $ev }
                            } else {
                                $ev = New-Evidence 'OrphanStartup' 'Strong' ("Run entry '$vn' points to missing $exe")
                                Add-Token $inv.Residue $vn $ev; if ($dir) { Add-Token $inv.Residue (Get-Leaf $dir) $ev }
                            }
                        }
                    }
                    $rk.Close()
                }
                $ap = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths')
                if ($ap) {
                    foreach ($an in $ap.GetSubKeyNames()) {
                        $ak = $ap.OpenSubKey($an); if (-not $ak) { continue }
                        $exe = Get-ExePathFromCommand ([string]$ak.GetValue(''))
                        if ($exe -and -not (Test-WindowsDir (ConvertTo-NormPath $exe))) {
                            $dir = Split-Path -Parent $exe
                            if (Test-PathSafe $exe) {
                                $ev = New-Evidence 'AppPaths' 'Medium' ("App Paths registration $an -> $exe")
                                Add-Token $inv.Installed ([IO.Path]::GetFileNameWithoutExtension($an)) $ev
                                if ($dir) { Add-Token $inv.Installed (Get-Leaf $dir) $ev }
                            } else {
                                $ev = New-Evidence 'OrphanAppPath' 'Strong' ("App Paths registration $an points to missing $exe")
                                Add-Token $inv.Residue ([IO.Path]::GetFileNameWithoutExtension($an)) $ev
                                if ($dir) { Add-Token $inv.Residue (Get-Leaf $dir) $ev }
                            }
                        }
                        $ak.Close()
                    }
                    $ap.Close()
                }
            } catch { $inv.Failures.Add(("Startup/AppPaths {0}/{1}: {2}" -f $h.L, $view, $_.Exception.Message)) }
            finally { if ($base) { $base.Close() } }
        }
    }
    $inv.Counts['StartupEntries'] = $n

    # ---- 8. Shortcuts (Start Menu, Desktop, Startup folders)
    Write-Host '  [8/10] Shortcuts (Start Menu, Desktop, Startup)'
    $shell = $null
    try {
        $shell = New-Object -ComObject WScript.Shell
        $dirs = @(
            @{P = (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'); R = $true},
            @{P = (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'); R = $true},
            @{P = (Join-Path $env:PUBLIC 'Desktop'); R = $false},
            @{P = [Environment]::GetFolderPath('Desktop'); R = $false})
        $lnks = New-Object System.Collections.Generic.List[string]
        foreach ($d in $dirs) {
            if (-not $d.P -or -not (Test-Path -LiteralPath $d.P)) { continue }
            try {
                $opt = if ($d.R) { [IO.SearchOption]::AllDirectories } else { [IO.SearchOption]::TopDirectoryOnly }
                foreach ($f in [IO.Directory]::EnumerateFiles($d.P, '*.lnk', $opt)) { $lnks.Add($f) }
            } catch { $inv.Notes.Add("Shortcut folder partially unreadable: $($d.P)") }
        }
        foreach ($l in $lnks) {
            try {
                $sc = $shell.CreateShortcut($l)
                $target = [string]$sc.TargetPath; $argsTxt = [string]$sc.Arguments; $wd = [string]$sc.WorkingDirectory
                $inv.Shortcuts.Add([pscustomobject]@{ Lnk = $l; Target = $target; Args = $argsTxt; WorkDir = $wd })
                if ($target -and [IO.Path]::IsPathRooted($target) -and -not (Test-WindowsDir (ConvertTo-NormPath $target))) {
                    $dir = Split-Path -Parent $target; $lnkBase = [IO.Path]::GetFileNameWithoutExtension($l)
                    if (Test-PathSafe $target) {
                        $ev = New-Evidence 'Shortcut' 'Medium' ("Shortcut '$l' -> $target")
                        Add-Token $inv.Installed $lnkBase $ev; if ($dir) { Add-Token $inv.Installed (Get-Leaf $dir) $ev }
                    } else {
                        $ev = New-Evidence 'BrokenShortcut' 'Strong' ("Shortcut '$l' points to missing $target")
                        Add-Token $inv.Residue $lnkBase $ev; if ($dir) { Add-Token $inv.Residue (Get-Leaf $dir) $ev }
                    }
                }
            } catch {}
        }
        $inv.Counts['Shortcuts'] = $inv.Shortcuts.Count
    } catch { $inv.Failures.Add("Shortcuts: $($_.Exception.Message)") }
    finally { if ($shell) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell) } }

    # ---- 9. Application registration keys (Software\Vendor\App with install paths)
    Write-Host '  [9/10] Application registration keys'
    $skipTop = @('microsoft', 'classes', 'policies', 'wow6432node', 'clients', 'registeredapplications', 'odbc', 'windows', 'javasoft', 'partner', 'dolby')
    $valRx = '(?i)install|path|dir|location|folder|home|exe|root'
    $n = 0
    foreach ($h in @(@{H = $HKLM; S = 'SOFTWARE'; L = 'HKLM'}, @{H = $HKCU; S = 'Software'; L = 'HKCU'})) {
        $base = $null
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($h.H, $V64)
            $sw = $base.OpenSubKey($h.S)
            foreach ($n1 in $sw.GetSubKeyNames()) {
                if ($skipTop -contains $n1.ToLowerInvariant()) { continue }
                $k1 = $null
                try {
                    $k1 = $sw.OpenSubKey($n1); if (-not $k1) { continue }
                    $keys = @(@{K = $k1; N = $n1; P = $null})
                    $subs = New-Object System.Collections.Generic.List[object]
                    foreach ($n2 in $k1.GetSubKeyNames()) { $k2 = $null; try { $k2 = $k1.OpenSubKey($n2) } catch {}; if ($k2) { $subs.Add(@{K = $k2; N = $n2; P = $n1}) } }
                    foreach ($e in (@($keys) + $subs.ToArray())) {
                        foreach ($vn in $e.K.GetValueNames()) {
                            if ($vn -notmatch $valRx) { continue }
                            $kind = $e.K.GetValueKind($vn)
                            if ($kind -ne 'String' -and $kind -ne 'ExpandString') { continue }
                            $val = [string]$e.K.GetValue($vn)
                            if (-not $val -or $val.StartsWith('\\') -or $val -notmatch '^[a-zA-Z]:\\') { continue }
                            $root = [IO.Path]::GetPathRoot($val)
                            if (-not (Test-Path -LiteralPath $root -ErrorAction SilentlyContinue)) { continue }
                            $leafDir = if ($val -match '\.[a-zA-Z0-9]{2,4}$') { Get-Leaf (Split-Path -Parent $val) } else { Get-Leaf $val }
                            if (Test-PathSafe $val) {
                                $ev = New-Evidence 'SoftwareKey' 'Medium' ("{0}\{1}\{2}\{3}={4}" -f $h.L, $h.S, $n1, $vn, $val)
                                Add-Token $inv.Installed $e.N $ev; Add-Token $inv.Installed $leafDir $ev
                            } else {
                                $ev = New-Evidence 'SoftwareKeyMissingPath' 'Strong' ("{0}\{1}\{2} value '{3}' points to missing {4}" -f $h.L, $h.S, $n1, $vn, $val)
                                Add-Token $inv.Residue $e.N $ev; Add-Token $inv.Residue $n1 $ev; Add-Token $inv.Residue $leafDir $ev
                            }
                            $n++
                        }
                    }
                    foreach ($s in $subs) { $s.K.Close() }
                } catch {} finally { if ($k1) { $k1.Close() } }
            }
        } catch { $inv.Failures.Add(("Application registration keys {0}: {1}" -f $h.L, $_.Exception.Message)) }
        finally { if ($base) { $base.Close() } }
    }
    $inv.Counts['SoftwareKeyHints'] = $n

    # ---- 10. PATH environment entries
    Write-Host '  [10/10] PATH environment'
    try {
        foreach ($t in @('Machine', 'User')) {
            $v = [Environment]::GetEnvironmentVariable('Path', $t)
            if ($v) { foreach ($e in ($v -split ';')) { if ($e.Trim()) { $inv.PathEntries.Add($e.Trim()) } } }
        }
    } catch { $inv.Failures.Add("PATH: $($_.Exception.Message)") }

    Write-Host ("  Inventory complete: {0} identity tokens, {1} residue tokens, {2} collector failure(s)." -f $inv.Installed.Count, $inv.Residue.Count, $inv.Failures.Count) -ForegroundColor Green
    foreach ($f in $inv.Failures) { Write-Host "  ! $f" -ForegroundColor Yellow; Add-ScanError 'Inventory' $f }
    return $inv
}

# Status values: ConfirmedInstalled, ProbablyInstalled, ConfirmedUninstalled, ProbablyUninstalled, Unknown, NeedStats
function Get-AppStatus {
    param([string]$Name, $Inv, $Stats, [string]$Scope = 'Current')
    $r = [pscustomobject]@{ Status = 'Unknown'; Evidence = (New-Object System.Collections.Generic.List[string]) }
    $key = Get-NameKey $Name
    if ($key.Length -lt 3) { $r.Evidence.Add('Name is too short or generic to identify an application.'); return $r }

    foreach ($pn in @($Script:UserRules.ProtectedNames)) {
        if ($pn -and (Get-NameKey $pn) -eq $key) { $r.Status = 'ConfirmedInstalled'; $r.Evidence.Add('User rule: ProtectedNames'); return $r }
    }
    $ev = New-Object System.Collections.Generic.List[object]
    if ($Inv.Installed.ContainsKey($key)) { foreach ($e in $Inv.Installed[$key]) { $ev.Add($e) } }
    if ($key.Length -ge 5) {
        $partial = 0
        foreach ($t in $Inv.Installed.Keys) {
            if ($t.Length -ge 5 -and $t -ne $key -and ($t.Contains($key) -or $key.Contains($t))) {
                $ev.Add((New-Evidence 'PartialNameMatch' 'Weak' ("Partial name match with installed-application identity '$t'")))
                $partial++; if ($partial -ge 3) { break }
            }
        }
    }
    $res = @(); if ($Inv.Residue.ContainsKey($key)) { $res = $Inv.Residue[$key].ToArray() }

    $kinds = @($ev | Where-Object { $_.Strength -ne 'Weak' } | ForEach-Object { $_.Kind } | Select-Object -Unique)
    $hasStrong = @($ev | Where-Object { $_.Strength -eq 'Strong' }).Count -gt 0
    $level = $null
    if ($hasStrong -or $kinds.Count -ge 2) { $level = 'ConfirmedInstalled' }
    elseif ($ev.Count -gt 0) { $level = 'ProbablyInstalled' }

    if ($level) {
        foreach ($e in ($ev | Select-Object -First 4)) { $r.Evidence.Add(('[{0}/{1}] {2}' -f $e.Kind, $e.Strength, $e.Detail)) }
        if ($res.Count -gt 0) {
            $r.Status = 'Unknown'
            $r.Evidence.Add('CONFLICT: installed-application evidence and uninstall residue both exist for this name:')
            foreach ($e in ($res | Select-Object -First 3)) { $r.Evidence.Add(('[{0}] {1}' -f $e.Kind, $e.Detail)) }
        } else { $r.Status = $level }
        return $r
    }

    # No evidence of an installed application.
    $userUninst = $false
    foreach ($un in @($Script:UserRules.ConfirmedUninstalledNames)) { if ($un -and (Get-NameKey $un) -eq $key) { $userUninst = $true } }
    if ($null -eq $Stats) { $r.Status = 'NeedStats'; return $r }
    if ($userUninst) { $r.Status = 'ConfirmedUninstalled'; $r.Evidence.Add('User rule: ConfirmedUninstalledNames'); return $r }

    if ($Stats.ExeCount -gt 0) {
        $r.Evidence.Add(("Folder contains {0} executable/library file(s); it may be a portable application or an unidentified installation." -f $Stats.ExeCount))
        return $r
    }
    if ($Stats.ActivityDays -lt [int]$Script:Settings.UninstalledRecentDays) {
        $r.Evidence.Add(("Recent activity ({0} days ago) conflicts with the application being uninstalled." -f $Stats.ActivityDays))
        return $r
    }
    $r.Evidence.Add('No installed-application evidence found in: uninstall registry, program folders, Store packages, processes, services, tasks, startup, shortcuts, App Paths, registration keys.')
    if ($Scope -ne 'Current') {
        $r.Status = 'ProbablyUninstalled'; $r.Evidence.Add("Other user's profile: that user's registry hive was not inspected."); return $r
    }
    if ($Inv.Failures.Count -gt 0) {
        $r.Status = 'ProbablyUninstalled'; $r.Evidence.Add('Application inventory was incomplete (collector failures).'); return $r
    }
    if ($res.Count -gt 0) {
        $r.Status = 'ConfirmedUninstalled'
        foreach ($e in ($res | Select-Object -First 4)) { $r.Evidence.Add(('Residue [{0}] {1}' -f $e.Kind, $e.Detail)) }
        return $r
    }
    if ($key.Length -ge 4) { $r.Status = 'ProbablyUninstalled'; $r.Evidence.Add('No positive uninstall residue was found, so uninstall is not confirmed.') }
    return $r
}
