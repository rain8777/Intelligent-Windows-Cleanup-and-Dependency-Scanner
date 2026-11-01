# Lib.Common.ps1 - shared helpers: settings, logging, paths, UI, persistence.
# ASCII only on purpose (Windows PowerShell 5.1 reads BOM-less files as ANSI).

$Script:AppName    = 'Intelligent Windows Cleanup and Dependency Scanner'
$Script:AppVersion = '1.0.0'

function Initialize-Environment {
    if ((Split-Path -Leaf $PSScriptRoot) -ieq 'src') { $Script:Root = Split-Path -Parent $PSScriptRoot } else { $Script:Root = $PSScriptRoot }
    $Script:Dirs = @{
        Config  = Join-Path $Script:Root 'config'
        Data    = Join-Path $Script:Root 'data'
        Reports = Join-Path $Script:Root 'reports'
        Logs    = Join-Path $Script:Root 'logs'
    }
    foreach ($d in $Script:Dirs.Values) {
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }
    try { $Script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { $Script:IsAdmin = $false }
    $Script:Settings  = Get-Settings
    $Script:UserRules = Get-UserRules
    $Script:ErrorLog  = New-Object System.Collections.Generic.List[string]
    $Script:SkipLog   = New-Object System.Collections.Generic.List[object]
    $Script:Scan      = $null
    $Script:Examined  = @{ Files = 0; Dirs = 0 }
    $Script:FileCounter = 0; $Script:CacheDirCount = 0; $Script:CacheSearchCapped = $false
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $Script:OsCaption = ('{0} (build {1})' -f $os.Caption, $os.BuildNumber)
    } catch { $Script:OsCaption = [Environment]::OSVersion.VersionString }
    $Script:QuarantineDirName = 'WinCleanup_Quarantine'
}

function Get-Settings {
    $defaults = [ordered]@{
        InactiveDays          = 365       # candidate-selection threshold (never below 365)
        TempAgeDays           = 30        # selection threshold for items in TEMP folders
        UninstalledRecentDays = 90        # "uninstalled" app with newer activity => uncertain
        ScanAllProfiles       = $false    # needs admin; other users' HKCU is not inspected
        RegistryMode          = 'Full'    # Full | Quick (Quick can never yield SAFE)
        MaxFileRefBytes       = 2097152
        MaxFileRefFiles       = 60000
        FileRefDepth          = 4
        MaxRegistryKeys       = 2000000
        CacheSearchDepth      = 5
        MaxDirsForCacheSearch = 60000
    }
    $path = Join-Path $Script:Dirs.Config 'settings.json'
    if (Test-Path -LiteralPath $path) {
        try {
            $u = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            foreach ($p in $u.PSObject.Properties) { if ($defaults.Contains($p.Name)) { $defaults[$p.Name] = $p.Value } }
        } catch { Write-Host 'settings.json could not be read; using defaults.' -ForegroundColor Yellow }
    } else {
        try { ($defaults | ConvertTo-Json) | Set-Content -LiteralPath $path -Encoding UTF8 } catch {}
    }
    if ([int]$defaults['InactiveDays'] -lt 365) { $defaults['InactiveDays'] = 365 }
    if ($defaults['RegistryMode'] -ne 'Quick') { $defaults['RegistryMode'] = 'Full' }
    return $defaults
}

function Get-UserRules {
    $path = Join-Path $Script:Dirs.Config 'user-rules.json'
    $rules = [pscustomobject]@{ ProtectedNames = @(); ConfirmedUninstalledNames = @() }
    if (Test-Path -LiteralPath $path) {
        try {
            $u = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            if ($u.ProtectedNames) { $rules.ProtectedNames = @($u.ProtectedNames) }
            if ($u.ConfirmedUninstalledNames) { $rules.ConfirmedUninstalledNames = @($u.ConfirmedUninstalledNames) }
        } catch { Write-Host 'user-rules.json could not be read; ignoring.' -ForegroundColor Yellow }
    } else {
        try { ($rules | ConvertTo-Json) | Set-Content -LiteralPath $path -Encoding UTF8 } catch {}
    }
    return $rules
}

# ---------------------------------------------------------------- logging
function Write-ActionLog {
    param([string]$Level = 'INFO', [string]$Message)
    $file = Join-Path $Script:Dirs.Logs ('actions-{0}.log' -f (Get-Date -Format 'yyyyMMdd'))
    $line = '{0} [{1}] [{2}] {3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $env:USERNAME, $Message
    try { Add-Content -LiteralPath $file -Value $line -Encoding UTF8 } catch {}
}
function Add-ScanError { param([string]$Where, [string]$Message)
    $Script:ErrorLog.Add(('{0}: {1}' -f $Where, $Message))
    Write-ActionLog 'ERROR' ('{0}: {1}' -f $Where, $Message)
}
function Add-Skip { param([string]$Path, [string]$Reason)
    $Script:SkipLog.Add([pscustomobject]@{ Path = $Path; Reason = $Reason })
}

# ------------------------------------------------------------------- text
function Format-Size {
    param([int64]$Bytes)
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N1} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N0} KB' -f ($Bytes / 1KB)) }
    return ('{0} B' -f $Bytes)
}
function Get-NameKey { param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return [regex]::Replace($Text.ToLowerInvariant(), '[^\p{L}\p{N}]', '')
}
function ConvertTo-NormPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $p = $Path.Trim().Trim('"')
    if ($p.IndexOf('%') -ge 0) { try { $p = [Environment]::ExpandEnvironmentVariables($p) } catch {} }
    $p = $p.Replace('/', '\')
    if ($p.StartsWith('\\?\')) { $p = $p.Substring(4) }
    $p = $p.TrimEnd('\').Trim()
    if ($p.Length -eq 2 -and $p[1] -eq ':') { $p = $p + '\' }
    return $p.ToLowerInvariant()
}
function Test-IsUnder {   # both arguments already normalized
    param([string]$Child, [string]$Parent)
    if (-not $Child -or -not $Parent) { return $false }
    return ($Child -eq $Parent) -or $Child.StartsWith($Parent + '\')
}
function Get-DaysSince { param([datetime]$When)
    return [int][math]::Floor(([datetime]::Now - $When).TotalDays)
}
function Test-LastAccessReliable {
    # Returns $true only if NTFS last-access updates are enabled for user-managed or system-managed volumes.
    try {
        $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name NtfsDisableLastAccessUpdate -ErrorAction Stop).NtfsDisableLastAccessUpdate
        return (([int64]$v -band 1) -eq 0)
    } catch { return $false }
}

# --------------------------------------------------------------------- UI
function Write-Title { param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host (' ' + $Text) -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
}
function Wait-Key { Write-Host ''; [void](Read-Host 'Press Enter to continue') }
function Confirm-Typed { param([string]$Prompt, [string]$Word)
    $a = Read-Host ('{0} (type {1} to confirm)' -f $Prompt, $Word)
    return ($a -ceq $Word)
}
function Get-OutcomeColor { param([string]$Outcome)
    switch ($Outcome) { 'SAFE CANDIDATE' { 'Green' } 'NEEDS REVIEW' { 'Yellow' } 'PROTECTED' { 'Red' } default { 'Gray' } }
}
function Resolve-IdList {   # "1,3,5-7" -> int[]
    param([string]$Text)
    $ids = New-Object System.Collections.Generic.List[int]
    foreach ($part in ($Text -split '[,\s]+')) {
        if (-not $part) { continue }
        if ($part -match '^(\d+)-(\d+)$') { for ($i = [int]$Matches[1]; $i -le [int]$Matches[2]; $i++) { $ids.Add($i) } }
        elseif ($part -match '^\d+$') { $ids.Add([int]$part) }
    }
    return @($ids | Sort-Object -Unique)
}

# ------------------------------------------------------------ persistence
function Save-Json { param($Object, [string]$Path, [int]$Depth = 8)
    $tmp = $Path + '.tmp'
    ($Object | ConvertTo-Json -Depth $Depth) | Set-Content -LiteralPath $tmp -Encoding UTF8
    Move-Item -LiteralPath $tmp -Destination $Path -Force
}
function Read-Json { param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try { return (Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json) } catch { return $null }
}
function Save-LastScan {
    $Script:Scan | Add-Member -NotePropertyName SavedAt -NotePropertyValue (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') -Force
    Save-Json -Object $Script:Scan -Path (Join-Path $Script:Dirs.Data 'last_scan.json') -Depth 8
}
function Restore-LastScan {
    $s = Read-Json (Join-Path $Script:Dirs.Data 'last_scan.json')
    if ($s) { $Script:Scan = $s }
}
