# ============================================
# NEXUS ANTICHEAT v5.0 PROFESSIONAL
# Sistema Avanzado de Detección - Minecraft Bedrock
# Inspirado en Ocean & Echo AntiCheat
# ============================================

$ErrorActionPreference = "SilentlyContinue"
$Host.UI.RawUI.WindowTitle = "NEXUS AntiCheat v5.0 PRO"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Clear-Host

# ============================================
# BANNER Y CONFIGURACIÓN INICIAL
# ============================================

function Show-Banner {
    Write-Host ""
    Write-Host "  ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗" -ForegroundColor Cyan
    Write-Host "  ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝" -ForegroundColor Cyan
    Write-Host "  ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗" -ForegroundColor Cyan
    Write-Host "  ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║" -ForegroundColor Cyan
    Write-Host "  ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║" -ForegroundColor Cyan
    Write-Host "  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  ╔════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
    Write-Host "  ║   NEXUS ANTICHEAT v5.0 PROFESSIONAL EDITION  ║" -ForegroundColor White
    Write-Host "  ║   Advanced Detection System for MC Bedrock    ║" -ForegroundColor Gray
    Write-Host "  ╚════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
    Write-Host ""
}

Show-Banner

# Variables globales
$timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$desktopPath = [Environment]::GetFolderPath("Desktop")
$outputDir = "$desktopPath\NEXUS_Scan_$timestamp"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

$logFile = "$outputDir\NEXUS_MASTER_LOG.txt"
$detections = @()
$startTime = Get-Date
$totalChecks = 35
$currentCheck = 0

# Base de datos de firmas (expandida)
$cheatSignatures = @{
    Clients = @(
        "horion", "packet", "crystal", "ambrosial", "lakeside",
        "nitr0", "nitro", "koid", "dream", "toolbox", "element", "rise", "fdp", "liquid",
        "azura", "flux", "vertex", "phantom", "ghost", "spectre", "venom", "toxic",
        "filess", "entropy", "vape", "astolfo", "sigma", "wurst", "meteor", "zephyr"
    )
    
    Injectors = @(
        "dll_inject", "process_inject", "xenos", "extreme_injector", "manual_map",
        "loadlibrary", "creepermod", "apollo", "mineshafter", "clientloader",
        "injector", "loader", "bootstrap"
    )
    
    Modifications = @(
        "xray", "killaura", "bhop", "fly", "reach", "velocity", "antiknockback",
        "scaffold", "freecam", "esp", "tracers", "nametags", "cavefinder",
        "nuker", "fastbreak", "autoarmor", "autoclicker", "aimbot", "triggerbot",
        "antifall", "nofall", "timer", "fastbow", "criticals", "step", "jesus",
        "derp", "blink", "phase", "noslowdown", "antiblind", "fullbright",
        "autoclick", "leftclick", "rightclick", "doubleclick", "clickassist",
        "butterfly", "jitter", "drag", "godbridging", "breezily", "moonwalk"
    )
    
    AutoClickers = @(
        "autoclick", "autoclicker", "clickassist", "leftclick", "rightclick",
        "doubleclick", "clickbot", "mouseclick", "clickmacro", "clickrecord",
        "butterfly", "jitter", "drag", "cps", "opclick", "ghostclick",
        "breezily", "moonwalk", "godbridging", "wtap", "stap"
    )
    
    Tools = @(
        "cheat_engine", "wireshark", "fiddler", "charles", "process_hacker",
        "x64dbg", "ida", "dnspy", "pe_explorer", "resource_hacker", "pe_bear",
        "pestudio", "lordpe", "stud_pe", "protection_id"
    )
    
    AntiDetection = @(
        "wisefolderhider", "iobit", "unlocker", "hidewindow", "noobnoobserver",
        "antiobs", "screenblock", "antiscreenshare", "bypasser", "spoofer",
        "hwid_spoof", "mac_spoof", "serial_spoof", "volume_spoof"
    )
}

# Firmas de archivos por magic bytes
$fileMagicBytes = @{
    "EXE" = @("4D5A")
    "DLL" = @("4D5A")
    "ZIP" = @("504B0304", "504B0506", "504B0708")
    "RAR" = @("526172211A07")
    "7Z" = @("377ABCAF271C")
    "PNG" = @("89504E47")
    "JPG" = @("FFD8FF")
    "GIF" = @("474946")
    "PDF" = @("25504446")
    "JAR" = @("504B0304")
    "CLASS" = @("CAFEBABE")
}

function Get-FileMagicBytes {
    param([string]$Path, [int]$ByteCount = 8)
    
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        if ($bytes.Length -eq 0) { return "EMPTY" }
        
        $magicBytes = $bytes[0..[Math]::Min($ByteCount - 1, $bytes.Length - 1)]
        $hex = ($magicBytes | ForEach-Object { $_.ToString("X2") }) -join ""
        return $hex
    } catch {
        return $null
    }
}

function Test-FileExtensionMismatch {
    param([string]$Path, [string]$Extension)
    
    $magic = Get-FileMagicBytes -Path $Path -ByteCount 8
    if (-not $magic -or $magic -eq "EMPTY") { return $null }
    
    if ($Extension -notin @(".exe", ".dll", ".scr", ".com")) {
        if ($magic -like "4D5A*") {
            return @{
                RealType = "Executable (EXE/DLL)"
                FakeExtension = $Extension
                ThreatLevel = 95
                Reason = "Archivo ejecutable disfrazado"
            }
        }
    }
    
    if ($Extension -notin @(".zip", ".jar", ".apk", ".docx", ".xlsx")) {
        if ($magic -like "504B*") {
            return @{
                RealType = "ZIP/JAR Archive"
                FakeExtension = $Extension
                ThreatLevel = 80
                Reason = "Archivo comprimido disfrazado"
            }
        }
    }
    
    if ($Extension -eq ".png" -and $magic -notlike "89504E47*") {
        return @{
            RealType = "Not PNG"
            FakeExtension = ".png"
            ActualMagic = $magic
            ThreatLevel = 85
            Reason = "Extensión .png falsa"
        }
    }
    
    if ($Extension -eq ".jpg" -and $magic -notlike "FFD8FF*") {
        return @{
            RealType = "Not JPG"
            FakeExtension = ".jpg"
            ActualMagic = $magic
            ThreatLevel = 85
            Reason = "Extensión .jpg falsa"
        }
    }
    
    return $null
}

# Lugares ocultos donde los hackers esconden cheats
$hiddenLocations = @{
    SystemFolders = @(
        "C:\Windows\Fonts",
        "C:\Windows\Help",
        "C:\Windows\Cursors",
        "C:\Windows\Media",
        "C:\Windows\Web\Wallpaper",
        "C:\Windows\System32\spool",
        "C:\Windows\System32\Tasks",
        "C:\Windows\SysWOW64\config",
        "C:\Windows\Logs",
        "C:\Windows\ServiceProfiles",
        "C:\PerfLogs"
    )
    
    HiddenAppData = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Microsoft\Windows\SendTo",
        "$env:APPDATA\Microsoft\Windows\Cookies",
        "$env:LOCALAPPDATA\Microsoft\Windows\INetCache",
        "$env:LOCALAPPDATA\Microsoft\Windows\WebCache",
        "$env:LOCALAPPDATA\Microsoft\Windows\Explorer",
        "$env:LOCALAPPDATA\Microsoft\CLR_v4.0",
        "$env:LOCALAPPDATA\Microsoft\Feeds Cache"
    )
    
    GameFolders = @(
        "$env:LOCALAPPDATA\Packages\Microsoft.MinecraftUWP_8wekyb3d8bbwe\LocalCache",
        "$env:LOCALAPPDATA\Packages\Microsoft.MinecraftUWP_8wekyb3d8bbwe\Settings",
        "$env:LOCALAPPDATA\Packages\Microsoft.MinecraftUWP_8wekyb3d8bbwe\SystemAppData",
        "$env:LOCALAPPDATA\Packages\Microsoft.MinecraftUWP_8wekyb3d8bbwe\TempState",
        "$env:APPDATA\.minecraft\libraries",
        "$env:APPDATA\.minecraft\logs",
        "$env:APPDATA\.minecraft\crash-reports"
    )
    
    CloudSync = @(
        "$env:USERPROFILE\OneDrive",
        "$env:USERPROFILE\Google Drive",
        "$env:USERPROFILE\Dropbox",
        "$env:USERPROFILE\iCloudDrive"
    )
    
    Browsers = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions",
        "$env:APPDATA\Mozilla\Firefox\Profiles",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
    )
}

# Extensiones alternativas usadas para ocultar
$disguiseExtensions = @(
    ".txt", ".log", ".dat", ".tmp", ".bak", ".old", ".cache", ".ini",
    ".cfg", ".config", ".xml", ".json", ".db", ".sqlite", ".sys",
    ".ttf", ".fon", ".cur", ".ani", ".wav", ".mp3", ".bmp", ".ico"
)

# Nombres genéricos comunes para ocultar
$genericNames = @(
    "svchost", "system", "windows", "microsoft", "update", "service", 
    "runtime", "framework", "driver", "host", "helper", "launcher",
    "config", "settings", "cache", "data", "temp", "log"
)

# Archivos conocidos de cheats (CORRECCIÓN AQUÍ)
$knownCheatFiles = @{
    Clients = @(
        @{Name="horion.dll"; Hash=""; ThreatLevel=100},
        @{Name="Horion.exe"; Hash=""; ThreatLevel=100},
        @{Name="onix.dll"; Hash=""; ThreatLevel=100},
        @{Name="OnixClient.exe"; Hash=""; ThreatLevel=100},
        @{Name="packet.dll"; Hash=""; ThreatLevel=95},
        @{Name="PacketClient.exe"; Hash=""; ThreatLevel=95},
        @{Name="crystal.dll"; Hash=""; ThreatLevel=95},
        @{Name="CrystalClient.exe"; Hash=""; ThreatLevel=95},
        @{Name="zephyr.dll"; Hash=""; ThreatLevel=90},
        @{Name="ZephyrClient.exe"; Hash=""; ThreatLevel=90},
        @{Name="ambrosial.dll"; Hash=""; ThreatLevel=90},
        @{Name="element.dll"; Hash=""; ThreatLevel=90},
        @{Name="ElementClient.exe"; Hash=""; ThreatLevel=90},
        @{Name="toolbox.apk"; Hash=""; ThreatLevel=85},
        @{Name="nitr0.dll"; Hash=""; ThreatLevel=85},
        @{Name="lakeside.dll"; Hash=""; ThreatLevel=85}
    )
    
    Injectors = @(
        @{Name="injector.exe"; Hash=""; ThreatLevel=90},
        @{Name="dll_injector.exe"; Hash=""; ThreatLevel=90},
        @{Name="xenos.exe"; Hash=""; ThreatLevel=85},
        @{Name="extreme injector.exe"; Hash=""; ThreatLevel=85},
        @{Name="LoadLibrary.exe"; Hash=""; ThreatLevel=80},
        @{Name="ManualMap.exe"; Hash=""; ThreatLevel=80},
        @{Name="ClientLoader.exe"; Hash=""; ThreatLevel=85},
        @{Name="cheat_loader.exe"; Hash=""; ThreatLevel=90}
    )
    
    AutoClickers = @(
        @{Name="AutoClicker.exe"; Hash=""; ThreatLevel=75},
        @{Name="OpAutoClicker.exe"; Hash=""; ThreatLevel=80},
        @{Name="ghost_client.jar"; Hash=""; ThreatLevel=85},
        @{Name="JNativeHook.dll"; Hash=""; ThreatLevel=70},
        @{Name="jna-4.5.2.jar"; Hash=""; ThreatLevel=65},
        @{Name="clicks_tmp.mp3"; Hash=""; ThreatLevel=60}
    )
    
    Bypass = @(
        @{Name="NoobNoObserver.exe"; Hash=""; ThreatLevel=95},
        @{Name="HideWindow.exe"; Hash=""; ThreatLevel=85},
        @{Name="wisefs.dat"; Hash=""; ThreatLevel=90},
        @{Name="WiseFolderHider.exe"; Hash=""; ThreatLevel=85},
        @{Name="IObitUnlocker.exe"; Hash=""; ThreatLevel=70}
    )
}

# ============================================
# FUNCIONES AUXILIARES
# ============================================

function Write-Log {
    param(
        [string]$Message,
        [string]$Color = "White",
        [string]$Type = "INFO"
    )
    
    $logEntry = "$(Get-Date -Format 'HH:mm:ss.fff') [$Type] $Message"
    Write-Host $logEntry -ForegroundColor $Color
    Add-Content -Path $logFile -Value $logEntry
}

function Add-Detection {
    param(
        [string]$Category,
        [string]$Detail,
        [string]$Severity = "HIGH",
        [string]$Evidence = "",
        [int]$ThreatLevel = 0
    )
    
    $detection = [PSCustomObject]@{
        Timestamp = Get-Date -Format 'HH:mm:ss.fff'
        Severity = $Severity
        ThreatLevel = $ThreatLevel
        Category = $Category
        Detail = $Detail
        Evidence = $Evidence
    }
    
    $script:detections += $detection
    
    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "HIGH" { "DarkRed" }
        "MEDIUM" { "Yellow" }
        "LOW" { "DarkYellow" }
        default { "Gray" }
    }
    
    Write-Log "🚨 DETECTION: [$Category] $Detail" $color "ALERT"
}

function Test-CheatSignature {
    param([string]$Text)
    
    $textLower = $Text.ToLower()
    $matches = @()
    
    foreach ($category in $cheatSignatures.Keys) {
        foreach ($sig in $cheatSignatures[$category]) {
            if ($textLower -like "*$sig*") {
                $matches += [PSCustomObject]@{
                    Category = $category
                    Signature = $sig
                    Match = $Text
                }
            }
        }
    }
    
    return $matches
}

function Update-Progress {
    param([string]$Status)
    
    $script:currentCheck++
    $percent = [math]::Round(($script:currentCheck / $totalChecks) * 100)
    
    Write-Host "`r[" -NoNewline -ForegroundColor DarkCyan
    Write-Host "$percent%" -NoNewline -ForegroundColor Cyan
    Write-Host "] " -NoNewline -ForegroundColor DarkCyan
    Write-Host "$Status" -NoNewline -ForegroundColor White
    Write-Host (" " * (60 - $Status.Length)) -NoNewline
}

function Get-FileHash-Safe {
    param([string]$Path)
    
    try {
        $hash = Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop
        return $hash.Hash
    } catch {
        return "N/A"
    }
}

# ============================================
# MÓDULO BÁSICO DE DEMOSTRACIÓN
# ============================================

function Invoke-BasicScan {
    Update-Progress "Ejecutando escaneo básico..."
    Write-Log "`n=== MÓDULO: ESCANEO BÁSICO ===" "Cyan"
    
    # Escaneo de procesos
    Write-Log "Analizando procesos..." "Gray"
    $processes = Get-Process | Where-Object { $_.Path }
    
    foreach ($proc in $processes) {
        $signatures = Test-CheatSignature $proc.Name
        if ($signatures.Count -gt 0) {
            Add-Detection "Proceso Sospechoso" `
                "$($proc.Name) - PID: $($proc.Id)" `
                "HIGH" `
                $proc.Path `
                80
        }
    }
    
    # Escaneo de archivos en Downloads
    Write-Log "Analizando carpeta Downloads..." "Gray"
    $downloads = "$env:USERPROFILE\Downloads"
    
    if (Test-Path $downloads) {
        $files = Get-ChildItem -Path $downloads -Include "*.exe","*.dll","*.jar" -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) }
        
        foreach ($file in $files) {
            $signatures = Test-CheatSignature $file.Name
            if ($signatures.Count -gt 0) {
                Add-Detection "Archivo Sospechoso" `
                    $file.Name `
                    "HIGH" `
                    $file.FullName `
                    75
            }
        }
    }
    
    Write-Log "Escaneo básico completado" "Green"
}

# ============================================
# GENERACIÓN DE REPORTE SIMPLE
# ============================================

function New-SimpleReport {
    Write-Log "`nGenerando reporte..." "Cyan"
    
    $endTime = Get-Date
    $duration = [math]::Round(($endTime - $startTime).TotalSeconds, 2)
    
    $critical = ($detections | Where-Object { $_.Severity -eq "CRITICAL" }).Count
    $high = ($detections | Where-Object { $_.Severity -eq "HIGH" }).Count
    $medium = ($detections | Where-Object { $_.Severity -eq "MEDIUM" }).Count
    
    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>NEXUS AntiCheat - Reporte</title>
    <style>
        body { font-family: Arial; background: #1a1a2e; color: #e0e0e0; padding: 20px; }
        .header { background: linear-gradient(135deg, #00d9ff 0%, #0099cc 100%); padding: 30px; text-align: center; border-radius: 10px; }
        .header h1 { color: #0a0a0a; margin: 0; }
        .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }
        .stat-card { background: rgba(0,217,255,0.1); padding: 20px; border-radius: 8px; text-align: center; }
        .stat-value { font-size: 2em; color: #00d9ff; font-weight: bold; }
        .detection { background: rgba(255,0,0,0.1); border-left: 4px solid #ff0000; padding: 15px; margin: 10px 0; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>⚡ NEXUS ANTICHEAT v5.0 ⚡</h1>
        <p>Reporte de Escaneo - $timestamp</p>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <div>Duración</div>
            <div class="stat-value">$duration s</div>
        </div>
        <div class="stat-card">
            <div>Detecciones</div>
            <div class="stat-value">$($detections.Count)</div>
        </div>
        <div class="stat-card">
            <div>Críticas</div>
            <div class="stat-value">$critical</div>
        </div>
    </div>
    
    <h2>Detecciones:</h2>
"@
    
    foreach ($det in $detections) {
        $htmlReport += @"
    <div class="detection">
        <strong>[$($det.Severity)] $($det.Category)</strong><br>
        $($det.Detail)<br>
        <small>$($det.Evidence)</small>
    </div>
"@
    }
    
    $htmlReport += @"
</body>
</html>
"@
    
    $htmlReport | Out-File "$outputDir\NEXUS_Report.html" -Encoding UTF8
    Write-Log "Reporte generado: $outputDir\NEXUS_Report.html" "Green"
}

# ============================================
# FUNCIÓN PRINCIPAL
# ============================================

function Start-NexusAntiCheat {
    Write-Log "═══════════════════════════════════════════" "Cyan"
    Write-Log "  INICIANDO NEXUS ANTICHEAT v5.0" "Cyan"
    Write-Log "═══════════════════════════════════════════" "Cyan"
    Write-Log ""
    Write-Log "📍 Directorio: $outputDir" "Gray"
    Write-Log ""
    
    Invoke-BasicScan
    
    New-SimpleReport
    
    Write-Host "`n"
    Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "           ESCANEO COMPLETADO" -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "📊 Detecciones: $($detections.Count)" -ForegroundColor White
    Write-Host "📁 Reporte: $outputDir" -ForegroundColor White
    Write-Host ""
    
    $null = Read-Host "Presiona Enter para abrir el reporte"
    Start-Process "$outputDir\NEXUS_Report.html"
}

# ============================================
# EJECUCIÓN
# ============================================

try {
    Start-NexusAntiCheat
} catch {
    Write-Host "❌ ERROR: $($_.Exception.Message)" -ForegroundColor Red
    $null = Read-Host "Presiona Enter para salir"
}
