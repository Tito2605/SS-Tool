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
$totalChecks = 30
$currentCheck = 0

# Base de datos de firmas (expandida)
$cheatSignatures = @{
    Clients = @(
        "horion", "onix", "zephyr", "packet", "crystal", "ambrosial", "lakeside",
        "nitr0", "koid", "dream", "toolbox", "element", "rise", "fdp", "liquid",
        "azura", "flux", "vertex", "phantom", "ghost", "spectre", "venom", "toxic"
    )
    
    Injectors = @(
        "dll_inject", "process_inject", "xenos", "extreme_injector", "manual_map",
        "loadlibrary", "creepermod", "apollo", "mineshafter", "clientloader"
    )
    
    Modifications = @(
        "xray", "killaura", "bhop", "fly", "reach", "velocity", "antiknockback",
        "scaffold", "freecam", "esp", "tracers", "nametags", "cavefinder",
        "nuker", "fastbreak", "autoarmor", "autoclicker", "aimbot", "triggerbot",
        "antifall", "nofall", "timer", "fastbow", "criticals", "step", "jesus",
        "derp", "blink", "phase", "noslowdown", "antiblind", "fullbright"
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

# Firmas de archivos por magic bytes (primeros bytes del archivo)
$fileMagicBytes = @{
    "EXE" = @("4D5A")  # MZ
    "DLL" = @("4D5A")  # MZ
    "ZIP" = @("504B0304", "504B0506", "504B0708")  # PK
    "RAR" = @("526172211A07")  # Rar!
    "7Z" = @("377ABCAF271C")
    "PNG" = @("89504E47")
    "JPG" = @("FFD8FF")
    "GIF" = @("474946")
    "PDF" = @("25504446")
    "JAR" = @("504B0304")  # Es un ZIP
    "CLASS" = @("CAFEBABE")  # Java class
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
    
    # Verificar si es ejecutable con extensión falsa
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
    
    # Verificar archivos comprimidos con extensión falsa
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
    
    # Verificar imágenes falsas
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

# Lugares ocultos donde los hackers esconden cheats (conocimiento experto)
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

# Extensiones alternativas usadas para ocultar (renombrado)
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
    # Clients de Minecraft Bedrock
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
    
    # Inyectores y loaders
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
    
    # AutoClickers
    AutoClickers = @(
        @{Name="AutoClicker.exe"; Hash=""; ThreatLevel=75},
        @{Name="OpAutoClicker.exe"; Hash=""; ThreatLevel=80},
        @{Name="ghost_client.jar"; Hash=""; ThreatLevel=85},
        @{Name="JNativeHook.dll"; Hash=""; ThreatLevel=70},
        @{Name="jna-4.5.2.jar"; Hash=""; ThreatLevel=65},
        @{Name="clicks_tmp.mp3"; Hash=""; ThreatLevel=60}
    )
    
    # Herramientas de bypass
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
# MÓDULO 1: ANÁLISIS PROFUNDO DE MINECRAFT
# ============================================

function Invoke-MinecraftDeepScan {
    Update-Progress "Analizando instalación de Minecraft..."
    Write-Log "`n=== MÓDULO 1: ANÁLISIS MINECRAFT PROFUNDO ===" "Cyan"
    
    $mcData = @()
    $mcPaths = @{
        UWP = "$env:LOCALAPPDATA\Packages\Microsoft.MinecraftUWP_8wekyb3d8bbwe"
        Java = "$env:APPDATA\.minecraft"
        LocalData = "$env:LOCALAPPDATA\Packages\Microsoft.MinecraftUWP_8wekyb3d8bbwe\LocalState"
        RoamingState = "$env:LOCALAPPDATA\Packages\Microsoft.MinecraftUWP_8wekyb3d8bbwe\RoamingState"
    }
    
    foreach ($pathType in $mcPaths.Keys) {
        $path = $mcPaths[$pathType]
        
        if (Test-Path $path) {
            Write-Log "Escaneando: $pathType" "Gray"
            
            # Buscar archivos modificados recientemente
            $recentFiles = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { 
                    $_.LastWriteTime -gt (Get-Date).AddDays(-7) -and
                    $_.Extension -match '\.(json|js|dll|exe|mcpack|mcaddon|mcworld|zip)$'
                } | Select-Object -First 200
            
            foreach ($file in $recentFiles) {
                $signatures = Test-CheatSignature $file.Name
                $isSuspicious = $signatures.Count -gt 0
                
                # Verificar ubicaciones críticas
                $criticalLocations = @(
                    "RoamingState\Horion",
                    "LocalState\games\com.mojang\minecraftWorlds",
                    "development_behavior_packs",
                    "development_resource_packs"
                )
                
                $inCriticalLocation = $false
                foreach ($loc in $criticalLocations) {
                    if ($file.FullName -like "*$loc*") {
                        $inCriticalLocation = $true
                        break
                    }
                }
                
                if ($isSuspicious) {
                    $threatLevel = 0
                    foreach ($sig in $signatures) {
                        $threatLevel += switch ($sig.Category) {
                            "Clients" { 100 }
                            "Injectors" { 90 }
                            "Modifications" { 70 }
                            default { 50 }
                        }
                    }
                    
                    Add-Detection "Minecraft - Archivo Sospechoso" `
                        "$($file.Name) en $pathType" `
                        "CRITICAL" `
                        $file.FullName `
                        $threatLevel
                }
                
                if ($inCriticalLocation -and $file.Extension -match '\.(dll|exe)$') {
                    Add-Detection "Minecraft - Archivo en Ubicación Crítica" `
                        "$($file.Name) podría ser un client" `
                        "HIGH" `
                        $file.FullName `
                        80
                }
                
                $mcData += [PSCustomObject]@{
                    Type = $pathType
                    Name = $file.Name
                    Extension = $file.Extension
                    Path = $file.FullName
                    Size = $file.Length
                    Created = $file.CreationTime
                    Modified = $file.LastWriteTime
                    Hash = Get-FileHash-Safe $file.FullName
                    Suspicious = $isSuspicious
                    CriticalLocation = $inCriticalLocation
                    Signatures = ($signatures.Signature -join ", ")
                }
            }
            
            # Detectar Horion específicamente
            $horionPath = Join-Path $path "RoamingState\Horion"
            if (Test-Path $horionPath) {
                Add-Detection "Minecraft - Horion Client" `
                    "Directorio Horion detectado" `
                    "CRITICAL" `
                    $horionPath `
                    100
                
                $horionFiles = Get-ChildItem -Path $horionPath -Recurse -ErrorAction SilentlyContinue
                foreach ($hf in $horionFiles) {
                    Add-Detection "Minecraft - Archivo Horion" `
                        $hf.Name `
                        "CRITICAL" `
                        $hf.FullName `
                        95
                }
            }
            
            # Buscar behavior packs modificados
            $bpPath = Join-Path $path "LocalState\games\com.mojang\behavior_packs"
            if (Test-Path $bpPath) {
                $behaviorPacks = Get-ChildItem -Path $bpPath -Recurse -Filter "*.json" -ErrorAction SilentlyContinue
                foreach ($bp in $behaviorPacks) {
                    $content = Get-Content $bp.FullName -Raw -ErrorAction SilentlyContinue
                    if ($content) {
                        $suspiciousPatterns = @(
                            "runtime_identifier",
                            "experiment",
                            "molang",
                            "script_module"
                        )
                        
                        foreach ($pattern in $suspiciousPatterns) {
                            if ($content -match $pattern) {
                                Add-Detection "Minecraft - Behavior Pack Modificado" `
                                    "$($bp.Name) contiene '$pattern'" `
                                    "MEDIUM" `
                                    $bp.FullName `
                                    60
                                break
                            }
                        }
                    }
                }
            }
        }
    }
    
    $mcData | Export-Csv "$outputDir\01_Minecraft_Files.csv" -NoTypeInformation
    Write-Log "Minecraft: $($mcData.Count) archivos analizados" "Green"
}

# ============================================
# MÓDULO 2: ANÁLISIS DE PROCESOS Y DLL INJECTION
# ============================================

function Invoke-ProcessAnalysis {
    Update-Progress "Analizando procesos y DLLs inyectadas..."
    Write-Log "`n=== MÓDULO 2: ANÁLISIS DE PROCESOS ===" "Cyan"
    
    $processData = @()
    $dllInjections = @()
    
    # Obtener todos los procesos
    $processes = Get-Process | Where-Object { $_.Path }
    
    foreach ($proc in $processes) {
        $isMCProcess = $proc.Name -match "(Minecraft|Bedrock)"
        $signatures = Test-CheatSignature $proc.Name
        $isSuspicious = $signatures.Count -gt 0
        
        # Verificar ubicación del ejecutable
        $suspiciousLocation = $false
        if ($proc.Path -match "\\(Temp|Downloads|Desktop|AppData\\Local\\Temp|Documents)\\") {
            $suspiciousLocation = $true
            Add-Detection "Proceso - Ubicación Sospechosa" `
                "$($proc.Name) ejecutándose desde ubicación temporal" `
                "HIGH" `
                $proc.Path `
                75
        }
        
        if ($isSuspicious) {
            Add-Detection "Proceso - Nombre Sospechoso" `
                "$($proc.Name) - PID: $($proc.Id)" `
                "HIGH" `
                $proc.Path `
                85
        }
        
        # Analizar módulos (DLLs) cargados
        if ($isMCProcess) {
            try {
                $modules = $proc.Modules
                
                foreach ($mod in $modules) {
                    $modPath = $mod.FileName
                    $modSigs = Test-CheatSignature $mod.ModuleName
                    
                    # DLL sospechosa por nombre
                    if ($modSigs.Count -gt 0) {
                        Add-Detection "DLL Injection - Nombre Sospechoso" `
                            "$($mod.ModuleName) en Minecraft (PID: $($proc.Id))" `
                            "CRITICAL" `
                            $modPath `
                            100
                        
                        $dllInjections += [PSCustomObject]@{
                            Process = $proc.Name
                            PID = $proc.Id
                            DLL = $mod.ModuleName
                            Path = $modPath
                            Size = $mod.Size
                            Reason = "Nombre sospechoso"
                            Signatures = ($modSigs.Signature -join ", ")
                        }
                    }
                    
                    # DLL desde ubicación no estándar
                    if ($modPath -match "\\(Temp|Downloads|Desktop|AppData\\Local\\Temp|Documents)\\") {
                        Add-Detection "DLL Injection - Ubicación Temporal" `
                            "$($mod.ModuleName) cargado desde ubicación sospechosa" `
                            "HIGH" `
                            $modPath `
                            90
                        
                        $dllInjections += [PSCustomObject]@{
                            Process = $proc.Name
                            PID = $proc.Id
                            DLL = $mod.ModuleName
                            Path = $modPath
                            Reason = "Ubicación temporal"
                        }
                    }
                    
                    # DLL sin firma digital
                    if ($modPath -and (Test-Path $modPath)) {
                        $sig = Get-AuthenticodeSignature $modPath -ErrorAction SilentlyContinue
                        if ($sig -and $sig.Status -ne "Valid" -and $modPath -notmatch "C:\\Windows\\") {
                            Add-Detection "DLL Injection - Sin Firma Válida" `
                                "$($mod.ModuleName) en Minecraft" `
                                "MEDIUM" `
                                $modPath `
                                70
                            
                            $dllInjections += [PSCustomObject]@{
                                Process = $proc.Name
                                PID = $proc.Id
                                DLL = $mod.ModuleName
                                Path = $modPath
                                Reason = "Sin firma válida ($($sig.Status))"
                            }
                        }
                    }
                }
            } catch {
                Write-Log "No se pudo analizar módulos del proceso $($proc.Name)" "Yellow"
            }
        }
        
        $processData += [PSCustomObject]@{
            Name = $proc.Name
            PID = $proc.Id
            Path = $proc.Path
            StartTime = $proc.StartTime
            CPU = $proc.CPU
            WorkingSet = [math]::Round($proc.WorkingSet64 / 1MB, 2)
            Suspicious = $isSuspicious
            SuspiciousLocation = $suspiciousLocation
            IsMinecraft = $isMCProcess
            Signatures = ($signatures.Signature -join ", ")
        }
    }
    
    # Buscar DLLs de cheats en todo el sistema
    $knownCheatDLLs = @(
        "horion.dll", "onix.dll", "packet.dll", "crystal.dll", "zephyr.dll",
        "element.dll", "toolbox.dll", "ambrosial.dll", "nitr0.dll"
    )
    
    foreach ($cheatDLL in $knownCheatDLLs) {
        $found = Get-ChildItem -Path C:\ -Filter $cheatDLL -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 3
        
        foreach ($file in $found) {
            Add-Detection "Cheat DLL - Archivo Conocido" `
                "$cheatDLL encontrado" `
                "CRITICAL" `
                $file.FullName `
                100
        }
    }
    
    $processData | Export-Csv "$outputDir\02_Processes.csv" -NoTypeInformation
    $dllInjections | Export-Csv "$outputDir\02_DLL_Injections.csv" -NoTypeInformation
    Write-Log "Procesos: $($processData.Count) analizados, $($dllInjections.Count) DLLs sospechosas" "Green"
}

# ============================================
# MÓDULO 3: PREFETCH AVANZADO
# ============================================

function Invoke-PrefetchAnalysis {
    Update-Progress "Analizando Prefetch (historial de ejecución)..."
    Write-Log "`n=== MÓDULO 3: ANÁLISIS PREFETCH ===" "Cyan"
    
    $prefetchPath = "C:\Windows\Prefetch"
    $prefetchData = @()
    
    if (Test-Path $prefetchPath) {
        $prefetchFiles = Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue
        
        foreach ($pf in $prefetchFiles) {
            $signatures = Test-CheatSignature $pf.Name
            $isSuspicious = $signatures.Count -gt 0
            $daysAgo = [math]::Round(((Get-Date) - $pf.LastWriteTime).TotalDays, 2)
            $hoursAgo = [math]::Round(((Get-Date) - $pf.LastWriteTime).TotalHours, 2)
            
            # Detección de cheats
            if ($isSuspicious) {
                Add-Detection "Prefetch - Ejecución de Cheat" `
                    "$($pf.Name) ejecutado hace $daysAgo días" `
                    "HIGH" `
                    $pf.FullName `
                    80
            }
            
            # Herramientas de inyección
            if ($pf.Name -match "(DLLHOST|RUNDLL32|REGSVR32|INJECTOR)") {
                Add-Detection "Prefetch - Posible Inyección DLL" `
                    "$($pf.Name) - hace $hoursAgo horas" `
                    "HIGH" `
                    $pf.FullName `
                    75
            }
            
            # Scripts y comandos sospechosos
            if ($pf.Name -match "(CMD|POWERSHELL|WMIC|FSUTIL)" -and $hoursAgo -le 24) {
                Add-Detection "Prefetch - Script Reciente" `
                    "$($pf.Name) ejecutado recientemente" `
                    "MEDIUM" `
                    $pf.FullName `
                    65
            }
            
            # Modificadores de archivos
            if ($pf.Name -match "(SETFILEDATE|TIMESTOMP|FILETOUCH)") {
                Add-Detection "Prefetch - Herramienta de Manipulación" `
                    "$($pf.Name) - usado para ocultar rastros" `
                    "HIGH" `
                    $pf.FullName `
                    85
            }
            
            $prefetchData += [PSCustomObject]@{
                FileName = $pf.Name
                LastExecution = $pf.LastWriteTime
                DaysAgo = $daysAgo
                HoursAgo = $hoursAgo
                Size = $pf.Length
                Suspicious = $isSuspicious
                Signatures = ($signatures.Signature -join ", ")
            }
        }
        
        $prefetchData | Export-Csv "$outputDir\03_Prefetch.csv" -NoTypeInformation
        Write-Log "Prefetch: $($prefetchFiles.Count) archivos analizados" "Green"
    } else {
        Write-Log "Prefetch: NO DISPONIBLE (puede estar deshabilitado)" "Red"
        Add-Detection "Sistema - Prefetch Deshabilitado" `
            "El Prefetch está deshabilitado o inaccesible" `
            "CRITICAL" `
            $prefetchPath `
            90
    }
}

# ============================================
# MÓDULO 4: BAM (Background Activity Moderator)
# ============================================

function Invoke-BAMAnalysis {
    Update-Progress "Extrayendo BAM (historial de actividad)..."
    Write-Log "`n=== MÓDULO 4: ANÁLISIS BAM ===" "Cyan"
    
    $bamData = @()
    $bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
    
    if (Test-Path $bamPath) {
        $bamUsers = Get-ChildItem $bamPath -ErrorAction SilentlyContinue
        
        foreach ($user in $bamUsers) {
            $entries = Get-ItemProperty -Path $user.PSPath -ErrorAction SilentlyContinue
            
            foreach ($prop in $entries.PSObject.Properties) {
                if ($prop.Name -like "*\*" -and $prop.Name -notlike "PS*") {
                    $execPath = $prop.Name
                    $signatures = Test-CheatSignature $execPath
                    
                    if ($signatures.Count -gt 0) {
                        Add-Detection "BAM - Ejecución de Cheat" `
                            $execPath `
                            "HIGH" `
                            $execPath `
                            80
                    }
                    
                    # Verificar ubicaciones sospechosas
                    if ($execPath -match "\\(Temp|Downloads|Desktop|AppData)\\") {
                        Add-Detection "BAM - Ejecución desde Ubicación Temporal" `
                            $execPath `
                            "MEDIUM" `
                            $execPath `
                            65
                    }
                    
                    $bamData += [PSCustomObject]@{
                        Path = $execPath
                        User = $user.PSChildName
                        Suspicious = ($signatures.Count -gt 0)
                        Signatures = ($signatures.Signature -join ", ")
                    }
                }
            }
        }
        
        $bamData | Export-Csv "$outputDir\04_BAM.csv" -NoTypeInformation
        Write-Log "BAM: $($bamData.Count) ejecuciones registradas" "Green"
    } else {
        Write-Log "BAM: NO DISPONIBLE" "Red"
        Add-Detection "Sistema - BAM Inaccesible" `
            "BAM no está disponible o deshabilitado" `
            "HIGH" `
            $bamPath `
            75
    }
}

# ============================================
# MÓDULO 5: ARCHIVOS TEMPORALES Y RESIDUOS
# ============================================

function Invoke-TempAnalysis {
    Update-Progress "Analizando archivos temporales..."
    Write-Log "`n=== MÓDULO 5: ANÁLISIS TEMP ===" "Cyan"
    
    $tempFindings = @()
    
    # Firmas específicas de AutoClickers
    $autoClickerSigs = @(
        "JNativeHook*", "jna-*.jar", "jansi-*.jar", "air.exe", "clicks_tmp.mp3",
        "Rar`$ex*", "7z*", "ghost-*", "mouse_rec*", "auto_*", "macro_*"
    )
    
    foreach ($sig in $autoClickerSigs) {
        $found = Get-ChildItem -Path $env:TEMP -Filter $sig -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-14) }
        
        foreach ($file in $found) {
            Add-Detection "AutoClicker - Residuo Detectado" `
                "$($file.Name) en TEMP" `
                "HIGH" `
                $file.FullName `
                85
            
            $tempFindings += [PSCustomObject]@{
                Type = "AutoClicker"
                Name = $file.Name
                Path = $file.FullName
                Size = $file.Length
                Modified = $file.LastWriteTime
                Hash = Get-FileHash-Safe $file.FullName
            }
        }
    }
    
    # Archivos ejecutables y DLLs recientes
    $tempFiles = Get-ChildItem -Path $env:TEMP -Include "*.exe","*.dll","*.jar","*.bat","*.ps1" -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }
    
    foreach ($file in $tempFiles) {
        $signatures = Test-CheatSignature $file.Name
        
        if ($signatures.Count -gt 0) {
            Add-Detection "Temp - Archivo Sospechoso" `
                $file.Name `
                "HIGH" `
                $file.FullName `
                80
            
            $tempFindings += [PSCustomObject]@{
                Type = "Suspicious"
                Name = $file.Name
                Path = $file.FullName
                Size = $file.Length
                Modified = $file.LastWriteTime
                Signatures = ($signatures.Signature -join ", ")
                Hash = Get-FileHash-Safe $file.FullName
            }
        }
    }
    
    # Buscar extractores de RAR/ZIP (común en cheats empaquetados)
    $extractorPatterns = @("Rar$*", "7z*", "WinRAR*", "unzip*")
    foreach ($pattern in $extractorPatterns) {
        $found = Get-ChildItem -Path $env:TEMP -Filter $pattern -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-48) }
        
        if ($found.Count -gt 3) {
            Add-Detection "Temp - Múltiples Extractores" `
                "$($found.Count) archivos de extracción recientes" `
                "MEDIUM" `
                $env:TEMP `
                60
        }
    }
    
    $tempFindings | Export-Csv "$outputDir\05_Temp_Files.csv" -NoTypeInformation
    Write-Log "Temp: $($tempFindings.Count) archivos sospechosos" "Green"
}

# ============================================
# MÓDULO 6: REGISTRO DE WINDOWS
# ============================================

function Invoke-RegistryAnalysis {
    Update-Progress "Analizando registro de Windows..."
    Write-Log "`n=== MÓDULO 6: ANÁLISIS DE REGISTRO ===" "Cyan"
    
    $regData = @()
    
    # AppCompatFlags Store
    $storePath = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
    if (Test-Path $storePath) {
        $entries = Get-ItemProperty -Path $storePath -ErrorAction SilentlyContinue
        
        foreach ($prop in $entries.PSObject.Properties) {
            if ($prop.Name -like "*\*" -and $prop.Name -notlike "PS*") {
                $signatures = Test-CheatSignature $prop.Name
                
                if ($signatures.Count -gt 0) {
                    Add-Detection "Registro - Store Sospechoso" `
                        $prop.Name `
                        "MEDIUM" `
                        "HKCU:\...\Store\$($prop.Name)" `
                        65
                }
                
                $regData += [PSCustomObject]@{
                    Source = "AppCompatFlags"
                    Key = $prop.Name
                    Value = $prop.Value
                    Suspicious = ($signatures.Count -gt 0)
                    Signatures = ($signatures.Signature -join ", ")
                }
            }
        }
    }
    
    # Run Keys (Autostart)
    $runKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    foreach ($runKey in $runKeys) {
        if (Test-Path $runKey) {
            $entries = Get-ItemProperty -Path $runKey -ErrorAction SilentlyContinue
            
            foreach ($prop in $entries.PSObject.Properties) {
                if ($prop.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) {
                    $signatures = Test-CheatSignature "$($prop.Name) $($prop.Value)"
                    
                    if ($signatures.Count -gt 0) {
                        Add-Detection "Registro - Startup Sospechoso" `
                            "$($prop.Name): $($prop.Value)" `
                            "HIGH" `
                            $runKey `
                            85
                    }
                    
                    $regData += [PSCustomObject]@{
                        Source = "Run Keys"
                        Key = $runKey
                        Name = $prop.Name
                        Value = $prop.Value
                        Suspicious = ($signatures.Count -gt 0)
                        Signatures = ($signatures.Signature -join ", ")
                    }
                }
            }
        }
    }
    
    # TCP/IP Settings (Lag Reduction)
    $tcpPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
        "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
    )
    
    foreach ($tcpPath in $tcpPaths) {
        if (Test-Path $tcpPath) {
            if ($tcpPath -like "*\Interfaces") {
                $interfaces = Get-ChildItem $tcpPath -ErrorAction SilentlyContinue
                foreach ($iface in $interfaces) {
                    $tcpEntries = Get-ItemProperty -Path $iface.PSPath -ErrorAction SilentlyContinue
                    $suspiciousKeys = @("TcpAckFrequency","TCPNoDelay","TcpDelAckTicks")
                    
                    foreach ($key in $suspiciousKeys) {
                        if ($tcpEntries.PSObject.Properties.Name -contains $key) {
                            Add-Detection "Registro - TCP Modificado (Lag Reduction)" `
                                "$key = $($tcpEntries.$key) en interfaz" `
                                "HIGH" `
                                $iface.PSPath `
                                80
                        }
                    }
                }
            } else {
                $tcpEntries = Get-ItemProperty -Path $tcpPath -ErrorAction SilentlyContinue
                $suspiciousKeys = @("TcpAckFrequency","TCPNoDelay","TcpDelAckTicks","DefaultTTL")
                
                foreach ($key in $suspiciousKeys) {
                    if ($tcpEntries.PSObject.Properties.Name -contains $key) {
                        Add-Detection "Registro - TCP Modificado (Lag Reduction)" `
                            "$key = $($tcpEntries.$key)" `
                            "HIGH" `
                            $tcpPath `
                            80
                    }
                }
            }
        }
    }
    
    # Uninstall Keys (Software instalado)
    $uninstallKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    foreach ($uninstallKey in $uninstallKeys) {
        $apps = Get-ItemProperty $uninstallKey -ErrorAction SilentlyContinue
        foreach ($app in $apps) {
            if ($app.DisplayName) {
                $signatures = Test-CheatSignature $app.DisplayName
                if ($signatures.Count -gt 0) {
                    Add-Detection "Registro - Software Sospechoso Instalado" `
                        $app.DisplayName `
                        "HIGH" `
                        $app.PSPath `
                        85
                }
            }
        }
    }
    
    $regData | Export-Csv "$outputDir\06_Registry.csv" -NoTypeInformation
    Write-Log "Registro: $($regData.Count) entradas analizadas" "Green"
}

# ============================================
# MÓDULO 7: USN JOURNAL
# ============================================

function Invoke-JournalAnalysis {
    Update-Progress "Analizando USN Journal..."
    Write-Log "`n=== MÓDULO 7: ANÁLISIS USN JOURNAL ===" "Cyan"
    
    $journalData = @()
    
    try {
        # Archivos ejecutables eliminados
        $deletedExe = fsutil usn readjournal c: csv 2>$null | 
            Select-String -Pattern "\.exe.*0x80000200" |
            Select-Object -First 100
        
        foreach ($line in $deletedExe) {
            $parts = $line -split ","
            if ($parts.Count -ge 2) {
                $fileName = $parts[1].Trim('"')
                $signatures = Test-CheatSignature $fileName
                
                if ($signatures.Count -gt 0) {
                    Add-Detection "Journal - Cheat Eliminado" `
                        $fileName `
                        "HIGH" `
                        "USN Journal" `
                        85
                }
                
                $journalData += [PSCustomObject]@{
                    Type = "Deleted EXE"
                    File = $fileName
                    Suspicious = ($signatures.Count -gt 0)
                    Signatures = ($signatures.Signature -join ", ")
                }
            }
        }
        
        # Prefetch eliminados
        $deletedPf = fsutil usn readjournal c: csv 2>$null |
            Select-String -Pattern "\.pf.*0x80000200" |
            Select-Object -First 50
        
        foreach ($line in $deletedPf) {
            Add-Detection "Journal - Prefetch Eliminado" `
                $line `
                "HIGH" `
                "USN Journal" `
                80
            
            $journalData += [PSCustomObject]@{
                Type = "Deleted Prefetch"
                File = $line
                Suspicious = $true
            }
        }
        
        # DLLs eliminadas
        $deletedDll = fsutil usn readjournal c: csv 2>$null |
            Select-String -Pattern "\.dll.*0x80000200" |
            Select-Object -First 50
        
        foreach ($line in $deletedDll) {
            $parts = $line -split ","
            if ($parts.Count -ge 2) {
                $fileName = $parts[1].Trim('"')
                $signatures = Test-CheatSignature $fileName
                
                if ($signatures.Count -gt 0) {
                    Add-Detection "Journal - DLL de Cheat Eliminada" `
                        $fileName `
                        "CRITICAL" `
                        "USN Journal" `
                        95
                }
            }
        }
        
        Write-Log "Journal: $($journalData.Count) cambios críticos detectados" "Green"
    } catch {
        Write-Log "Journal: Error al acceder - $($_.Exception.Message)" "Red"
    }
    
    $journalData | Export-Csv "$outputDir\07_USN_Journal.csv" -NoTypeInformation
}

# ============================================
# MÓDULO 8: DISPOSITIVOS USB Y EXTERNOS
# ============================================

function Invoke-USBAnalysis {
    Update-Progress "Verificando dispositivos USB..."
    Write-Log "`n=== MÓDULO 8: ANÁLISIS USB ===" "Cyan"
    
    $usbData = @()
    
    # Dispositivos USB actuales
    $currentUSBs = Get-WmiObject Win32_USBHub -ErrorAction SilentlyContinue
    foreach ($usb in $currentUSBs) {
        $usbData += [PSCustomObject]@{
            Type = "Current Device"
            DeviceID = $usb.DeviceID
            Description = $usb.Description
            Status = $usb.Status
            Timestamp = Get-Date
        }
    }
    
    # Historial USB en registro
    $usbRegPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
    if (Test-Path $usbRegPath) {
        $usbHistory = Get-ChildItem -Path $usbRegPath -Recurse -ErrorAction SilentlyContinue
        foreach ($usb in $usbHistory) {
            $usbData += [PSCustomObject]@{
                Type = "Historical Device"
                Device = $usb.PSChildName
                Path = $usb.PSPath
            }
        }
    }
    
    # Eventos de desconexión reciente
    try {
        $usbEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-Kernel-PnP/Configuration'
            ID = @(400,410,420)
        } -MaxEvents 100 -ErrorAction SilentlyContinue
        
        foreach ($event in $usbEvents) {
            $minutesAgo = [math]::Round(((Get-Date) - $event.TimeCreated).TotalMinutes, 0)
            
            if ($minutesAgo -le 120) {
                Add-Detection "USB - Dispositivo Desconectado Recientemente" `
                    "Hace $minutesAgo minutos" `
                    "HIGH" `
                    "Event ID: $($event.Id)" `
                    75
            }
        }
    } catch {}
    
    # Detectar FAT32 (común en bypass USB)
    $volumes = Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.FileSystemType -eq "FAT32" }
    foreach ($vol in $volumes) {
        if ($vol.DriveLetter) {
            Add-Detection "USB - Volumen FAT32 Detectado" `
                "Letra: $($vol.DriveLetter) - Tamaño: $([Math]::Round($vol.Size/1GB, 2))GB" `
                "MEDIUM" `
                "Drive $($vol.DriveLetter):" `
                60
        }
    }
    
    $usbData | Export-Csv "$outputDir\08_USB_Devices.csv" -NoTypeInformation
    Write-Log "USB: $($currentUSBs.Count) dispositivos actuales, $($usbHistory.Count) en historial" "Green"
}

# ============================================
# MÓDULO 9: DETECCIÓN DE MACROS
# ============================================

function Invoke-MacroAnalysis {
    Update-Progress "Detectando macros en periféricos..."
    Write-Log "`n=== MÓDULO 9: ANÁLISIS DE MACROS ===" "Cyan"
    
    $macroData = @()
    
    # === LOGITECH G HUB ===
    $logitechPaths = @(
        "$env:LOCALAPPDATA\LGHUB\settings.db",
        "$env:LOCALAPPDATA\LGHUB\settings.json",
        "$env:APPDATA\Logitech\Logitech Gaming Software\settings.json",
        "$env:APPDATA\Logitech\Logitech Gaming Software\profiles"
    )
    
    foreach ($path in $logitechPaths) {
        if (Test-Path $path) {
            $file = Get-Item $path
            $hoursSince = [math]::Round(((Get-Date) - $file.LastWriteTime).TotalHours, 2)
            
            if ($hoursSince -lt 4) {
                Add-Detection "Macro - Logitech Modificado Recientemente" `
                    "$path - Hace $hoursSince horas" `
                    "HIGH" `
                    $path `
                    85
            }
            
            $macroData += [PSCustomObject]@{
                Brand = "Logitech"
                Type = "Settings"
                Path = $path
                Modified = $file.LastWriteTime
                HoursSince = $hoursSince
                Suspicious = ($hoursSince -lt 4)
            }
        }
    }
    
    $lghubProcess = Get-Process -Name "lghub*" -ErrorAction SilentlyContinue
    if ($lghubProcess) {
        Add-Detection "Macro - Logitech G HUB Activo" `
            "Software de macros en ejecución" `
            "MEDIUM" `
            $lghubProcess.Path `
            70
    }
    
    # === RAZER SYNAPSE ===
    $razerPaths = @(
        "$env:APPDATA\Razer\Synapse3\Log\Razer Macros3.txt",
        "$env:PROGRAMDATA\Razer\Synapse3\Log\SynapseService.log",
        "$env:PROGRAMDATA\Razer\Synapse3\Settings\Settings.json"
    )
    
    foreach ($path in $razerPaths) {
        if (Test-Path $path) {
            $content = Get-Content $path -Tail 200 -ErrorAction SilentlyContinue
            
            if ($content -match "MacroClient:Delete") {
                Add-Detection "Macro - Razer Macro Eliminado" `
                    "Detectada eliminación en logs" `
                    "HIGH" `
                    $path `
                    85
            }
            
            if ($content -match "turbo:\s*true") {
                Add-Detection "Macro - Razer Turbo Mode Activo" `
                    "Modo turbo detectado" `
                    "CRITICAL" `
                    $path `
                    95
            }
            
            $macroData += [PSCustomObject]@{
                Brand = "Razer"
                Type = "Log"
                Path = $path
                HasMacroDelete = ($content -match "MacroClient:Delete")
                HasTurbo = ($content -match "turbo:\s*true")
            }
        }
    }
    
    # === CORSAIR iCUE ===
    $corsairPaths = @(
        "$env:APPDATA\Corsair\CUE\Config.cuecf",
        "$env:APPDATA\Corsair\CUE4\settings.json"
    )
    
    foreach ($path in $corsairPaths) {
        if (Test-Path $path) {
            $content = Get-Content $path -ErrorAction SilentlyContinue
            if ($content -match "RecMouseClicksEnable") {
                Add-Detection "Macro - Corsair Grabación Habilitada" `
                    "Grabación de clicks detectada" `
                    "HIGH" `
                    $path `
                    80
            }
        }
    }
    
    # === BLOODY / A4TECH ===
    $bloodyPath = "$env:PROGRAMFILES(x86)\Bloody7\Bloody7\Data"
    if (Test-Path $bloodyPath) {
        $files = Get-ChildItem $bloodyPath -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }
        
        if ($files.Count -gt 0) {
            Add-Detection "Macro - Bloody7 Activo" `
                "$($files.Count) archivos modificados recientemente" `
                "HIGH" `
                $bloodyPath `
                85
        }
    }
    
    # === STEELSERIES ===
    $steelProcess = Get-Process -Name "SteelSeriesGGClient" -ErrorAction SilentlyContinue
    if ($steelProcess) {
        Add-Detection "Macro - SteelSeries Activo" `
            "Software detectado" `
            "MEDIUM" `
            $steelProcess.Path `
                    65
    }
    
    # Información del mouse actual
    $mouseInfo = Get-WmiObject Win32_PointingDevice -ErrorAction SilentlyContinue
    foreach ($mouse in $mouseInfo) {
        $macroData += [PSCustomObject]@{
            Brand = "Current Mouse"
            Type = "Device"
            Name = $mouse.Name
            Manufacturer = $mouse.Manufacturer
            DeviceID = $mouse.DeviceID
        }
    }
    
    $macroData | Export-Csv "$outputDir\09_Mouse_Macros.csv" -NoTypeInformation
    Write-Log "Macros: $($macroData.Count) configuraciones verificadas" "Green"
}

# ============================================
# MÓDULO 10: HERRAMIENTAS ANTI-DETECCIÓN
# ============================================

function Invoke-AntiDetectionAnalysis {
    Update-Progress "Detectando herramientas anti-detección..."
    Write-Log "`n=== MÓDULO 10: ANTI-DETECCIÓN ===" "Cyan"
    
    $antiDetectApps = @()
    
    # Herramientas de ocultación
    $hiddenTools = @(
        "Noob No Observer", "Hide Window", "Window Hider", 
        "Wise Folder Hider", "IObit Unlocker", "Free Hide Folder",
        "My Lockbox", "Folder Guard", "Protected Folder"
    )
    
    foreach ($tool in $hiddenTools) {
        # Buscar en procesos
        $foundProc = Get-Process -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match $tool.Replace(" ", "") }
        
        if ($foundProc) {
            Add-Detection "Anti-Detección - Herramienta Activa" `
                "$tool en ejecución" `
                "CRITICAL" `
                $foundProc.Path `
                100
            
            $antiDetectApps += [PSCustomObject]@{
                Type = "Active Process"
                Tool = $tool
                PID = $foundProc.Id
                Path = $foundProc.Path
            }
        }
        
        # Buscar instalación
        $foundFile = Get-ChildItem -Path "C:\Program Files*" `
            -Filter "*$($tool.Replace(' ',''))*" `
            -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 1
        
        if ($foundFile) {
            Add-Detection "Anti-Detección - Herramienta Instalada" `
                "$tool instalado" `
                "HIGH" `
                $foundFile.FullName `
                90
            
            $antiDetectApps += [PSCustomObject]@{
                Type = "Installed"
                Tool = $tool
                Path = $foundFile.FullName
            }
        }
    }
    
    # Wise Folder Hider específico
    $wisePaths = @("C:\wisefs.dat", "C:\ProgramData\wisefs.dat")
    foreach ($wisePath in $wisePaths) {
        if (Test-Path $wisePath) {
            Add-Detection "Anti-Detección - Wise Folder Hider" `
                "wisefs.dat encontrado" `
                "CRITICAL" `
                $wisePath `
                100
        }
    }
    
    # Procesos sin ventana (ocultos)
    $hiddenProcs = Get-Process -ErrorAction SilentlyContinue |
        Where-Object { 
            $_.MainWindowHandle -eq 0 -and 
            $_.ProcessName -notmatch "^(svchost|System|Registry|smss|csrss|wininit|services|lsass)$"
        }
    
    foreach ($proc in $hiddenProcs) {
        $signatures = Test-CheatSignature $proc.Name
        if ($signatures.Count -gt 0) {
            Add-Detection "Anti-Detección - Proceso Oculto Sospechoso" `
                "$($proc.Name) sin ventana" `
                "HIGH" `
                $proc.Path `
                85
        }
    }
    
    # Bypass de screenshare
    $screenShareBypass = @("NoObserver", "OBS Virtual", "ScreenBlock", "AntiScreenShare")
    foreach ($bypass in $screenShareBypass) {
        $foundProc = Get-Process -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "*$bypass*" }
        
        if ($foundProc) {
            Add-Detection "Anti-Detección - Bypass de Screenshare" `
                $foundProc.Name `
                "CRITICAL" `
                $foundProc.Path `
                100
        }
    }
    
    $antiDetectApps | Export-Csv "$outputDir\10_AntiDetection.csv" -NoTypeInformation
    Write-Log "Anti-Detección: $($antiDetectApps.Count) herramientas verificadas" "Green"
}

# ============================================
# MÓDULO 11: SERVICIOS CRÍTICOS
# ============================================

function Invoke-ServiceAnalysis {
    Update-Progress "Verificando servicios del sistema..."
    Write-Log "`n=== MÓDULO 11: SERVICIOS CRÍTICOS ===" "Cyan"
    
    $criticalServices = @("EventLog", "SysMain", "DPS", "PcaSvc", "Diagtrack", "bam", "WinDefend")
    $serviceResults = @()
    
    foreach ($svc in $criticalServices) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service) {
            $isSuspicious = ($service.Status -ne "Running")
            
            if ($isSuspicious) {
                Add-Detection "Servicio - Deshabilitado/Detenido" `
                    "$svc está $($service.Status)" `
                    "CRITICAL" `
                    "Service: $svc" `
                    95
            }
            
            $serviceResults += [PSCustomObject]@{
                Service = $svc
                Status = $service.Status
                StartType = $service.StartType
                Suspicious = $isSuspicious
            }
        }
    }
    
    $serviceResults | Export-Csv "$outputDir\11_Services.csv" -NoTypeInformation
    Write-Log "Servicios: $($serviceResults.Count) verificados" "Green"
}

# ============================================
# MÓDULO 12: CONEXIONES DE RED
# ============================================

function Invoke-NetworkAnalysis {
    Update-Progress "Analizando conexiones de red..."
    Write-Log "`n=== MÓDULO 12: CONEXIONES DE RED ===" "Cyan"
    
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    $connData = @()
    
    # IPs sospechosas de servidores de cheats (ejemplo)
    $suspiciousIPs = @("185.193.126", "45.142.212", "193.239.85")
    
    foreach ($conn in $connections) {
        try {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            
            if ($proc) {
                $signatures = Test-CheatSignature $proc.Name
                $isSuspiciousIP = $false
                
                foreach ($suspIP in $suspiciousIPs) {
                    if ($conn.RemoteAddress -like "$suspIP*") {
                        $isSuspiciousIP = $true
                        break
                    }
                }
                
                if ($signatures.Count -gt 0) {
                    Add-Detection "Red - Proceso Sospechoso Conectado" `
                        "$($proc.Name) -> $($conn.RemoteAddress):$($conn.RemotePort)" `
                        "HIGH" `
                        $proc.Path `
                        85
                }
                
                if ($isSuspiciousIP) {
                    Add-Detection "Red - Conexión a IP Sospechosa" `
                        "$($proc.Name) -> $($conn.RemoteAddress)" `
                        "HIGH" `
                        $proc.Path `
                        80
                }
                
                $connData += [PSCustomObject]@{
                    Process = $proc.Name
                    PID = $proc.Id
                    LocalPort = $conn.LocalPort
                    RemoteAddress = $conn.RemoteAddress
                    RemotePort = $conn.RemotePort
                    Suspicious = ($signatures.Count -gt 0 -or $isSuspiciousIP)
                }
            }
        } catch {}
    }
    
    $connData | Export-Csv "$outputDir\12_Network.csv" -NoTypeInformation
    Write-Log "Red: $($connections.Count) conexiones analizadas" "Green"
}

# ============================================
# MÓDULO 13: ARCHIVOS RECIENTES
# ============================================

function Invoke-RecentFilesAnalysis {
    Update-Progress "Analizando archivos recientes..."
    Write-Log "`n=== MÓDULO 13: ARCHIVOS RECIENTES ===" "Cyan"
    
    $recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
    $recentData = @()
    
    if (Test-Path $recentPath) {
        $recentFiles = Get-ChildItem -Path $recentPath -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-14) }
        
        foreach ($file in $recentFiles) {
            $signatures = Test-CheatSignature $file.Name
            
            if ($signatures.Count -gt 0) {
                Add-Detection "Reciente - Archivo Sospechoso" `
                    $file.Name `
                    "MEDIUM" `
                    $file.FullName `
                    65
            }
            
            $recentData += [PSCustomObject]@{
                Name = $file.Name
                LastAccess = $file.LastWriteTime
                Suspicious = ($signatures.Count -gt 0)
                Signatures = ($signatures.Signature -join ", ")
            }
        }
    }
    
    $recentData | Export-Csv "$outputDir\13_Recent_Files.csv" -NoTypeInformation
    Write-Log "Recientes: $($recentData.Count) archivos" "Green"
}

# ============================================
# MÓDULO 14: TAREAS PROGRAMADAS
# ============================================

function Invoke-TaskAnalysis {
    Update-Progress "Verificando tareas programadas..."
    Write-Log "`n=== MÓDULO 14: TAREAS PROGRAMADAS ===" "Cyan"
    
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.State -ne "Disabled" }
    
    $taskData = @()
    
    foreach ($task in $tasks) {
        $signatures = Test-CheatSignature $task.TaskName
        
        if ($signatures.Count -gt 0) {
            $taskInfo = $task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            
            Add-Detection "Tarea - Nombre Sospechoso" `
                $task.TaskName `
                "HIGH" `
                $task.TaskPath `
                80
            
            $taskData += [PSCustomObject]@{
                Name = $task.TaskName
                Path = $task.TaskPath
                State = $task.State
                LastRunTime = $taskInfo.LastRunTime
                Suspicious = $true
                Signatures = ($signatures.Signature -join ", ")
            }
        }
    }
    
    $taskData | Export-Csv "$outputDir\14_Tasks.csv" -NoTypeInformation
    Write-Log "Tareas: $($tasks.Count) verificadas, $($taskData.Count) sospechosas" "Green"
}

# ============================================
# MÓDULO 15: HISTORIAL POWERSHELL
# ============================================

function Invoke-PowerShellHistory {
    Update-Progress "Analizando historial PowerShell..."
    Write-Log "`n=== MÓDULO 15: HISTORIAL POWERSHELL ===" "Cyan"
    
    $psHistoryPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    $suspiciousCmds = @()
    
    if (Test-Path $psHistoryPath) {
        $psHistory = Get-Content $psHistoryPath -ErrorAction SilentlyContinue
        
        $dangerousPatterns = @(
            "fsutil", "wmic", "reg delete", "bypass", "invoke-", "downloadstring",
            "horion", "cheat", "setfiledate", "timestomp", "hidden", "noprofile",
            "executionpolicy bypass", "system.net.webclient"
        )
        
        foreach ($cmd in $psHistory) {
            foreach ($pattern in $dangerousPatterns) {
                if ($cmd -match $pattern) {
                    Add-Detection "PowerShell - Comando Sospechoso" `
                        $cmd `
                        "HIGH" `
                        $psHistoryPath `
                        85
                    
                    $suspiciousCmds += $cmd
                    break
                }
            }
        }
        
        if ($suspiciousCmds.Count -gt 0) {
            $suspiciousCmds | Out-File "$outputDir\15_PowerShell_History.txt"
        }
    }
    
    Write-Log "PowerShell: $($suspiciousCmds.Count) comandos sospechosos" "Green"
}

# ============================================
# MÓDULO 16: PAPELERA DE RECICLAJE
# ============================================

function Invoke-RecycleBinAnalysis {
    Update-Progress "Verificando papelera de reciclaje..."
    Write-Log "`n=== MÓDULO 16: PAPELERA DE RECICLAJE ===" "Cyan"
    
    $recycleBin = "C:\`$Recycle.Bin"
    
    if (Test-Path $recycleBin) {
        $binInfo = Get-Item $recycleBin -Force -ErrorAction SilentlyContinue
        
        if ($binInfo) {
            $hoursSince = [math]::Round(((Get-Date) - $binInfo.LastWriteTime).TotalHours, 2)
            
            if ($hoursSince -lt 2) {
                Add-Detection "Papelera - Modificación Reciente" `
                    "Modificada hace $hoursSince horas" `
                    "MEDIUM" `
                    $recycleBin `
                    60
            }
            
            # Buscar archivos eliminados recientemente
            $deletedFiles = Get-ChildItem -Path $recycleBin -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-24) }
            
            foreach ($file in $deletedFiles) {
                $signatures = Test-CheatSignature $file.Name
                if ($signatures.Count -gt 0) {
                    Add-Detection "Papelera - Archivo Sospechoso Eliminado" `
                        $file.Name `
                        "HIGH" `
                        $file.FullName `
                        80
                }
            }
        }
    }
    
    Write-Log "Papelera: Análisis completado" "Green"
}

# ============================================
# MÓDULO 17: DRIVERS Y KERNEL
# ============================================

function Invoke-DriverAnalysis {
    Update-Progress "Analizando drivers del sistema..."
    Write-Log "`n=== MÓDULO 17: DRIVERS ===" "Cyan"
    
    $driverData = @()
    $drivers = Get-WmiObject Win32_SystemDriver -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq "Running" }
    
    foreach ($driver in $drivers) {
        $signatures = Test-CheatSignature $driver.Name
        
        if ($signatures.Count -gt 0) {
            Add-Detection "Driver - Nombre Sospechoso" `
                "$($driver.Name) - $($driver.PathName)" `
                "CRITICAL" `
                $driver.PathName `
                95
        }
        
        # Drivers sin firma
        if ($driver.PathName -and (Test-Path $driver.PathName)) {
            $sig = Get-AuthenticodeSignature $driver.PathName -ErrorAction SilentlyContinue
            if ($sig -and $sig.Status -ne "Valid") {
                Add-Detection "Driver - Sin Firma Válida" `
                    "$($driver.Name) - Status: $($sig.Status)" `
                    "HIGH" `
                    $driver.PathName `
                    85
            }
        }
        
        $driverData += [PSCustomObject]@{
            Name = $driver.Name
            DisplayName = $driver.DisplayName
            Path = $driver.PathName
            State = $driver.State
            StartMode = $driver.StartMode
            Suspicious = ($signatures.Count -gt 0)
        }
    }
    
    $driverData | Export-Csv "$outputDir\16_Drivers.csv" -NoTypeInformation
    Write-Log "Drivers: $($drivers.Count) analizados" "Green"
}

# ============================================
# MÓDULO 18: MEMORIA Y RENDIMIENTO
# ============================================

function Invoke-PerformanceAnalysis {
    Update-Progress "Analizando rendimiento del sistema..."
    Write-Log "`n=== MÓDULO 18: RENDIMIENTO ===" "Cyan"
    
    $perfData = @()
    
    # Uso de CPU
    $cpuUsage = Get-WmiObject Win32_Processor -ErrorAction SilentlyContinue |
        Measure-Object -Property LoadPercentage -Average |
        Select-Object -ExpandProperty Average
    
    # Memoria
    $os = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue
    $totalMemory = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    $freeMemory = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    $usedMemory = $totalMemory - $freeMemory
    $memoryPercent = [math]::Round(($usedMemory / $totalMemory) * 100, 2)
    
    # Procesos con alto consumo
    $topProcesses = Get-Process -ErrorAction SilentlyContinue |
        Sort-Object WorkingSet -Descending |
        Select-Object -First 10
    
    foreach ($proc in $topProcesses) {
        $signatures = Test-CheatSignature $proc.Name
        $memMB = [math]::Round($proc.WorkingSet / 1MB, 2)
        
        if ($signatures.Count -gt 0 -and $memMB -gt 100) {
            Add-Detection "Rendimiento - Proceso Sospechoso con Alto Consumo" `
                "$($proc.Name) usando $memMB MB" `
                "MEDIUM" `
                $proc.Path `
                70
        }
        
        $perfData += [PSCustomObject]@{
            Process = $proc.Name
            MemoryMB = $memMB
            CPU = $proc.CPU
            Threads = $proc.Threads.Count
            Suspicious = ($signatures.Count -gt 0)
        }
    }
    
    $perfData | Export-Csv "$outputDir\17_Performance.csv" -NoTypeInformation
    Write-Log "Rendimiento: CPU $cpuUsage%, RAM $memoryPercent% ($usedMemory/$totalMemory GB)" "Green"
}

# ============================================
# MÓDULO 19: EVENTOS DEL SISTEMA
# ============================================

function Invoke-EventLogAnalysis {
    Update-Progress "Analizando eventos del sistema..."
    Write-Log "`n=== MÓDULO 19: EVENTOS ===" "Cyan"
    
    $eventData = @()
    
    try {
        # Eventos de seguridad críticos
        $securityEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = @(4688, 4689, 4697, 5140)
        } -MaxEvents 100 -ErrorAction SilentlyContinue
        
        foreach ($event in $securityEvents) {
            $message = $event.Message
            $signatures = Test-CheatSignature $message
            
            if ($signatures.Count -gt 0) {
                Add-Detection "Evento - Actividad Sospechosa" `
                    "Event ID $($event.Id): $($signatures.Signature -join ', ')" `
                    "MEDIUM" `
                    "Event Log" `
                    65
            }
            
            $eventData += [PSCustomObject]@{
                TimeCreated = $event.TimeCreated
                ID = $event.Id
                Level = $event.LevelDisplayName
                Message = $message.Substring(0, [Math]::Min(200, $message.Length))
                Suspicious = ($signatures.Count -gt 0)
            }
        }
        
        # Eventos de aplicación con errores
        $appErrors = Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            Level = 2
        } -MaxEvents 50 -ErrorAction SilentlyContinue
        
        foreach ($event in $appErrors) {
            if ($event.Message -match "Minecraft") {
                $eventData += [PSCustomObject]@{
                    TimeCreated = $event.TimeCreated
                    ID = $event.Id
                    Level = "Error"
                    Message = $event.Message.Substring(0, [Math]::Min(200, $event.Message.Length))
                    Suspicious = $true
                }
            }
        }
        
    } catch {
        Write-Log "Eventos: Error al acceder - $($_.Exception.Message)" "Yellow"
    }
    
    $eventData | Export-Csv "$outputDir\18_Events.csv" -NoTypeInformation
    Write-Log "Eventos: $($eventData.Count) analizados" "Green"
}

# ============================================
# MÓDULO 21: DETECCIÓN AVANZADA DE ARCHIVOS
# ============================================

function Invoke-AdvancedFileDetection {
    Update-Progress "Escaneando archivos en todo el sistema..."
    Write-Log "`n=== MÓDULO 21: DETECCIÓN AVANZADA DE ARCHIVOS ===" "Cyan"
    
    $fileFindings = @()
    $totalScanned = 0
    
    # Carpetas críticas para escanear
    $criticalPaths = @(
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:APPDATA",
        "$env:LOCALAPPDATA",
        "$env:TEMP",
        "C:\Users\Public",
        "C:\ProgramData"
    )
    
    Write-Log "Iniciando escaneo profundo de archivos..." "Yellow"
    
    # ===== FASE 1: BUSCAR ARCHIVOS CONOCIDOS =====
    Write-Log "Fase 1: Buscando archivos conocidos de cheats..." "Gray"
    
    foreach ($category in $knownCheatFiles.Keys) {
        foreach ($cheatFile in $knownCheatFiles[$category]) {
            $fileName = $cheatFile.Name
            
            # Buscar en carpetas críticas
            foreach ($path in $criticalPaths) {
                if (Test-Path $path) {
                    $found = Get-ChildItem -Path $path -Filter $fileName -Recurse -ErrorAction SilentlyContinue -Force |
                        Select-Object -First 5
                    
                    foreach ($file in $found) {
                        $totalScanned++
                        $hash = Get-FileHash-Safe $file.FullName
                        
                        Add-Detection "Archivo - Cheat Conocido Detectado" `
                            "$fileName encontrado en $($file.DirectoryName)" `
                            "CRITICAL" `
                            $file.FullName `
                            $cheatFile.ThreatLevel
                        
                        $fileFindings += [PSCustomObject]@{
                            Category = $category
                            FileName = $file.Name
                            Path = $file.FullName
                            Size = $file.Length
                            Created = $file.CreationTime
                            Modified = $file.LastWriteTime
                            Accessed = $file.LastAccessTime
                            Hash = $hash
                            ThreatLevel = $cheatFile.ThreatLevel
                            Reason = "Archivo conocido de cheat"
                            Hidden = $file.Attributes -match "Hidden"
                        }
                    }
                }
            }
            
            # Buscar en disco C:\ (solo raíz y Program Files)
            $systemPaths = @("C:\", "C:\Program Files", "C:\Program Files (x86)")
            foreach ($sysPath in $systemPaths) {
                $found = Get-ChildItem -Path $sysPath -Filter $fileName -ErrorAction SilentlyContinue -Force |
                    Where-Object { -not $_.PSIsContainer } |
                    Select-Object -First 2
                
                foreach ($file in $found) {
                    $totalScanned++
                    Add-Detection "Archivo - Cheat en Ubicación del Sistema" `
                        "$fileName en $($file.DirectoryName)" `
                        "CRITICAL" `
                        $file.FullName `
                        ($cheatFile.ThreatLevel + 5)
                }
            }
        }
    }
    
    # ===== FASE 2: ARCHIVOS SOSPECHOSOS POR EXTENSIÓN =====
    Write-Log "Fase 2: Analizando archivos sospechosos por extensión..." "Gray"
    
    $suspiciousExtensions = @("*.dll", "*.exe", "*.jar", "*.bat", "*.vbs", "*.ps1", "*.scr")
    
    foreach ($path in $criticalPaths) {
        if (Test-Path $path) {
            foreach ($ext in $suspiciousExtensions) {
                $files = Get-ChildItem -Path $path -Filter $ext -Recurse -ErrorAction SilentlyContinue -Force |
                    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) } |
                    Select-Object -First 100
                
                foreach ($file in $files) {
                    $totalScanned++
                    $signatures = Test-CheatSignature $file.Name
                    
                    if ($signatures.Count -gt 0) {
                        $hash = Get-FileHash-Safe $file.FullName
                        
                        Add-Detection "Archivo - Nombre Sospechoso" `
                            "$($file.Name) en $($file.DirectoryName)" `
                            "HIGH" `
                            $file.FullName `
                            80
                        
                        $fileFindings += [PSCustomObject]@{
                            Category = "Suspicious Name"
                            FileName = $file.Name
                            Path = $file.FullName
                            Size = $file.Length
                            Created = $file.CreationTime
                            Modified = $file.LastWriteTime
                            Hash = $hash
                            ThreatLevel = 80
                            Reason = "Nombre contiene palabras clave sospechosas"
                            Signatures = ($signatures.Signature -join ", ")
                        }
                    }
                }
            }
        }
    }
    
    # ===== FASE 3: ARCHIVOS OCULTOS =====
    Write-Log "Fase 3: Detectando archivos ocultos..." "Gray"
    
    foreach ($path in $criticalPaths) {
        if (Test-Path $path) {
            $hiddenFiles = Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object { 
                    $_.Attributes -match "Hidden" -and 
                    -not $_.PSIsContainer -and
                    $_.Extension -in @(".exe", ".dll", ".jar", ".bat", ".vbs")
                } | Select-Object -First 50
            
            foreach ($file in $hiddenFiles) {
                $totalScanned++
                $signatures = Test-CheatSignature $file.Name
                
                if ($signatures.Count -gt 0 -or $file.Length -gt 1MB) {
                    Add-Detection "Archivo - Archivo Oculto Sospechoso" `
                        "$($file.Name) (oculto)" `
                        "HIGH" `
                        $file.FullName `
                        75
                    
                    $fileFindings += [PSCustomObject]@{
                        Category = "Hidden File"
                        FileName = $file.Name
                        Path = $file.FullName
                        Size = $file.Length
                        Modified = $file.LastWriteTime
                        ThreatLevel = 75
                        Reason = "Archivo ejecutable oculto"
                        Hidden = $true
                    }
                }
            }
        }
    }
    
    # ===== FASE 4: ARCHIVOS SIN EXTENSIÓN O DOBLE EXTENSIÓN =====
    Write-Log "Fase 4: Buscando archivos sin extensión o con doble extensión..." "Gray"
    
    foreach ($path in $criticalPaths) {
        if (Test-Path $path) {
            # Archivos sin extensión
            $noExtFiles = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue -Force |
                Where-Object { 
                    -not $_.Extension -and 
                    $_.Length -gt 100KB -and
                    $_.LastWriteTime -gt (Get-Date).AddDays(-30)
                } | Select-Object -First 20
            
            foreach ($file in $noExtFiles) {
                $totalScanned++
                Add-Detection "Archivo - Sin Extensión" `
                    "$($file.Name) sin extensión" `
                    "MEDIUM" `
                    $file.FullName `
                    60
                
                $fileFindings += [PSCustomObject]@{
                    Category = "No Extension"
                    FileName = $file.Name
                    Path = $file.FullName
                    Size = $file.Length
                    ThreatLevel = 60
                    Reason = "Archivo sin extensión"
                }
            }
            
            # Doble extensión (ej: archivo.pdf.exe)
            $doubleExtFiles = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue -Force |
                Where-Object { 
                    $_.Name -match "\.[a-z]{3,4}\.(exe|dll|bat|vbs|scr|jar)$" -and
                    $_.LastWriteTime -gt (Get-Date).AddDays(-30)
                } | Select-Object -First 20
            
            foreach ($file in $doubleExtFiles) {
                $totalScanned++
                Add-Detection "Archivo - Doble Extensión Sospechosa" `
                    "$($file.Name) con doble extensión" `
                    "HIGH" `
                    $file.FullName `
                    85
                
                $fileFindings += [PSCustomObject]@{
                    Category = "Double Extension"
                    FileName = $file.Name
                    Path = $file.FullName
                    Size = $file.Length
                    ThreatLevel = 85
                    Reason = "Doble extensión (posible malware)"
                }
            }
        }
    }
    
    # ===== FASE 5: ARCHIVOS CON TIMESTAMPS MANIPULADOS =====
    Write-Log "Fase 5: Detectando manipulación de timestamps..." "Gray"
    
    foreach ($path in @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop")) {
        if (Test-Path $path) {
            $manipulatedFiles = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue -Force |
                Where-Object { 
                    $_.CreationTime -gt $_.LastWriteTime -and
                    $_.Extension -in @(".exe", ".dll", ".jar") -and
                    $_.LastWriteTime -gt (Get-Date).AddDays(-14)
                } | Select-Object -First 30
            
            foreach ($file in $manipulatedFiles) {
                $totalScanned++
                $timeDiff = ($file.CreationTime - $file.LastWriteTime).TotalHours
                
                if ($timeDiff -gt 1) {
                    Add-Detection "Archivo - Timestamp Manipulado" `
                        "$($file.Name) - Creado después de modificado ($([Math]::Round($timeDiff, 1))h diferencia)" `
                        "HIGH" `
                        $file.FullName `
                        80
                    
                    $fileFindings += [PSCustomObject]@{
                        Category = "Manipulated Timestamp"
                        FileName = $file.Name
                        Path = $file.FullName
                        Created = $file.CreationTime
                        Modified = $file.LastWriteTime
                        TimeDifference = "$([Math]::Round($timeDiff, 1)) horas"
                        ThreatLevel = 80
                        Reason = "Timestamp manipulado con SetFileDate o similar"
                    }
                }
            }
        }
    }
    
    # ===== FASE 6: ARCHIVOS GRANDES EN TEMP =====
    Write-Log "Fase 6: Buscando archivos grandes en carpetas temporales..." "Gray"
    
    $tempPaths = @($env:TEMP, "$env:LOCALAPPDATA\Temp", "C:\Windows\Temp")
    foreach ($tempPath in $tempPaths) {
        if (Test-Path $tempPath) {
            $largeFiles = Get-ChildItem -Path $tempPath -Recurse -File -ErrorAction SilentlyContinue -Force |
                Where-Object { 
                    $_.Length -gt 10MB -and
                    $_.Extension -in @(".exe", ".dll", ".zip", ".rar", ".7z") -and
                    $_.LastWriteTime -gt (Get-Date).AddDays(-7)
                } | Select-Object -First 20
            
            foreach ($file in $largeFiles) {
                $totalScanned++
                $sizeMB = [Math]::Round($file.Length / 1MB, 2)
                
                Add-Detection "Archivo - Archivo Grande en TEMP" `
                    "$($file.Name) ($sizeMB MB)" `
                    "MEDIUM" `
                    $file.FullName `
                    65
                
                $fileFindings += [PSCustomObject]@{
                    Category = "Large Temp File"
                    FileName = $file.Name
                    Path = $file.FullName
                    Size = $file.Length
                    SizeMB = $sizeMB
                    ThreatLevel = 65
                    Reason = "Archivo grande en carpeta temporal"
                }
            }
        }
    }
    
    # ===== FASE 7: ARCHIVOS .JAR SOSPECHOSOS (AutoClickers) =====
    Write-Log "Fase 7: Analizando archivos JAR..." "Gray"
    
    foreach ($path in $criticalPaths) {
        if (Test-Path $path) {
            $jarFiles = Get-ChildItem -Path $path -Filter "*.jar" -Recurse -ErrorAction SilentlyContinue -Force |
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-60) } |
                Select-Object -First 30
            
            foreach ($jar in $jarFiles) {
                $totalScanned++
                $signatures = Test-CheatSignature $jar.Name
                
                # Nombres sospechosos de AutoClickers
                if ($jar.Name -match "(auto|click|macro|ghost|jna|jnative)" -or $signatures.Count -gt 0) {
                    Add-Detection "Archivo - JAR Sospechoso (Posible AutoClicker)" `
                        $jar.Name `
                        "HIGH" `
                        $jar.FullName `
                        80
                    
                    $fileFindings += [PSCustomObject]@{
                        Category = "Suspicious JAR"
                        FileName = $jar.Name
                        Path = $jar.FullName
                        Size = $jar.Length
                        ThreatLevel = 80
                        Reason = "JAR con nombre sospechoso de AutoClicker"
                    }
                }
            }
        }
    }
    
    # ===== FASE 8: ARCHIVOS EN CARPETAS DE RECICLAJE =====
    Write-Log "Fase 8: Escaneando papelera de reciclaje..." "Gray"
    
    $recycleBin = "C:\`$Recycle.Bin"
    if (Test-Path $recycleBin) {
        $deletedFiles = Get-ChildItem -Path $recycleBin -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { 
                -not $_.PSIsContainer -and
                $_.Extension -in @(".exe", ".dll", ".jar") -and
                $_.LastWriteTime -gt (Get-Date).AddDays(-7)
            } | Select-Object -First 30
        
        foreach ($file in $deletedFiles) {
            $totalScanned++
            $signatures = Test-CheatSignature $file.Name
            
            if ($signatures.Count -gt 0) {
                Add-Detection "Archivo - Cheat en Papelera" `
                    "$($file.Name) eliminado recientemente" `
                    "HIGH" `
                    $file.FullName `
                    75
                
                $fileFindings += [PSCustomObject]@{
                    Category = "Deleted File"
                    FileName = $file.Name
                    Path = $file.FullName
                    DeletedDate = $file.LastWriteTime
                    ThreatLevel = 75
                    Reason = "Archivo sospechoso en papelera"
                }
            }
        }
    }
    
    # Exportar resultados
    $fileFindings | Export-Csv "$outputDir\20_Advanced_File_Detection.csv" -NoTypeInformation
    Write-Log "Detección de Archivos: $totalScanned archivos escaneados, $($fileFindings.Count) sospechosos" "Green"
    
    # Estadísticas por categoría
    if ($fileFindings.Count -gt 0) {
        Write-Log "`nEstadísticas por categoría:" "Cyan"
        $fileFindings | Group-Object Category | Sort-Object Count -Descending | ForEach-Object {
            Write-Log "  - $($_.Name): $($_.Count)" "Gray"
        }
    }
}

# ============================================
# MÓDULO 22: ANÁLISIS FORENSE DE EXTENSIONES FALSAS
# ============================================

function Invoke-FileForensicsAnalysis {
    Update-Progress "Analizando extensiones falsas y archivos manipulados..."
    Write-Log "`n=== MÓDULO 22: ANÁLISIS FORENSE DE ARCHIVOS ===" "Cyan"
    
    $forensicFindings = @()
    $totalAnalyzed = 0
    
    Write-Log "Iniciando análisis forense profundo..." "Yellow"
    
    # Carpetas a analizar
    $scanPaths = @(
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Pictures",  # Común para ocultar .exe como .png
        "$env:USERPROFILE\Videos",
        "$env:APPDATA",
        "$env:LOCALAPPDATA"
    )
    
    # ===== FASE 1: DETECCIÓN DE EXTENSIONES FALSAS =====
    Write-Log "Fase 1: Detectando extensiones falsas (magic bytes)..." "Gray"
    
    # Extensiones a verificar (sospechosas de ser falsas)
    $extensionsToCheck = @(".png", ".jpg", ".gif", ".txt", ".pdf", ".doc", ".mp3", ".mp4", ".avi")
    
    foreach ($path in $scanPaths) {
        if (Test-Path $path) {
            foreach ($ext in $extensionsToCheck) {
                $files = Get-ChildItem -Path $path -Filter "*$ext" -Recurse -File -ErrorAction SilentlyContinue -Force |
                    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-60) -and $_.Length -gt 10KB } |
                    Select-Object -First 50
                
                foreach ($file in $files) {
                    $totalAnalyzed++
                    
                    # Analizar magic bytes
                    $mismatch = Test-FileExtensionMismatch -Path $file.FullName -Extension $file.Extension
                    
                    if ($mismatch) {
                        $severity = if ($mismatch.ThreatLevel -ge 90) { "CRITICAL" } 
                                   elseif ($mismatch.ThreatLevel -ge 75) { "HIGH" }
                                   else { "MEDIUM" }
                        
                        Add-Detection "Forense - Extensión Falsa Detectada" `
                            "$($file.Name) - Real: $($mismatch.RealType), Falso: $($mismatch.FakeExtension)" `
                            $severity `
                            $file.FullName `
                            $mismatch.ThreatLevel
                        
                        $forensicFindings += [PSCustomObject]@{
                            Category = "Fake Extension"
                            FileName = $file.Name
                            Path = $file.FullName
                            FakeExtension = $mismatch.FakeExtension
                            RealType = $mismatch.RealType
                            MagicBytes = $mismatch.ActualMagic
                            Size = $file.Length
                            Modified = $file.LastWriteTime
                            ThreatLevel = $mismatch.ThreatLevel
                            Hash = Get-FileHash-Safe $file.FullName
                        }
                    }
                }
            }
        }
    }
    
    # ===== FASE 2: ARCHIVOS VACÍOS O CASI VACÍOS =====
    Write-Log "Fase 2: Detectando archivos vacíos o con contenido eliminado..." "Gray"
    
    foreach ($path in $scanPaths) {
        if (Test-Path $path) {
            $emptyFiles = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue -Force |
                Where-Object { 
                    $_.Length -eq 0 -and
                    $_.Extension -in @(".exe", ".dll", ".jar", ".zip", ".rar") -and
                    $_.LastWriteTime -gt (Get-Date).AddDays(-30)
                } | Select-Object -First 30
            
            foreach ($file in $emptyFiles) {
                $totalAnalyzed++
                
                Add-Detection "Forense - Archivo Vaciado" `
                    "$($file.Name) (0 bytes) - Contenido eliminado" `
                    "HIGH" `
                    $file.FullName `
                    85
                
                $forensicFindings += [PSCustomObject]@{
                    Category = "Empty File"
                    FileName = $file.Name
                    Path = $file.FullName
                    Size = 0
                    Modified = $file.LastWriteTime
                    ThreatLevel = 85
                    Reason = "Archivo ejecutable/comprimido vacío (contenido eliminado)"
                }
            }
            
            # Archivos sospechosamente pequeños (menos de 1KB)
            $tinyFiles = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue -Force |
                Where-Object { 
                    $_.Length -gt 0 -and $_.Length -lt 1024 -and
                    $_.Extension -in @(".exe", ".dll") -and
                    $_.LastWriteTime -gt (Get-Date).AddDays(-30)
                } | Select-Object -First 20
            
            foreach ($file in $tinyFiles) {
                $totalAnalyzed++
                
                Add-Detection "Forense - Archivo Sospechosamente Pequeño" `
                    "$($file.Name) ($($file.Length) bytes) - Posible stub o vaciado parcial" `
                    "MEDIUM" `
                    $file.FullName `
                    70
                
                $forensicFindings += [PSCustomObject]@{
                    Category = "Tiny Executable"
                    FileName = $file.Name
                    Path = $file.FullName
                    Size = $file.Length
                    ThreatLevel = 70
                    Reason = "Ejecutable sospechosamente pequeño"
                }
            }
        }
    }
    
    # ===== FASE 3: ARCHIVOS RENOMBRADOS CON PATRONES SOSPECHOSOS =====
    Write-Log "Fase 3: Detectando patrones de renombrado sospechoso..." "Gray"
    
    foreach ($path in $scanPaths) {
        if (Test-Path $path) {
            # Buscar archivos con nombres genéricos sospechosos
            $suspiciousNames = @("file", "document", "image", "photo", "video", "temp", "new", "untitled", "backup")
            
            foreach ($susName in $suspiciousNames) {
                $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue -Force |
                    Where-Object { 
                        $_.Name -match "^$susName\d*\." -and
                        $_.Extension -in @(".exe", ".dll", ".jar", ".bat") -and
                        $_.LastWriteTime -gt (Get-Date).AddDays(-30)
                    } | Select-Object -First 20
                
                foreach ($file in $files) {
                    $totalAnalyzed++
                    
                    Add-Detection "Forense - Nombre Genérico Sospechoso" `
                        "$($file.Name) - Posible renombrado para ocultar" `
                        "MEDIUM" `
                        $file.FullName `
                        65
                    
                    $forensicFindings += [PSCustomObject]@{
                        Category = "Suspicious Rename"
                        FileName = $file.Name
                        Path = $file.FullName
                        ThreatLevel = 65
                        Reason = "Nombre genérico en archivo ejecutable"
                    }
                }
            }
        }
    }
    
    # ===== FASE 4: ARCHIVOS CON METADATA CORRUPTA =====
    Write-Log "Fase 4: Verificando metadata de archivos..." "Gray"
    
    foreach ($path in @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop")) {
        if (Test-Path $path) {
            $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue -Force |
                Where-Object { 
                    $_.Extension -in @(".exe", ".dll") -and
                    $_.LastWriteTime -gt (Get-Date).AddDays(-30)
                } | Select-Object -First 50
            
            foreach ($file in $files) {
                $totalAnalyzed++
                
                try {
                    $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($file.FullName)
                    
                    # Detectar ejecutables sin información de versión
                    if (-not $versionInfo.CompanyName -and -not $versionInfo.FileDescription -and $file.Length -gt 100KB) {
                        Add-Detection "Forense - Ejecutable Sin Metadata" `
                            "$($file.Name) - Sin información de compañía/descripción" `
                            "MEDIUM" `
                            $file.FullName `
                            65
                        
                        $forensicFindings += [PSCustomObject]@{
                            Category = "No Metadata"
                            FileName = $file.Name
                            Path = $file.FullName
                            ThreatLevel = 65
                            Reason = "Ejecutable sin metadata de versión"
                        }
                    }
                } catch {}
            }
        }
    }
    
    # ===== FASE 5: ARCHIVOS CON ICONOS FALSOS =====
    Write-Log "Fase 5: Detectando ejecutables con iconos falsos..." "Gray"
    
    # Buscar .exe con iconos de documentos/imágenes (técnica común de malware)
    foreach ($path in @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents")) {
        if (Test-Path $path) {
            $exeFiles = Get-ChildItem -Path $path -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue -Force |
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) } |
                Select-Object -First 30
            
            foreach ($exe in $exeFiles) {
                $totalAnalyzed++
                
                # Si el nombre sugiere que es un documento pero es .exe
                if ($exe.Name -match "\.(pdf|doc|txt|jpg|png)\.exe$") {
                    Add-Detection "Forense - EXE Disfrazado de Documento" `
                        "$($exe.Name) - Extensión engañosa" `
                        "CRITICAL" `
                        $exe.FullName `
                        95
                    
                    $forensicFindings += [PSCustomObject]@{
                        Category = "Fake Document"
                        FileName = $exe.Name
                        Path = $exe.FullName
                        ThreatLevel = 95
                        Reason = "Ejecutable disfrazado con extensión de documento"
                    }
                }
            }
        }
    }
    
    # ===== FASE 6: ARCHIVOS CON ENTROPÍA SOSPECHOSA =====
    Write-Log "Fase 6: Analizando entropía de archivos..." "Gray"
    
    foreach ($path in @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop")) {
        if (Test-Path $path) {
            $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue -Force |
                Where-Object { 
                    $_.Extension -in @(".exe", ".dll", ".jar") -and
                    $_.Length -gt 50KB -and $_.Length -lt 500KB -and
                    $_.LastWriteTime -gt (Get-Date).AddDays(-30)
                } | Select-Object -First 30
            
            foreach ($file in $files) {
                $totalAnalyzed++
                
                try {
                    # Leer primeros 1KB para análisis rápido
                    $bytes = [System.IO.File]::ReadAllBytes($file.FullName) | Select-Object -First 1024
                    
                    # Calcular entropía simple
                    $uniqueBytes = ($bytes | Group-Object | Measure-Object).Count
                    $entropy = $uniqueBytes / 256.0
                    
                    # Entropía muy baja o muy alta es sospechosa
                    if ($entropy -lt 0.3 -or $entropy -gt 0.95) {
                        $reason = if ($entropy -lt 0.3) { "muy baja (posible padding)" } else { "muy alta (posible compresión/cifrado)" }
                        
                        Add-Detection "Forense - Entropía Anómala" `
                            "$($file.Name) - Entropía $reason" `
                            "MEDIUM" `
                            $file.FullName `
                            60
                    }
                } catch {}
            }
        }
    }
    
    # Exportar resultados
    $forensicFindings | Export-Csv "$outputDir\21_File_Forensics.csv" -NoTypeInformation
    Write-Log "Análisis Forense: $totalAnalyzed archivos analizados, $($forensicFindings.Count) anomalías detectadas" "Green"
    
    # Estadísticas
    if ($forensicFindings.Count -gt 0) {
        Write-Log "`nAnomalías por categoría:" "Cyan"
        $forensicFindings | Group-Object Category | Sort-Object Count -Descending | ForEach-Object {
            Write-Log "  - $($_.Name): $($_.Count)" "Gray"
        }
    }
}

# ============================================
# MÓDULO 24: ESCANEO DE UBICACIONES OCULTAS
# ============================================

function Invoke-HiddenLocationScan {
    Update-Progress "Escaneando ubicaciones ocultas de expertos..."
    Write-Log "`n=== MÓDULO 24: UBICACIONES OCULTAS ===" "Cyan"
    
    $hiddenFindings = @()
    $totalScanned = 0
    
    Write-Log "Escaneando lugares donde los hackers esconden archivos..." "Yellow"
    
    # === CARPETAS DEL SISTEMA (RARO ENCONTRAR ARCHIVOS AQUÍ) ===
    Write-Log "Fase 1: Carpetas del sistema (Fonts, Help, Cursors)..." "Gray"
    
    foreach ($folder in $hiddenLocations.SystemFolders) {
        if (Test-Path $folder) {
            $suspiciousFiles = Get-ChildItem -Path $folder -File -Force -ErrorAction SilentlyContinue |
                Where-Object { 
                    $_.Extension -in @(".exe", ".dll", ".jar", ".bat", ".ps1", ".vbs") -or
                    ($_.Extension -in $disguiseExtensions -and $_.Length -gt 500KB)
                } | Select-Object -First 20
            
            foreach ($file in $suspiciousFiles) {
                $totalScanned++
                $magic = Get-FileMagicBytes -Path $file.FullName
                
                Add-Detection "Ubicación Oculta - Sistema" `
                    "$($file.Name) en ubicación inusual: $folder" `
                    "CRITICAL" `
                    $file.FullName `
                    95
                
                $hiddenFindings += [PSCustomObject]@{
                    Category = "System Folder"
                    Location = $folder
                    FileName = $file.Name
                    Path = $file.FullName
                    Size = $file.Length
                    Extension = $file.Extension
                    MagicBytes = $magic
                    Modified = $file.LastWriteTime
                    ThreatLevel = 95
                }
            }
        }
    }
    
    # === APPDATA OCULTO ===
    Write-Log "Fase 2: AppData oculto (Startup, SendTo, Cookies)..." "Gray"
    
    foreach ($folder in $hiddenLocations.HiddenAppData) {
        if (Test-Path $folder) {
            $files = Get-ChildItem -Path $folder -File -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object { 
                    $_.Extension -in @(".exe", ".dll", ".jar", ".bat", ".scr") -and
                    $_.LastWriteTime -gt (Get-Date).AddDays(-60)
                } | Select-Object -First 20
            
            foreach ($file in $files) {
                $totalScanned++
                $signatures = Test-CheatSignature $file.Name
                
                if ($signatures.Count -gt 0 -or $file.Length -gt 1MB) {
                    Add-Detection "Ubicación Oculta - AppData" `
                        "$($file.Name) en AppData oculto" `
                        "HIGH" `
                        $file.FullName `
                        85
                    
                    $hiddenFindings += [PSCustomObject]@{
                        Category = "Hidden AppData"
                        Location = $folder
                        FileName = $file.Name
                        Path = $file.FullName
                        ThreatLevel = 85
                    }
                }
            }
        }
    }
    
    # === CARPETAS DE JUEGOS ===
    Write-Log "Fase 3: Carpetas de Minecraft (LocalCache, Settings)..." "Gray"
    
    foreach ($folder in $hiddenLocations.GameFolders) {
        if (Test-Path $folder) {
            $files = Get-ChildItem -Path $folder -File -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object { 
                    $_.Extension -in @(".exe", ".dll", ".jar") -and
                    $_.LastWriteTime -gt (Get-Date).AddDays(-30)
                } | Select-Object -First 30
            
            foreach ($file in $files) {
                $totalScanned++
                Add-Detection "Ubicación Oculta - Carpetas de Juego" `
                    "$($file.Name) en carpeta de Minecraft" `
                    "HIGH" `
                    $file.FullName `
                    80
                
                $hiddenFindings += [PSCustomObject]@{
                    Category = "Game Folders"
                    Location = $folder
                    FileName = $file.Name
                    Path = $file.FullName
                    ThreatLevel = 80
                }
            }
        }
    }
    
    # === SINCRONIZACIÓN EN LA NUBE ===
    Write-Log "Fase 4: Carpetas de sincronización (OneDrive, Google Drive)..." "Gray"
    
    foreach ($folder in $hiddenLocations.CloudSync) {
        if (Test-Path $folder) {
            $files = Get-ChildItem -Path $folder -Include "*.exe","*.dll","*.jar" -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-90) } |
                Select-Object -First 30
            
            foreach ($file in $files) {
                $totalScanned++
                $signatures = Test-CheatSignature $file.Name
                
                if ($signatures.Count -gt 0) {
                    Add-Detection "Ubicación Oculta - Nube" `
                        "$($file.Name) sincronizado en la nube" `
                        "HIGH" `
                        $file.FullName `
                        85
                    
                    $hiddenFindings += [PSCustomObject]@{
                        Category = "Cloud Sync"
                        Location = $folder
                        FileName = $file.Name
                        Path = $file.FullName
                        ThreatLevel = 85
                    }
                }
            }
        }
    }
    
    # === EXTENSIONES DE NAVEGADORES ===
    Write-Log "Fase 5: Extensiones de navegadores (Chrome, Firefox)..." "Gray"
    
    foreach ($folder in $hiddenLocations.Browsers) {
        if (Test-Path $folder) {
            $files = Get-ChildItem -Path $folder -Include "*.exe","*.dll","*.js" -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) } |
                Select-Object -First 20
            
            foreach ($file in $files) {
                $totalScanned++
                if ($file.Extension -eq ".exe" -or ($file.Extension -eq ".dll" -and $file.Length -gt 500KB)) {
                    Add-Detection "Ubicación Oculta - Navegador" `
                        "$($file.Name) en carpeta de extensiones" `
                        "MEDIUM" `
                        $file.FullName `
                        70
                }
            }
        }
    }
    
    $hiddenFindings | Export-Csv "$outputDir\23_Hidden_Locations.csv" -NoTypeInformation
    Write-Log "Ubicaciones Ocultas: $totalScanned archivos en lugares sospechosos" "Green"
}

# ============================================
# MÓDULO 25: DETECCIÓN DE ARCHIVOS DISFRAZADOS
# ============================================

function Invoke-DisguisedFileDetection {
    Update-Progress "Detectando archivos disfrazados con nombres genéricos..."
    Write-Log "`n=== MÓDULO 25: ARCHIVOS DISFRAZADOS ===" "Cyan"
    
    $disguisedFindings = @()
    $totalScanned = 0
    
    Write-Log "Buscando ejecutables con nombres genéricos..." "Yellow"
    
    $searchPaths = @(
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:APPDATA",
        "$env:LOCALAPPDATA",
        "$env:TEMP"
    )
    
    # === NOMBRES GENÉRICOS SOSPECHOSOS ===
    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            foreach ($genericName in $genericNames) {
                $files = Get-ChildItem -Path $path -Filter "$genericName*" -Recurse -File -Force -ErrorAction SilentlyContinue |
                    Where-Object { 
                        $_.Extension -in @(".exe", ".dll", ".scr") -and
                        $_.LastWriteTime -gt (Get-Date).AddDays(-60)
                    } | Select-Object -First 10
                
                foreach ($file in $files) {
                    $totalScanned++
                    
                    # Verificar si es archivo legítimo de Windows
                    $isLegit = $file.Directory.FullName -like "C:\Windows\System32*" -or
                               $file.Directory.FullName -like "C:\Windows\SysWOW64*"
                    
                    if (-not $isLegit) {
                        Add-Detection "Archivo Disfrazado - Nombre Genérico" `
                            "$($file.Name) usa nombre genérico de sistema" `
                            "HIGH" `
                            $file.FullName `
                            80
                        
                        $disguisedFindings += [PSCustomObject]@{
                            Category = "Generic Name"
                            FileName = $file.Name
                            Path = $file.FullName
                            GenericPattern = $genericName
                            Size = $file.Length
                            Modified = $file.LastWriteTime
                            ThreatLevel = 80
                        }
                    }
                }
            }
        }
    }
    
    # === EXTENSIONES DISFRAZADAS ===
    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            foreach ($fakeExt in $disguiseExtensions) {
                $files = Get-ChildItem -Path $path -Filter "*$fakeExt" -Recurse -File -Force -ErrorAction SilentlyContinue |
                    Where-Object { 
                        $_.Length -gt 500KB -and
                        $_.LastWriteTime -gt (Get-Date).AddDays(-60)
                    } | Select-Object -First 20
                
                foreach ($file in $files) {
                    $totalScanned++
                    $magic = Get-FileMagicBytes -Path $file.FullName
                    
                    # Si es ejecutable con extensión falsa
                    if ($magic -like "4D5A*") {
                        Add-Detection "Archivo Disfrazado - Extensión Falsa" `
                            "$($file.Name) es ejecutable con extensión $fakeExt" `
                            "CRITICAL" `
                            $file.FullName `
                            95
                        
                        $disguisedFindings += [PSCustomObject]@{
                            Category = "Fake Extension"
                            FileName = $file.Name
                            Path = $file.FullName
                            FakeExtension = $fakeExt
                            RealType = "Executable"
                            MagicBytes = $magic
                            ThreatLevel = 95
                        }
                    }
                }
            }
        }
    }
    
    $disguisedFindings | Export-Csv "$outputDir\24_Disguised_Files.csv" -NoTypeInformation
    Write-Log "Archivos Disfrazados: $($disguisedFindings.Count) detectados" "Green"
}

# ============================================
# MÓDULO 26: ANÁLISIS DE CERTIFICADOS DIGITALES
# ============================================

function Invoke-CertificateAnalysis {
    Update-Progress "Analizando certificados digitales..."
    Write-Log "`n=== MÓDULO 26: CERTIFICADOS DIGITALES ===" "Cyan"
    
    $certFindings = @()
    $totalScanned = 0
    
    Write-Log "Verificando firmas digitales de ejecutables..." "Yellow"
    
    $searchPaths = @(
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents"
    )
    
    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            $exeFiles = Get-ChildItem -Path $path -Include "*.exe","*.dll" -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-60) } |
                Select-Object -First 50
            
            foreach ($file in $exeFiles) {
                $totalScanned++
                
                try {
                    $sig = Get-AuthenticodeSignature $file.FullName -ErrorAction SilentlyContinue
                    
                    if ($sig) {
                        # Sin firma
                        if ($sig.Status -eq "NotSigned" -and $file.Length -gt 100KB) {
                            Add-Detection "Certificado - Sin Firma Digital" `
                                "$($file.Name) no está firmado digitalmente" `
                                "MEDIUM" `
                                $file.FullName `
                                65
                            
                            $certFindings += [PSCustomObject]@{
                                FileName = $file.Name
                                Path = $file.FullName
                                Status = "Not Signed"
                                ThreatLevel = 65
                            }
                        }
                        
                        # Firma inválida
                        elseif ($sig.Status -in @("Invalid", "HashMismatch", "NotTrusted")) {
                            Add-Detection "Certificado - Firma Inválida" `
                                "$($file.Name) - Estado: $($sig.Status)" `
                                "HIGH" `
                                $file.FullName `
                                85
                            
                            $certFindings += [PSCustomObject]@{
                                FileName = $file.Name
                                Path = $file.FullName
                                Status = $sig.Status
                                Signer = $sig.SignerCertificate.Subject
                                ThreatLevel = 85
                            }
                        }
                        
                        # Certificado expirado
                        elseif ($sig.Status -eq "Valid" -and $sig.SignerCertificate) {
                            if ($sig.SignerCertificate.NotAfter -lt (Get-Date)) {
                                Add-Detection "Certificado - Certificado Expirado" `
                                    "$($file.Name) - Expirado: $($sig.SignerCertificate.NotAfter)" `
                                    "MEDIUM" `
                                    $file.FullName `
                                    60
                            }
                        }
                    }
                } catch {}
            }
        }
    }
    
    $certFindings | Export-Csv "$outputDir\25_Certificates.csv" -NoTypeInformation
    Write-Log "Certificados: $totalScanned archivos verificados" "Green"
}

# ============================================
# MÓDULO 27: DETECCIÓN DE CONEXIONES C2
# ============================================

function Invoke-C2Detection {
    Update-Progress "Detectando conexiones a servidores C2..."
    Write-Log "`n=== MÓDULO 27: DETECCIÓN DE SERVIDORES C2 ===" "Cyan"
    
    $c2Findings = @()
    
    Write-Log "Analizando conexiones de red sospechosas..." "Yellow"
    
    # IPs/dominios sospechosos conocidos
    $suspiciousIPs = @(
        "185.193.126", "45.142.212", "193.239.85", "104.21.0", "172.67.0"
    )
    
    $suspiciousDomains = @(
        "pastebin.com", "hastebin.com", "discord.gg", "bit.ly", 
        "tinyurl.com", "raw.githubusercontent.com"
    )
    
    # Conexiones activas
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    
    foreach ($conn in $connections) {
        $remoteIP = $conn.RemoteAddress
        $remotePort = $conn.RemotePort
        
        try {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            
            if ($proc) {
                # Verificar IPs sospechosas
                $isSuspicious = $false
                foreach ($suspIP in $suspiciousIPs) {
                    if ($remoteIP -like "$suspIP*") {
                        $isSuspicious = $true
                        break
                    }
                }
                
                # Puertos sospechosos (no comunes)
                $suspiciousPorts = @(4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337)
                if ($remotePort -in $suspiciousPorts) {
                    $isSuspicious = $true
                }
                
                if ($isSuspicious) {
                    Add-Detection "C2 - Conexión Sospechosa" `
                        "$($proc.Name) conectado a $remoteIP`:$remotePort" `
                        "HIGH" `
                        $proc.Path `
                        80
                    
                    $c2Findings += [PSCustomObject]@{
                        Process = $proc.Name
                        PID = $proc.Id
                        RemoteIP = $remoteIP
                        RemotePort = $remotePort
                        ThreatLevel = 80
                    }
                }
            }
        } catch {}
    }
    
    # DNS Cache
    try {
        $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
        foreach ($entry in $dnsCache) {
            foreach ($domain in $suspiciousDomains) {
                if ($entry.Entry -like "*$domain*") {
                    Add-Detection "C2 - Dominio Sospechoso en DNS" `
                        "Acceso a: $($entry.Entry)" `
                        "MEDIUM" `
                        "DNS Cache" `
                        65
                }
            }
        }
    } catch {}
    
    $c2Findings | Export-Csv "$outputDir\26_C2_Connections.csv" -NoTypeInformation
    Write-Log "C2: $($c2Findings.Count) conexiones sospechosas" "Green"
}

# ============================================
# MÓDULO 28: ANÁLISIS DE STREAMS ALTERNATIVOS (ADS)
# ============================================

function Invoke-AlternateDataStreamScan {
    Update-Progress "Escaneando Alternate Data Streams..."
    Write-Log "`n=== MÓDULO 28: ALTERNATE DATA STREAMS (ADS) ===" "Cyan"
    
    $adsFindings = @()
    $totalScanned = 0
    
    Write-Log "Detectando archivos ocultos en ADS (técnica avanzada)..." "Yellow"
    
    $searchPaths = @(
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents"
    )
    
    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-60) } |
                Select-Object -First 100
            
            foreach ($file in $files) {
                $totalScanned++
                
                try {
                    # Buscar streams alternativos
                    $streams = Get-Item $file.FullName -Stream * -ErrorAction SilentlyContinue |
                        Where-Object { $_.Stream -ne ':$DATA' }
                    
                    if ($streams) {
                        foreach ($stream in $streams) {
                            if ($stream.Length -gt 1KB) {
                                Add-Detection "ADS - Stream Alternativo Detectado" `
                                    "$($file.Name) tiene stream oculto: $($stream.Stream) ($($stream.Length) bytes)" `
                                    "HIGH" `
                                    $file.FullName `
                                    85
                                
                                $adsFindings += [PSCustomObject]@{
                                    FileName = $file.Name
                                    Path = $file.FullName
                                    StreamName = $stream.Stream
                                    StreamSize = $stream.Length
                                    ThreatLevel = 85
                                }
                            }
                        }
                    }
                } catch {}
            }
        }
    }
    
    $adsFindings | Export-Csv "$outputDir\27_ADS_Streams.csv" -NoTypeInformation
    Write-Log "ADS: $($adsFindings.Count) streams alternativos detectados" "Green"
}

# ============================================
# MÓDULO 29: ANÁLISIS DE MEMORIA Y HOOKS
# ============================================

function Invoke-MemoryAnalysis {
    Update-Progress "Analizando memoria y hooks del sistema..."
    Write-Log "`n=== MÓDULO 29: ANÁLISIS DE MEMORIA ===" "Cyan"
    
    $memoryFindings = @()
    
    Write-Log "Detectando hooks y modificaciones en memoria..." "Yellow"
    
    # Procesos con alto uso de memoria (posibles inyecciones)
    $processes = Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.WorkingSet64 -gt 500MB } |
        Sort-Object WorkingSet64 -Descending |
        Select-Object -First 20
    
    foreach ($proc in $processes) {
        $signatures = Test-CheatSignature $proc.Name
        
        if ($signatures.Count -gt 0) {
            $memMB = [math]::Round($proc.WorkingSet64 / 1MB, 2)
            
            Add-Detection "Memoria - Proceso Sospechoso Alto Consumo" `
                "$($proc.Name) usando $memMB MB" `
                "MEDIUM" `
                $proc.Path `
                70
            
            $memoryFindings += [PSCustomObject]@{
                Process = $proc.Name
                PID = $proc.Id
                MemoryMB = $memMB
                Threads = $proc.Threads.Count
                ThreatLevel = 70
            }
        }
    }
    
    # Detectar handles sospechosos
    $mcProcesses = Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "Minecraft" }
    
    foreach ($mcProc in $mcProcesses) {
        try {
            $handles = $mcProc.Handles
            if ($handles -gt 10000) {
                Add-Detection "Memoria - Exceso de Handles" `
                    "Minecraft tiene $handles handles (posible hook/inyección)" `
                    "MEDIUM" `
                    $mcProc.Path `
                    65
            }
        } catch {}
    }
    
    $memoryFindings | Export-Csv "$outputDir\28_Memory_Analysis.csv" -NoTypeInformation
    Write-Log "Memoria: $($memoryFindings.Count) anomalías detectadas" "Green"
}

# ============================================
# MÓDULO 30: ANÁLISIS DE MODIFICACIONES DEL SISTEMA
# ============================================

function Invoke-SystemModificationAnalysis {
    Update-Progress "Detectando modificaciones del sistema..."
    Write-Log "`n=== MÓDULO 30: MODIFICACIONES DEL SISTEMA ===" "Cyan"
    
    $sysModFindings = @()
    
    Write-Log "Analizando modificaciones críticas del sistema..." "Yellow"
    
    # === HOSTS FILE ===
    $hostsFile = "C:\Windows\System32\drivers\etc\hosts"
    if (Test-Path $hostsFile) {
        $hostsContent = Get-Content $hostsFile -ErrorAction SilentlyContinue
        $suspiciousEntries = $hostsContent | Where-Object { 
            $_ -notmatch "^#" -and $_ -match "(minecraft|mojang|microsoft|xbox|live)" 
        }
        
        if ($suspiciousEntries) {
            Add-Detection "Sistema - Archivo HOSTS Modificado" `
                "$($suspiciousEntries.Count) entradas sospechosas en hosts" `
                "HIGH" `
                $hostsFile `
                85
            
            $sysModFindings += [PSCustomObject]@{
                Type = "Hosts File"
                Modifications = ($suspiciousEntries -join " | ")
                ThreatLevel = 85
            }
        }
    }
    
    # === FIREWALL RULES ===
    try {
        $fwRules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
            Where-Object { $_.Enabled -eq $true -and $_.Direction -eq "Outbound" }
        
        foreach ($rule in $fwRules) {
            $signatures = Test-CheatSignature $rule.Name
            if ($signatures.Count -gt 0) {
                Add-Detection "Sistema - Regla de Firewall Sospechosa" `
                    $rule.Name `
                    "MEDIUM" `
                    "Firewall" `
                    60
            }
        }
    } catch {}
    
    # === PROXY SETTINGS ===
    $proxyReg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    if (Test-Path $proxyReg) {
        $proxy = Get-ItemProperty -Path $proxyReg -ErrorAction SilentlyContinue
        if ($proxy.ProxyEnable -eq 1) {
            Add-Detection "Sistema - Proxy Habilitado" `
                "Proxy: $($proxy.ProxyServer)" `
                "MEDIUM" `
                $proxyReg `
                60
        }
    }
    
    # === WINDOWS DEFENDER ===
    try {
        $defender = Get-MpPreference -ErrorAction SilentlyContinue
        if ($defender.DisableRealtimeMonitoring -eq $true) {
            Add-Detection "Sistema - Windows Defender Deshabilitado" `
                "Real-time protection está deshabilitado" `
                "CRITICAL" `
                "Windows Defender" `
                95
        }
        
        if ($defender.ExclusionPath) {
            foreach ($exclusion in $defender.ExclusionPath) {
                if ($exclusion -match "(Downloads|Desktop|Documents|Temp)") {
                    Add-Detection "Sistema - Exclusión de Defender Sospechosa" `
                        "Ruta excluida: $exclusion" `
                        "HIGH" `
                        "Windows Defender" `
                        80
                }
            }
        }
    } catch {}
    
    $sysModFindings | Export-Csv "$outputDir\29_System_Modifications.csv" -NoTypeInformation
    Write-Log "Modificaciones del Sistema: $($sysModFindings.Count) detectadas" "Green"
}

# ============================================
# MÓDULO 23: ANÁLISIS PROFUNDO DE STRINGS Y OFUSCACIÓN
# ============================================

function Invoke-DeepStringAnalysis {
    Update-Progress "Analizando strings y detectando ofuscación..."
    Write-Log "`n=== MÓDULO 23: ANÁLISIS DE STRINGS Y OFUSCACIÓN ===" "Cyan"
    
    $stringFindings = @()
    $totalAnalyzed = 0
    
    Write-Log "Iniciando análisis profundo de strings en ejecutables..." "Yellow"
    
    # Palabras clave sospechosas para buscar dentro de archivos
    $suspiciousStrings = @{
        CheatFunctions = @(
            "killaura", "bhop", "fly", "xray", "reach", "velocity", "antiknockback",
            "scaffold", "freecam", "esp", "aimbot", "triggerbot", "autoclicker",
            "inject", "hook", "detour", "patch", "bypass", "loader"
        )
        
        ClientNames = @(
            "horion", "onix", "zephyr", "packet", "crystal", "element", "toolbox",
            "ambrosial", "lakeside", "nitr0", "koid"
        )
        
        APICalls = @(
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "LoadLibrary",
            "GetProcAddress", "OpenProcess", "ReadProcessMemory", "VirtualProtect",
            "SetWindowsHookEx", "GetAsyncKeyState", "mouse_event", "keybd_event"
        )
        
        Obfuscation = @(
            "base64", "decrypt", "deobfuscate", "unpack", "rc4", "xor", "aes",
            "cipher", "encode", "obfuscate", "scramble"
        )
        
        AntiDebug = @(
            "IsDebuggerPresent", "CheckRemoteDebugger", "NtQueryInformationProcess",
            "OutputDebugString", "debugger", "anti-debug", "anti_debug"
        )
        
        Minecraft = @(
            "minecraft", "mojang", "bedrock", "renderdragon", "level.dat",
            "behavior_pack", "resource_pack", "MinecraftUWP"
        )
    }
    
    # Carpetas a analizar
    $scanPaths = @(
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:APPDATA",
        "$env:LOCALAPPDATA\Temp",
        "$env:TEMP"
    )
    
    # ===== FASE 1: EXTRACCIÓN Y ANÁLISIS DE STRINGS =====
    Write-Log "Fase 1: Extrayendo strings de archivos ejecutables..." "Gray"
    
    foreach ($path in $scanPaths) {
        if (Test-Path $path) {
            $executableFiles = Get-ChildItem -Path $path -Include "*.exe","*.dll","*.jar" -Recurse -File -ErrorAction SilentlyContinue -Force |
                Where-Object { 
                    $_.LastWriteTime -gt (Get-Date).AddDays(-60) -and 
                    $_.Length -gt 10KB -and $_.Length -lt 50MB
                } | Select-Object -First 30
            
            foreach ($file in $executableFiles) {
                $totalAnalyzed++
                
                try {
                    # Leer contenido como bytes
                    $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
                    
                    # Convertir a string para búsqueda de patrones
                    $content = [System.Text.Encoding]::ASCII.GetString($bytes)
                    
                    $detectedStrings = @()
                    $threatScore = 0
                    
                    # Buscar cada categoría de strings
                    foreach ($category in $suspiciousStrings.Keys) {
                        foreach ($keyword in $suspiciousStrings[$category]) {
                            if ($content -match $keyword) {
                                $detectedStrings += "$category : $keyword"
                                
                                # Calcular threat score
                                $threatScore += switch ($category) {
                                    "CheatFunctions" { 20 }
                                    "ClientNames" { 30 }
                                    "APICalls" { 15 }
                                    "Obfuscation" { 10 }
                                    "AntiDebug" { 25 }
                                    "Minecraft" { 5 }
                                    default { 5 }
                                }
                            }
                        }
                    }
                    
                    # Si se encontraron strings sospechosos
                    if ($detectedStrings.Count -gt 0) {
                        $severity = if ($threatScore -ge 80) { "CRITICAL" }
                                   elseif ($threatScore -ge 50) { "HIGH" }
                                   elseif ($threatScore -ge 30) { "MEDIUM" }
                                   else { "LOW" }
                        
                        Add-Detection "Strings - Contenido Sospechoso Detectado" `
                            "$($file.Name) contiene $($detectedStrings.Count) strings sospechosos" `
                            $severity `
                            $file.FullName `
                            $threatScore
                        
                        $stringFindings += [PSCustomObject]@{
                            Category = "Suspicious Strings"
                            FileName = $file.Name
                            Path = $file.FullName
                            Size = $file.Length
                            DetectedStrings = ($detectedStrings -join " | ")
                            StringCount = $detectedStrings.Count
                            ThreatScore = $threatScore
                            Hash = Get-FileHash-Safe $file.FullName
                        }
                    }
                    
                } catch {
                    Write-Log "Error analizando $($file.Name): $($_.Exception.Message)" "Yellow"
                }
            }
        }
    }
    
    # ===== FASE 2: DETECCIÓN DE OFUSCACIÓN =====
    Write-Log "Fase 2: Detectando técnicas de ofuscación..." "Gray"
    
    foreach ($path in $scanPaths) {
        if (Test-Path $path) {
            $files = Get-ChildItem -Path $path -Include "*.exe","*.dll" -Recurse -File -ErrorAction SilentlyContinue -Force |
                Where-Object { 
                    $_.LastWriteTime -gt (Get-Date).AddDays(-30) -and 
                    $_.Length -gt 50KB -and $_.Length -lt 20MB
                } | Select-Object -First 20
            
            foreach ($file in $files) {
                $totalAnalyzed++
                
                try {
                    $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
                    
                    # === TÉCNICA 1: Detectar alto porcentaje de bytes nulos (padding) ===
                    $nullBytes = ($bytes | Where-Object { $_ -eq 0 }).Count
                    $nullPercentage = ($nullBytes / $bytes.Length) * 100
                    
                    if ($nullPercentage -gt 60) {
                        Add-Detection "Ofuscación - Alto Contenido de Padding" `
                            "$($file.Name) - $([math]::Round($nullPercentage, 1))% bytes nulos (padding sospechoso)" `
                            "MEDIUM" `
                            $file.FullName `
                            70
                        
                        $stringFindings += [PSCustomObject]@{
                            Category = "Obfuscation - Padding"
                            FileName = $file.Name
                            Path = $file.FullName
                            NullPercentage = [math]::Round($nullPercentage, 1)
                            ThreatScore = 70
                            Reason = "Exceso de bytes nulos (posible evasión)"
                        }
                    }
                    
                    # === TÉCNICA 2: Detectar secciones con alta entropía (cifrado) ===
                    if ($bytes.Length -gt 1024) {
                        # Analizar en bloques de 1KB
                        $blockSize = 1024
                        $highEntropyBlocks = 0
                        
                        for ($i = 0; $i -lt $bytes.Length - $blockSize; $i += $blockSize) {
                            $block = $bytes[$i..($i + $blockSize - 1)]
                            $uniqueBytes = ($block | Group-Object | Measure-Object).Count
                            $entropy = $uniqueBytes / 256.0
                            
                            if ($entropy -gt 0.95) {
                                $highEntropyBlocks++
                            }
                        }
                        
                        $totalBlocks = [math]::Floor($bytes.Length / $blockSize)
                        $highEntropyPercentage = ($highEntropyBlocks / $totalBlocks) * 100
                        
                        if ($highEntropyPercentage -gt 40) {
                            Add-Detection "Ofuscación - Contenido Cifrado/Comprimido" `
                                "$($file.Name) - $([math]::Round($highEntropyPercentage, 1))% bloques con alta entropía" `
                                "HIGH" `
                                $file.FullName `
                                80
                            
                            $stringFindings += [PSCustomObject]@{
                                Category = "Obfuscation - Encryption"
                                FileName = $file.Name
                                Path = $file.FullName
                                HighEntropyPercentage = [math]::Round($highEntropyPercentage, 1)
                                ThreatScore = 80
                                Reason = "Contenido posiblemente cifrado"
                            }
                        }
                    }
                    
                    # === TÉCNICA 3: Detectar strings codificados en Base64 ===
                    $content = [System.Text.Encoding]::ASCII.GetString($bytes)
                    $base64Pattern = '[A-Za-z0-9+/]{40,}={0,2}'
                    $base64Matches = [regex]::Matches($content, $base64Pattern)
                    
                    if ($base64Matches.Count -gt 10) {
                        Add-Detection "Ofuscación - Múltiples Strings Base64" `
                            "$($file.Name) - $($base64Matches.Count) strings Base64 detectados" `
                            "MEDIUM" `
                            $file.FullName `
                            65
                        
                        $stringFindings += [PSCustomObject]@{
                            Category = "Obfuscation - Base64"
                            FileName = $file.Name
                            Path = $file.FullName
                            Base64Count = $base64Matches.Count
                            ThreatScore = 65
                            Reason = "Múltiples strings codificados en Base64"
                        }
                    }
                    
                    # === TÉCNICA 4: Detectar ausencia de strings legibles (packed) ===
                    $readableStrings = [regex]::Matches($content, '[\x20-\x7E]{8,}')
                    $readablePercentage = ($readableStrings.Count / ($bytes.Length / 100)) * 100
                    
                    if ($readablePercentage -lt 5 -and $bytes.Length -gt 100KB) {
                        Add-Detection "Ofuscación - Archivo Empaquetado (Packed)" `
                            "$($file.Name) - Muy pocos strings legibles ($([math]::Round($readablePercentage, 2))%)" `
                            "HIGH" `
                            $file.FullName `
                            85
                        
                        $stringFindings += [PSCustomObject]@{
                            Category = "Obfuscation - Packed"
                            FileName = $file.Name
                            Path = $file.FullName
                            ReadablePercentage = [math]::Round($readablePercentage, 2)
                            ThreatScore = 85
                            Reason = "Archivo empaquetado o comprimido (UPX, etc.)"
                        }
                    }
                    
                } catch {
                    Write-Log "Error en análisis de ofuscación de $($file.Name)" "Yellow"
                }
            }
        }
    }
    
    # ===== FASE 3: ANÁLISIS DE IMPORTS (API CALLS SOSPECHOSAS) =====
    Write-Log "Fase 3: Analizando imports de Windows API..." "Gray"
    
    foreach ($path in @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop")) {
        if (Test-Path $path) {
            $exeFiles = Get-ChildItem -Path $path -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue -Force |
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) } |
                Select-Object -First 20
            
            foreach ($file in $exeFiles) {
                $totalAnalyzed++
                
                try {
                    $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
                    $content = [System.Text.Encoding]::ASCII.GetString($bytes)
                    
                    # APIs peligrosas de inyección
                    $dangerousAPIs = @(
                        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                        "NtCreateThreadEx", "RtlCreateUserThread", "SetWindowsHookEx",
                        "GetAsyncKeyState", "SetThreadContext", "QueueUserAPC"
                    )
                    
                    $detectedAPIs = @()
                    foreach ($api in $dangerousAPIs) {
                        if ($content -match $api) {
                            $detectedAPIs += $api
                        }
                    }
                    
                    if ($detectedAPIs.Count -ge 3) {
                        Add-Detection "Strings - APIs de Inyección Detectadas" `
                            "$($file.Name) usa $($detectedAPIs.Count) APIs de inyección: $($detectedAPIs -join ', ')" `
                            "CRITICAL" `
                            $file.FullName `
                            95
                        
                        $stringFindings += [PSCustomObject]@{
                            Category = "Dangerous APIs"
                            FileName = $file.Name
                            Path = $file.FullName
                            APIs = ($detectedAPIs -join ", ")
                            APICount = $detectedAPIs.Count
                            ThreatScore = 95
                            Reason = "Múltiples APIs de inyección/hooking"
                        }
                    }
                    
                } catch {}
            }
        }
    }
    
    # ===== FASE 4: DETECCIÓN DE ANTI-ANÁLISIS =====
    Write-Log "Fase 4: Detectando técnicas anti-análisis y anti-debug..." "Gray"
    
    foreach ($path in $scanPaths) {
        if (Test-Path $path) {
            $files = Get-ChildItem -Path $path -Include "*.exe","*.dll" -Recurse -File -ErrorAction SilentlyContinue -Force |
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) } |
                Select-Object -First 15
            
            foreach ($file in $files) {
                $totalAnalyzed++
                
                try {
                    $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
                    $content = [System.Text.Encoding]::ASCII.GetString($bytes)
                    
                    $antiAnalysisTechniques = @()
                    
                    # Técnicas anti-debug
                    if ($content -match "IsDebuggerPresent") { $antiAnalysisTechniques += "IsDebuggerPresent" }
                    if ($content -match "CheckRemoteDebugger") { $antiAnalysisTechniques += "CheckRemoteDebugger" }
                    if ($content -match "NtQueryInformationProcess") { $antiAnalysisTechniques += "NtQueryInformationProcess" }
                    if ($content -match "OutputDebugString") { $antiAnalysisTechniques += "OutputDebugString" }
                    
                    # Técnicas anti-VM
                    if ($content -match "VirtualBox|VMware|QEMU|Xen") { $antiAnalysisTechniques += "VM Detection" }
                    
                    # Técnicas anti-sandbox
                    if ($content -match "Sleep|GetTickCount|QueryPerformanceCounter") {
                        # Verificar si hay múltiples llamadas (técnica de evasión temporal)
                        $sleepCount = ([regex]::Matches($content, "Sleep")).Count
                        if ($sleepCount -gt 5) {
                            $antiAnalysisTechniques += "Time-based Evasion"
                        }
                    }
                    
                    if ($antiAnalysisTechniques.Count -gt 0) {
                        Add-Detection "Anti-Análisis - Técnicas de Evasión Detectadas" `
                            "$($file.Name) - $($antiAnalysisTechniques.Count) técnicas: $($antiAnalysisTechniques -join ', ')" `
                            "HIGH" `
                            $file.FullName `
                            85
                        
                        $stringFindings += [PSCustomObject]@{
                            Category = "Anti-Analysis"
                            FileName = $file.Name
                            Path = $file.FullName
                            Techniques = ($antiAnalysisTechniques -join ", ")
                            TechniqueCount = $antiAnalysisTechniques.Count
                            ThreatScore = 85
                            Reason = "Contiene técnicas anti-debug/anti-VM"
                        }
                    }
                    
                } catch {}
            }
        }
    }
    
    # ===== FASE 5: ANÁLISIS DE SECCIONES PE (EJECUTABLES) =====
    Write-Log "Fase 5: Analizando estructura PE de ejecutables..." "Gray"
    
    foreach ($path in @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop")) {
        if (Test-Path $path) {
            $exeFiles = Get-ChildItem -Path $path -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue -Force |
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) } |
                Select-Object -First 15
            
            foreach ($file in $exeFiles) {
                $totalAnalyzed++
                
                try {
                    $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
                    
                    # Verificar si es PE válido (MZ header)
                    if ($bytes.Length -gt 64 -and $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
                        
                        # Buscar secciones sospechosas
                        $content = [System.Text.Encoding]::ASCII.GetString($bytes)
                        
                        # Nombres de secciones comunes en packers/malware
                        $suspiciousSections = @(".upx", ".pack", ".crypted", ".enigma", ".aspack", ".petite")
                        
                        foreach ($section in $suspiciousSections) {
                            if ($content -match [regex]::Escape($section)) {
                                Add-Detection "PE Analysis - Sección Sospechosa" `
                                    "$($file.Name) contiene sección '$section' (posible packer)" `
                                    "HIGH" `
                                    $file.FullName `
                                    80
                                
                                $stringFindings += [PSCustomObject]@{
                                    Category = "PE Structure"
                                    FileName = $file.Name
                                    Path = $file.FullName
                                    SuspiciousSection = $section
                                    ThreatScore = 80
                                    Reason = "Sección PE indica uso de packer/crypter"
                                }
                                break
                            }
                        }
                        
                        # Detectar ejecutables sin imports (muy sospechoso)
                        $hasImports = $content -match "kernel32|user32|ntdll|advapi32"
                        if (-not $hasImports -and $bytes.Length -gt 50KB) {
                            Add-Detection "PE Analysis - Sin Imports" `
                                "$($file.Name) no tiene imports estándar (posible packed/cifrado)" `
                                "HIGH" `
                                $file.FullName `
                                85
                        }
                    }
                    
                } catch {}
            }
        }
    }
    
    # Exportar resultados
    $stringFindings | Export-Csv "$outputDir\22_String_Analysis.csv" -NoTypeInformation
    Write-Log "Análisis de Strings: $totalAnalyzed archivos analizados, $($stringFindings.Count) hallazgos" "Green"
    
    # Estadísticas
    if ($stringFindings.Count -gt 0) {
        Write-Log "`nHallazgos por categoría:" "Cyan"
        $stringFindings | Group-Object Category | Sort-Object Count -Descending | ForEach-Object {
            Write-Log "  - $($_.Name): $($_.Count)" "Gray"
        }
        
        # Top archivos más sospechosos
        $topThreats = $stringFindings | Sort-Object ThreatScore -Descending | Select-Object -First 5
        if ($topThreats.Count -gt 0) {
            Write-Log "`nTop 5 archivos más sospechosos:" "Red"
            foreach ($threat in $topThreats) {
                Write-Log "  - $($threat.FileName) (Score: $($threat.ThreatScore))" "Red"
            }
        }
    }
}

# ============================================
# MÓDULO 20: ANÁLISIS HEURÍSTICO AVANZADO
# ============================================================================

function Invoke-AdvancedFileDetection {
    Update-Progress "Escaneando archivos en todo el sistema..."
    Write-Log "`n=== MÓDULO 21: DETECCIÓN AVANZADA DE ARCHIVOS ===" "Cyan"
    
    $fileFindings = @()
    $totalScanned = 0
    
    # Carpetas críticas para escanear
    $criticalPaths = @(
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:APPDATA",
        "$env:LOCALAPPDATA",
        "$env:TEMP",
        "C:\Users\Public",
        "C:\ProgramData"
    )
    
    Write-Log "Iniciando escaneo profundo de archivos..." "Yellow"
    
    # ===== FASE 1: BUSCAR ARCHIVOS CONOCIDOS =====
    Write-Log "Fase 1: Buscando archivos conocidos de cheats..." "Gray"
    
    foreach ($category in $knownCheatFiles.Keys) {
        foreach ($cheatFile in $knownCheatFiles[$category]) {
            $fileName = $cheatFile.Name
            
            # Buscar en carpetas críticas
            foreach ($path in $criticalPaths) {
                if (Test-Path $path) {
                    $found = Get-ChildItem -Path $path -Filter $fileName -Recurse -ErrorAction SilentlyContinue -Force |
                        Select-Object -First 5
                    
                    foreach ($file in $found) {
                        $totalScanned++
                        $hash = Get-FileHash-Safe $file.FullName
                        
                        Add-Detection "Archivo - Cheat Conocido Detectado" `
                            "$fileName encontrado en $($file.DirectoryName)" `
                            "CRITICAL" `
                            $file.FullName `
                            $cheatFile.ThreatLevel
                        
                        $fileFindings += [PSCustomObject]@{
                            Category = $category
                            FileName = $file.Name
                            Path = $file.FullName
                            Size = $file.Length
                            Created = $file.CreationTime
                            Modified = $file.LastWriteTime
                            Accessed = $file.LastAccessTime
                            Hash = $hash
                            ThreatLevel = $cheatFile.ThreatLevel
                            Reason = "Archivo conocido de cheat"
                            Hidden = $file.Attributes -match "Hidden"
                        }
                    }
                }
            }
            
            # Buscar en disco C:\ (solo raíz y Program Files)
            $systemPaths = @("C:\", "C:\Program Files", "C:\Program Files (x86)")
            foreach ($sysPath in $systemPaths) {
                $found = Get-ChildItem -Path $sysPath -Filter $fileName -ErrorAction SilentlyContinue -Force |
                    Where-Object { -not $_.PSIsContainer } |
                    Select-Object -First 2
                
                foreach ($file in $found) {
                    $totalScanned++
                    Add-Detection "Archivo - Cheat en Ubicación del Sistema" `
                        "$fileName en $($file.DirectoryName)" `
                        "CRITICAL" `
                        $file.FullName `
                        ($cheatFile.ThreatLevel + 5)
                }
            }
        }
    }
    
    # ===== FASE 2: ARCHIVOS SOSPECHOSOS POR EXTENSIÓN =====
    Write-Log "Fase 2: Analizando archivos sospechosos por extensión..." "Gray"
    
    $suspiciousExtensions = @("*.dll", "*.exe", "*.jar", "*.bat", "*.vbs", "*.ps1", "*.scr")
    
    foreach ($path in $criticalPaths) {
        if (Test-Path $path) {
            foreach ($ext in $suspiciousExtensions) {
                $files = Get-ChildItem -Path $path -Filter $ext -Recurse -ErrorAction SilentlyContinue -Force |
                    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) } |
                    Select-Object -First 100
                
                foreach ($file in $files) {
                    $totalScanned++
                    $signatures = Test-CheatSignature $file.Name
                    
                    if ($signatures.Count -gt 0) {
                        $hash = Get-FileHash-Safe $file.FullName
                        
                        Add-Detection "Archivo - Nombre Sospechoso" `
                            "$($file.Name) en $($file.DirectoryName)" `
                            "HIGH" `
                            $file.FullName `
                            80
                        
                        $fileFindings += [PSCustomObject]@{
                            Category = "Suspicious Name"
                            FileName = $file.Name
                            Path = $file.FullName
                            Size = $file.Length
                            Created = $file.CreationTime
                            Modified = $file.LastWriteTime
                            Hash = $hash
                            ThreatLevel = 80
                            Reason = "Nombre contiene palabras clave sospechosas"
                            Signatures = ($signatures.Signature -join ", ")
                        }
                    }
                }
            }
        }
    }
    
    # ===== FASE 3: ARCHIVOS OCULTOS =====
    Write-Log "Fase 3: Detectando archivos ocultos..." "Gray"
    
    foreach ($path in $criticalPaths) {
        if (Test-Path $path) {
            $hiddenFiles = Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object { 
                    $_.Attributes -match "Hidden" -and 
                    -not $_.PSIsContainer -and
                    $_.Extension -in @(".exe", ".dll", ".jar", ".bat", ".vbs")
                } | Select-Object -First 50
            
            foreach ($file in $hiddenFiles) {
                $totalScanned++
                $signatures = Test-CheatSignature $file.Name
                
                if ($signatures.Count -gt 0 -or $file.Length -gt 1MB) {
                    Add-Detection "Archivo - Archivo Oculto Sospechoso" `
                        "$($file.Name) (oculto)" `
                        "HIGH" `
                        $file.FullName `
                        75
                    
                    $fileFindings += [PSCustomObject]@{
                        Category = "Hidden File"
                        FileName = $file.Name
                        Path = $file.FullName
                        Size = $file.Length
                        Modified = $file.LastWriteTime
                        ThreatLevel = 75
                        Reason = "Archivo ejecutable oculto"
                        Hidden = $true
                    }
                }
            }
        }
    }
    
    # ===== FASE 4: ARCHIVOS SIN EXTENSIÓN O DOBLE EXTENSIÓN =====
    Write-Log "Fase 4: Buscando archivos sin extensión o con doble extensión..." "Gray"
    
    foreach ($path in $criticalPaths) {
        if (Test-Path $path) {
            # Archivos sin extensión
            $noExtFiles = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue -Force |
                Where-Object { 
                    -not $_.Extension -and 
                    $_.Length -gt 100KB -and
                    $_.LastWriteTime -gt (Get-Date).AddDays(-30)
                } | Select-Object -First 20
            
            foreach ($file in $noExtFiles) {
                $totalScanned++
                Add-Detection "Archivo - Sin Extensión" `
                    "$($file.Name) sin extensión" `
                    "MEDIUM" `
                    $file.FullName `
                    60
                
                $fileFindings += [PSCustomObject]@{
                    Category = "No Extension"
                    FileName = $file.Name
                    Path = $file.FullName
                    Size = $file.Length
                    ThreatLevel = 60
                    Reason = "Archivo sin extensión"
                }
            }
            
            # Doble extensión (ej: archivo.pdf.exe)
            $doubleExtFiles = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue -Force |
                Where-Object { 
                    $_.Name -match "\.[a-z]{3,4}\.(exe|dll|bat|vbs|scr|jar)$" -and
                    $_.LastWriteTime -gt (Get-Date).AddDays(-30)
                } | Select-Object -First 20
            
            foreach ($file in $doubleExtFiles) {
                $totalScanned++
                Add-Detection "Archivo - Doble Extensión Sospechosa" `
                    "$($file.Name) con doble extensión" `
                    "HIGH" `
                    $file.FullName `
                    85
                
                $fileFindings += [PSCustomObject]@{
                    Category = "Double Extension"
                    FileName = $file.Name
                    Path = $file.FullName
                    Size = $file.Length
                    ThreatLevel = 85
                    Reason = "Doble extensión (posible malware)"
                }
            }
        }
    }
    
    # ===== FASE 5: ARCHIVOS CON TIMESTAMPS MANIPULADOS =====
    Write-Log "Fase 5: Detectando manipulación de timestamps..." "Gray"
    
    foreach ($path in @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop")) {
        if (Test-Path $path) {
            $manipulatedFiles = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue -Force |
                Where-Object { 
                    $_.CreationTime -gt $_.LastWriteTime -and
                    $_.Extension -in @(".exe", ".dll", ".jar") -and
                    $_.LastWriteTime -gt (Get-Date).AddDays(-14)
                } | Select-Object -First 30
            
            foreach ($file in $manipulatedFiles) {
                $totalScanned++
                $timeDiff = ($file.CreationTime - $file.LastWriteTime).TotalHours
                
                if ($timeDiff -gt 1) {
                    Add-Detection "Archivo - Timestamp Manipulado" `
                        "$($file.Name) - Creado después de modificado ($([Math]::Round($timeDiff, 1))h diferencia)" `
                        "HIGH" `
                        $file.FullName `
                        80
                    
                    $fileFindings += [PSCustomObject]@{
                        Category = "Manipulated Timestamp"
                        FileName = $file.Name
                        Path = $file.FullName
                        Created = $file.CreationTime
                        Modified = $file.LastWriteTime
                        TimeDifference = "$([Math]::Round($timeDiff, 1)) horas"
                        ThreatLevel = 80
                        Reason = "Timestamp manipulado con SetFileDate o similar"
                    }
                }
            }
        }
    }
    
    # ===== FASE 6: ARCHIVOS GRANDES EN TEMP =====
    Write-Log "Fase 6: Buscando archivos grandes en carpetas temporales..." "Gray"
    
    $tempPaths = @($env:TEMP, "$env:LOCALAPPDATA\Temp", "C:\Windows\Temp")
    foreach ($tempPath in $tempPaths) {
        if (Test-Path $tempPath) {
            $largeFiles = Get-ChildItem -Path $tempPath -Recurse -File -ErrorAction SilentlyContinue -Force |
                Where-Object { 
                    $_.Length -gt 10MB -and
                    $_.Extension -in @(".exe", ".dll", ".zip", ".rar", ".7z") -and
                    $_.LastWriteTime -gt (Get-Date).AddDays(-7)
                } | Select-Object -First 20
            
            foreach ($file in $largeFiles) {
                $totalScanned++
                $sizeMB = [Math]::Round($file.Length / 1MB, 2)
                
                Add-Detection "Archivo - Archivo Grande en TEMP" `
                    "$($file.Name) ($sizeMB MB)" `
                    "MEDIUM" `
                    $file.FullName `
                    65
                
                $fileFindings += [PSCustomObject]@{
                    Category = "Large Temp File"
                    FileName = $file.Name
                    Path = $file.FullName
                    Size = $file.Length
                    SizeMB = $sizeMB
                    ThreatLevel = 65
                    Reason = "Archivo grande en carpeta temporal"
                }
            }
        }
    }
    
    # ===== FASE 7: ARCHIVOS .JAR SOSPECHOSOS (AutoClickers) =====
    Write-Log "Fase 7: Analizando archivos JAR..." "Gray"
    
    foreach ($path in $criticalPaths) {
        if (Test-Path $path) {
            $jarFiles = Get-ChildItem -Path $path -Filter "*.jar" -Recurse -ErrorAction SilentlyContinue -Force |
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-60) } |
                Select-Object -First 30
            
            foreach ($jar in $jarFiles) {
                $totalScanned++
                $signatures = Test-CheatSignature $jar.Name
                
                # Nombres sospechosos de AutoClickers
                if ($jar.Name -match "(auto|click|macro|ghost|jna|jnative)" -or $signatures.Count -gt 0) {
                    Add-Detection "Archivo - JAR Sospechoso (Posible AutoClicker)" `
                        $jar.Name `
                        "HIGH" `
                        $jar.FullName `
                        80
                    
                    $fileFindings += [PSCustomObject]@{
                        Category = "Suspicious JAR"
                        FileName = $jar.Name
                        Path = $jar.FullName
                        Size = $jar.Length
                        ThreatLevel = 80
                        Reason = "JAR con nombre sospechoso de AutoClicker"
                    }
                }
            }
        }
    }
    
    # ===== FASE 8: ARCHIVOS EN CARPETAS DE RECICLAJE =====
    Write-Log "Fase 8: Escaneando papelera de reciclaje..." "Gray"
    
    $recycleBin = "C:\`$Recycle.Bin"
    if (Test-Path $recycleBin) {
        $deletedFiles = Get-ChildItem -Path $recycleBin -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { 
                -not $_.PSIsContainer -and
                $_.Extension -in @(".exe", ".dll", ".jar") -and
                $_.LastWriteTime -gt (Get-Date).AddDays(-7)
            } | Select-Object -First 30
        
        foreach ($file in $deletedFiles) {
            $totalScanned++
            $signatures = Test-CheatSignature $file.Name
            
            if ($signatures.Count -gt 0) {
                Add-Detection "Archivo - Cheat en Papelera" `
                    "$($file.Name) eliminado recientemente" `
                    "HIGH" `
                    $file.FullName `
                    75
                
                $fileFindings += [PSCustomObject]@{
                    Category = "Deleted File"
                    FileName = $file.Name
                    Path = $file.FullName
                    DeletedDate = $file.LastWriteTime
                    ThreatLevel = 75
                    Reason = "Archivo sospechoso en papelera"
                }
            }
        }
    }
    
    # Exportar resultados
    $fileFindings | Export-Csv "$outputDir\20_Advanced_File_Detection.csv" -NoTypeInformation
    Write-Log "Detección de Archivos: $totalScanned archivos escaneados, $($fileFindings.Count) sospechosos" "Green"
    
    # Estadísticas por categoría
    if ($fileFindings.Count -gt 0) {
        Write-Log "`nEstadísticas por categoría:" "Cyan"
        $fileFindings | Group-Object Category | Sort-Object Count -Descending | ForEach-Object {
            Write-Log "  - $($_.Name): $($_.Count)" "Gray"
        }
    }
}

# ============================================
# MÓDULO 20: ANÁLISIS HEURÍSTICO AVANZADO
# ============================================

function Invoke-HeuristicAnalysis {
    Update-Progress "Ejecutando análisis heurístico..."
    Write-Log "`n=== MÓDULO 20: ANÁLISIS HEURÍSTICO ===" "Cyan"
    
    $heuristicScore = 0
    $heuristicFindings = @()
    
    # Patrón 1: Múltiples herramientas de limpieza
    $cleanerTools = @("CCleaner", "BleachBit", "PrivaZer", "Eraser")
    $cleanerCount = 0
    foreach ($tool in $cleanerTools) {
        $found = Get-Process -Name "*$tool*" -ErrorAction SilentlyContinue
        if ($found) { $cleanerCount++ }
    }
    
    if ($cleanerCount -ge 2) {
        $heuristicScore += 40
        Add-Detection "Heurístico - Múltiples Herramientas de Limpieza" `
            "$cleanerCount herramientas detectadas" `
            "HIGH" `
            "Behavioral Analysis" `
            80
    }
    
    # Patrón 2: Modificación de timestamps
    $recentTimestampMods = Get-ChildItem -Path "C:\Users" -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { 
            $_.CreationTime -gt $_.LastWriteTime -and
            $_.LastWriteTime -gt (Get-Date).AddDays(-7)
        } | Select-Object -First 10
    
    if ($recentTimestampMods.Count -gt 5) {
        $heuristicScore += 30
        Add-Detection "Heurístico - Timestamps Manipulados" `
            "$($recentTimestampMods.Count) archivos con timestamps sospechosos" `
            "HIGH" `
            "Behavioral Analysis" `
            75
    }
    
    # Patrón 3: Actividad en horario sospechoso
    $currentHour = (Get-Date).Hour
    if ($currentHour -ge 2 -and $currentHour -le 5) {
        $heuristicScore += 20
        Add-Detection "Heurístico - Actividad en Horario Sospechoso" `
            "Escaneo ejecutado a las $currentHour:00 (madrugada)" `
            "MEDIUM" `
            "Behavioral Analysis" `
            60
    }
    
    # Patrón 4: Ratio alto de detecciones
    $detectionRatio = ($detections.Count / 100) * 100
    if ($detectionRatio -gt 50) {
        $heuristicScore += 50
        Add-Detection "Heurístico - Alto Ratio de Detecciones" `
            "$($detections.Count) detecciones encontradas" `
            "CRITICAL" `
            "Behavioral Analysis" `
            90
    }
    
    # Patrón 5: Servicios críticos deshabilitados
    $disabledServices = Get-Service -ErrorAction SilentlyContinue |
        Where-Object { 
            $_.Name -in @("EventLog","WinDefend","wscsvc") -and 
            $_.Status -ne "Running"
        }
    
    if ($disabledServices.Count -ge 2) {
        $heuristicScore += 60
        Add-Detection "Heurístico - Múltiples Servicios Críticos Deshabilitados" `
            "$($disabledServices.Count) servicios deshabilitados" `
            "CRITICAL" `
            "Behavioral Analysis" `
            95
    }
    
    $heuristicFindings += [PSCustomObject]@{
        Metric = "Puntuación Total"
        Value = $heuristicScore
        Threshold = 100
        Status = if ($heuristicScore -gt 80) { "CRÍTICO" } 
                 elseif ($heuristicScore -gt 50) { "ALTO" }
                 elseif ($heuristicScore -gt 30) { "MEDIO" }
                 else { "BAJO" }
    }
    
    $heuristicFindings | Export-Csv "$outputDir\19_Heuristic.csv" -NoTypeInformation
    Write-Log "Heurístico: Puntuación $heuristicScore/100" "Cyan"
    
    return $heuristicScore
}

# ============================================
# GENERACIÓN DE REPORTE HTML AVANZADO
# ============================================

function New-HTMLReport {
    param([int]$HeuristicScore)
    
    Write-Host "`n"
    Write-Log "Generando reporte HTML..." "Cyan"
    
    $endTime = Get-Date
    $duration = [math]::Round(($endTime - $startTime).TotalSeconds, 2)
    
    # Agrupar detecciones por severidad
    $critical = ($detections | Where-Object { $_.Severity -eq "CRITICAL" }).Count
    $high = ($detections | Where-Object { $_.Severity -eq "HIGH" }).Count
    $medium = ($detections | Where-Object { $_.Severity -eq "MEDIUM" }).Count
    $low = ($detections | Where-Object { $_.Severity -eq "LOW" }).Count
    
    # Calcular threat level
    $avgThreatLevel = if ($detections.Count -gt 0) {
        [math]::Round(($detections | Measure-Object -Property ThreatLevel -Average).Average, 0)
    } else { 0 }
    
    # Determinar veredicto
    $verdict = if ($critical -gt 0 -or $avgThreatLevel -gt 85 -or $HeuristicScore -gt 80) {
        @{Status = "POSITIVO"; Color = "#ff0000"; Message = "SE DETECTARON EVIDENCIAS DE CHEATS"}
    } elseif ($high -gt 3 -or $avgThreatLevel -gt 70 -or $HeuristicScore -gt 60) {
        @{Status = "SOSPECHOSO"; Color = "#ff6600"; Message = "SE DETECTARON MÚLTIPLES INDICADORES SOSPECHOSOS"}
    } elseif ($medium -gt 5 -or $HeuristicScore -gt 40) {
        @{Status = "PRECAUCIÓN"; Color = "#ffaa00"; Message = "SE DETECTARON ALGUNOS INDICADORES"}
    } else {
        @{Status = "LIMPIO"; Color = "#00ff00"; Message = "NO SE DETECTARON EVIDENCIAS SIGNIFICATIVAS"}
    }
    
    $htmlReport = @"
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NEXUS AntiCheat - Reporte $timestamp</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', 'Roboto', Arial, sans-serif;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%);
            color: #e0e0e0;
            padding: 20px;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: rgba(20, 20, 35, 0.95);
            border-radius: 15px;
            box-shadow: 0 10px 50px rgba(0, 217, 255, 0.2);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #00d9ff 0%, #0099cc 100%);
            padding: 40px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
            animation: pulse 4s ease-in-out infinite;
        }
        
        @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 0.3; }
            50% { transform: scale(1.1); opacity: 0.6; }
        }
        
        .header h1 {
            font-size: 3em;
            color: #0a0a0a;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
            position: relative;
            z-index: 1;
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            font-size: 1.2em;
            color: #1a1a2e;
            position: relative;
            z-index: 1;
        }
        
        .verdict-box {
            background: linear-gradient(135deg, rgba(0,0,0,0.8) 0%, rgba(26,26,46,0.8) 100%);
            margin: 30px;
            padding: 40px;
            border-radius: 12px;
            border: 3px solid $($verdict.Color);
            text-align: center;
            box-shadow: 0 5px 30px rgba(0,0,0,0.5), inset 0 0 30px rgba(0,217,255,0.1);
        }
        
        .verdict-status {
            font-size: 3em;
            font-weight: bold;
            color: $($verdict.Color);
            text-transform: uppercase;
            letter-spacing: 5px;
            margin-bottom: 15px;
            text-shadow: 0 0 20px $($verdict.Color);
        }
        
        .verdict-message {
            font-size: 1.3em;
            color: #e0e0e0;
            margin-top: 10px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, rgba(0,217,255,0.1) 0%, rgba(0,153,204,0.05) 100%);
            padding: 25px;
            border-radius: 10px;
            border: 1px solid rgba(0,217,255,0.3);
            transition: all 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0,217,255,0.3);
            border-color: rgba(0,217,255,0.6);
        }
        
        .stat-label {
            font-size: 0.9em;
            color: #888;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-bottom: 10px;
        }
        
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #00d9ff;
            text-shadow: 0 0 10px rgba(0,217,255,0.5);
        }
        
        .severity-indicators {
            display: flex;
            justify-content: space-around;
            padding: 30px;
            background: rgba(0,0,0,0.3);
        }
        
        .severity-item {
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            min-width: 120px;
        }
        
        .severity-item.critical { background: rgba(255,0,0,0.2); border: 2px solid #ff0000; }
        .severity-item.high { background: rgba(255,102,0,0.2); border: 2px solid #ff6600; }
        .severity-item.medium { background: rgba(255,170,0,0.2); border: 2px solid #ffaa00; }
        .severity-item.low { background: rgba(255,255,0,0.2); border: 2px solid #ffff00; }
        
        .severity-count {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .severity-label {
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .content-section {
            padding: 30px;
            border-top: 1px solid rgba(0,217,255,0.2);
        }
        
        .section-title {
            font-size: 1.8em;
            color: #00d9ff;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid rgba(0,217,255,0.3);
            display: flex;
            align-items: center;
        }
        
        .section-title::before {
            content: '▶';
            margin-right: 15px;
            color: #ff6600;
        }
        
        .detection-item {
            background: rgba(255,0,0,0.05);
            border-left: 4px solid #ff0000;
            padding: 15px;
            margin: 15px 0;
            border-radius: 5px;
            transition: all 0.3s ease;
        }
        
        .detection-item:hover {
            background: rgba(255,0,0,0.1);
            transform: translateX(5px);
        }
        
        .detection-item.high { border-left-color: #ff6600; background: rgba(255,102,0,0.05); }
        .detection-item.medium { border-left-color: #ffaa00; background: rgba(255,170,0,0.05); }
        .detection-item.low { border-left-color: #ffff00; background: rgba(255,255,0,0.05); }
        
        .detection-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .detection-category {
            font-weight: bold;
            color: #00d9ff;
            font-size: 1.1em;
        }
        
        .detection-severity {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .detection-severity.critical { background: #ff0000; color: #fff; }
        .detection-severity.high { background: #ff6600; color: #fff; }
        .detection-severity.medium { background: #ffaa00; color: #000; }
        .detection-severity.low { background: #ffff00; color: #000; }
        
        .detection-detail {
            color: #ccc;
            margin: 10px 0;
            font-size: 0.95em;
        }
        
        .detection-evidence {
            font-family: 'Courier New', monospace;
            background: rgba(0,0,0,0.5);
            padding: 10px;
            border-radius: 5px;
            font-size: 0.85em;
            color: #00ff00;
            margin-top: 10px;
            word-break: break-all;
        }
        
        .detection-time {
            font-size: 0.85em;
            color: #888;
            margin-top: 5px;
        }
        
        .files-list {
            background: rgba(0,0,0,0.3);
            padding: 20px;
            border-radius: 8px;
            margin-top: 20px;
        }
        
        .file-item {
            padding: 10px;
            margin: 5px 0;
            background: rgba(0,217,255,0.05);
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            transition: all 0.2s ease;
        }
        
        .file-item:hover {
            background: rgba(0,217,255,0.1);
        }
        
        .threat-meter {
            margin: 30px;
            text-align: center;
        }
        
        .meter-container {
            background: rgba(0,0,0,0.5);
            height: 40px;
            border-radius: 20px;
            overflow: hidden;
            position: relative;
            border: 2px solid rgba(0,217,255,0.3);
        }
        
        .meter-fill {
            height: 100%;
            background: linear-gradient(90deg, #00ff00 0%, #ffff00 40%, #ff6600 70%, #ff0000 100%);
            width: $avgThreatLevel%;
            transition: width 1s ease;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            padding-right: 15px;
            font-weight: bold;
            color: #000;
        }
        
        .meter-label {
            margin-top: 15px;
            font-size: 1.3em;
            color: #00d9ff;
        }
        
        .footer {
            background: rgba(0,0,0,0.5);
            padding: 30px;
            text-align: center;
            border-top: 2px solid rgba(0,217,255,0.3);
            margin-top: 30px;
        }
        
        .footer-info {
            color: #888;
            font-size: 0.9em;
            line-height: 1.8;
        }
        
        .watermark {
            margin-top: 20px;
            font-size: 1.2em;
            color: #00d9ff;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚡ NEXUS ANTICHEAT ⚡</h1>
            <div class="subtitle">Sistema Avanzado de Detección - Minecraft Bedrock Edition</div>
        </div>
        
        <div class="verdict-box">
            <div class="verdict-status">$($verdict.Status)</div>
            <div class="verdict-message">$($verdict.Message)</div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">📅 Fecha de Escaneo</div>
                <div class="stat-value" style="font-size: 1.2em;">$timestamp</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">⏱️ Duración</div>
                <div class="stat-value">$duration<span style="font-size: 0.5em;">seg</span></div>
            </div>
            <div class="stat-card">
                <div class="stat-label">🎯 Detecciones</div>
                <div class="stat-value">$($detections.Count)</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">💻 Usuario</div>
                <div class="stat-value" style="font-size: 1.2em;">$env:USERNAME</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">🖥️ Equipo</div>
                <div class="stat-value" style="font-size: 1.2em;">$env:COMPUTERNAME</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">📊 Score Heurístico</div>
                <div class="stat-value">$HeuristicScore<span style="font-size: 0.5em;">/100</span></div>
            </div>
        </div>
        
        <div class="threat-meter">
            <h3 style="color: #00d9ff; margin-bottom: 15px;">NIVEL DE AMENAZA PROMEDIO</h3>
            <div class="meter-container">
                <div class="meter-fill">$avgThreatLevel%</div>
            </div>
            <div class="meter-label">Threat Level: $avgThreatLevel / 100</div>
        </div>
        
        <div class="severity-indicators">
            <div class="severity-item critical">
                <div class="severity-count">$critical</div>
                <div class="severity-label">Crítico</div>
            </div>
            <div class="severity-item high">
                <div class="severity-count">$high</div>
                <div class="severity-label">Alto</div>
            </div>
            <div class="severity-item medium">
                <div class="severity-count">$medium</div>
                <div class="severity-label">Medio</div>
            </div>
            <div class="severity-item low">
                <div class="severity-count">$low</div>
                <div class="severity-label">Bajo</div>
            </div>
        </div>
"@

    # Agregar detecciones al HTML
    if ($detections.Count -gt 0) {
        $htmlReport += @"
        <div class="content-section">
            <div class="section-title">🚨 DETECCIONES DETALLADAS</div>
"@
        
        # Agrupar por categoría
        $grouped = $detections | Group-Object Category | Sort-Object Count -Descending
        
        foreach ($group in $grouped) {
            $htmlReport += "<h3 style='color: #ff6600; margin: 25px 0 15px 0;'>📁 $($group.Name) ($($group.Count))</h3>"
            
            foreach ($det in $group.Group) {
                $severityClass = $det.Severity.ToLower()
                $htmlReport += @"
                <div class="detection-item $severityClass">
                    <div class="detection-header">
                        <div class="detection-category">$($det.Category)</div>
                        <div class="detection-severity $severityClass">$($det.Severity) | Threat: $($det.ThreatLevel)</div>
                    </div>
                    <div class="detection-detail">$($det.Detail)</div>
"@
                if ($det.Evidence) {
                    $htmlReport += "<div class='detection-evidence'>📍 $($det.Evidence)</div>"
                }
                $htmlReport += "<div class='detection-time'>⏰ $($det.Timestamp)</div></div>"
            }
        }
        
        $htmlReport += "</div>"
    }
    
    # Archivos generados
    $htmlReport += @"
        <div class="content-section">
            <div class="section-title">📂 ARCHIVOS DE EVIDENCIA GENERADOS</div>
            <div class="files-list">
                <div class="file-item">📄 01_Minecraft_Files.csv - Archivos de Minecraft analizados</div>
                <div class="file-item">📄 02_Processes.csv - Procesos del sistema</div>
                <div class="file-item">📄 02_DLL_Injections.csv - DLLs inyectadas detectadas</div>
                <div class="file-item">📄 03_Prefetch.csv - Historial de ejecuciones (Prefetch)</div>
                <div class="file-item">📄 04_BAM.csv - Background Activity Moderator</div>
                <div class="file-item">📄 05_Temp_Files.csv - Archivos temporales</div>
                <div class="file-item">📄 06_Registry.csv - Entradas del registro</div>
                <div class="file-item">📄 07_USN_Journal.csv - Cambios en el sistema de archivos</div>
                <div class="file-item">📄 08_USB_Devices.csv - Dispositivos USB (actuales e históricos)</div>
                <div class="file-item">📄 09_Mouse_Macros.csv - Detección de macros en periféricos</div>
                <div class="file-item">📄 10_AntiDetection.csv - Herramientas anti-detección</div>
                <div class="file-item">📄 11_Services.csv - Servicios del sistema</div>
                <div class="file-item">📄 12_Network.csv - Conexiones de red activas</div>
                <div class="file-item">📄 13_Recent_Files.csv - Archivos recientes</div>
                <div class="file-item">📄 14_Tasks.csv - Tareas programadas</div>
                <div class="file-item">📄 15_PowerShell_History.txt - Historial de PowerShell</div>
                <div class="file-item">📄 16_Drivers.csv - Drivers del sistema</div>
                <div class="file-item">📄 17_Performance.csv - Análisis de rendimiento</div>
                <div class="file-item">📄 18_Events.csv - Eventos del sistema</div>
                <div class="file-item">📄 19_Heuristic.csv - Análisis heurístico</div>
                <div class="file-item">📄 20_Advanced_File_Detection.csv - Detección avanzada de archivos</div>
                <div class="file-item">📄 21_File_Forensics.csv - Análisis forense (extensiones falsas, archivos vaciados)</div>
                <div class="file-item">📄 22_String_Analysis.csv - Análisis de strings, ofuscación, APIs peligrosas</div>
                <div class="file-item">📄 23_Hidden_Locations.csv - Ubicaciones ocultas del sistema</div>
                <div class="file-item">📄 24_Disguised_Files.csv - Archivos disfrazados con nombres genéricos</div>
                <div class="file-item">📄 25_Certificates.csv - Análisis de certificados digitales</div>
                <div class="file-item">📄 26_C2_Connections.csv - Detección de servidores C2</div>
                <div class="file-item">📄 27_ADS_Streams.csv - Alternate Data Streams</div>
                <div class="file-item">📄 28_Memory_Analysis.csv - Análisis de memoria y hooks</div>
                <div class="file-item">📄 29_System_Modifications.csv - Modificaciones del sistema</div>
                <div class="file-item">📄 NEXUS_MASTER_LOG.txt - Log completo del escaneo</div>
            </div>
        </div>
        
        <div class="footer">
            <div class="footer-info">
                <strong>NEXUS ANTICHEAT v5.0 PROFESSIONAL EDITION</strong><br>
                Sistema Avanzado de Detección para Minecraft Bedrock<br>
                Desarrollado con tecnología de análisis forense y detección heurística<br>
                Inspirado en Ocean & Echo AntiCheat
            </div>
            <div class="watermark">⚡ POWERED BY NEXUS SECURITY ⚡</div>
        </div>
    </div>
</body>
</html>
"@
    
    $htmlReport | Out-File "$outputDir\NEXUS_Report.html" -Encoding UTF8
    Write-Log "Reporte HTML generado exitosamente" "Green"
}

# ============================================
# FUNCIÓN PRINCIPAL - EJECUTAR TODOS LOS MÓDULOS
# ============================================

function Start-NexusAntiCheat {
    Write-Log "═══════════════════════════════════════════════════════════" "Cyan"
    Write-Log "  INICIANDO NEXUS ANTICHEAT v5.0" "Cyan"
    Write-Log "═══════════════════════════════════════════════════════════" "Cyan"
    Write-Log ""
    Write-Log "📍 Directorio de salida: $outputDir" "Gray"
    Write-Log "⏰ Hora de inicio: $(Get-Date -Format 'HH:mm:ss')" "Gray"
    Write-Log ""
    
    # Ejecutar todos los módulos
    Invoke-MinecraftDeepScan
    Invoke-ProcessAnalysis
    Invoke-PrefetchAnalysis
    Invoke-BAMAnalysis
    Invoke-TempAnalysis
    Invoke-RegistryAnalysis
    Invoke-JournalAnalysis
    Invoke-USBAnalysis
    Invoke-MacroAnalysis
    Invoke-AntiDetectionAnalysis
    Invoke-ServiceAnalysis
    Invoke-NetworkAnalysis
    Invoke-RecentFilesAnalysis
    Invoke-TaskAnalysis
    Invoke-PowerShellHistory
    Invoke-RecycleBinAnalysis
    Invoke-DriverAnalysis
    Invoke-PerformanceAnalysis
    Invoke-EventLogAnalysis
    Invoke-AdvancedFileDetection
    Invoke-FileForensicsAnalysis
    Invoke-DeepStringAnalysis
    Invoke-HiddenLocationScan
    Invoke-DisguisedFileDetection
    Invoke-CertificateAnalysis
    Invoke-C2Detection
    Invoke-AlternateDataStreamScan
    Invoke-MemoryAnalysis
    Invoke-SystemModificationAnalysis
    
    # Análisis heurístico final
    $heuristicScore = Invoke-HeuristicAnalysis
    
    # Generar reporte HTML
    New-HTMLReport -HeuristicScore $heuristicScore
    
    # Resumen final
    Write-Host "`n"
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "                 ESCANEO COMPLETADO" -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    $endTime = Get-Date
    $duration = [math]::Round(($endTime - $startTime).TotalSeconds, 2)
    
    Write-Host "⏱️  Duración total: " -NoNewline -ForegroundColor Gray
    Write-Host "$duration segundos" -ForegroundColor White
    
    Write-Host "📊 Total de detecciones: " -NoNewline -ForegroundColor Gray
    if ($detections.Count -eq 0) {
        Write-Host "$($detections.Count)" -ForegroundColor Green
    } elseif ($detections.Count -le 5) {
        Write-Host "$($detections.Count)" -ForegroundColor Yellow
    } else {
        Write-Host "$($detections.Count)" -ForegroundColor Red
    }
    
    Write-Host "🎯 Score heurístico: " -NoNewline -ForegroundColor Gray
    if ($heuristicScore -le 30) {
        Write-Host "$heuristicScore/100" -ForegroundColor Green
    } elseif ($heuristicScore -le 60) {
        Write-Host "$heuristicScore/100" -ForegroundColor Yellow
    } else {
        Write-Host "$heuristicScore/100" -ForegroundColor Red
    }
    
    Write-Host ""
    
    if ($detections.Count -eq 0) {
        Write-Host "✅ VEREDICTO: " -NoNewline -ForegroundColor White
        Write-Host "SISTEMA LIMPIO" -ForegroundColor Green
        Write-Host "   No se detectaron evidencias de cheats o modificaciones sospechosas." -ForegroundColor Gray
    } else {
        $critical = ($detections | Where-Object { $_.Severity -eq "CRITICAL" }).Count
        $high = ($detections | Where-Object { $_.Severity -eq "HIGH" }).Count
        
        if ($critical -gt 0 -or $high -gt 5 -or $heuristicScore -gt 80) {
            Write-Host "🚨 VEREDICTO: " -NoNewline -ForegroundColor White
            Write-Host "POSITIVO - CHEATS DETECTADOS" -ForegroundColor Red
            Write-Host "   Se encontraron evidencias significativas de uso de cheats." -ForegroundColor Red
        } elseif ($high -gt 2 -or $heuristicScore -gt 50) {
            Write-Host "⚠️  VEREDICTO: " -NoNewline -ForegroundColor White
            Write-Host "SOSPECHOSO" -ForegroundColor Yellow
            Write-Host "   Se detectaron múltiples indicadores sospechosos." -ForegroundColor Yellow
        } else {
            Write-Host "⚡ VEREDICTO: " -NoNewline -ForegroundColor White
            Write-Host "PRECAUCIÓN" -ForegroundColor DarkYellow
            Write-Host "   Se detectaron algunos indicadores que requieren revisión." -ForegroundColor Gray
        }
        
        Write-Host ""
        Write-Host "📋 RESUMEN POR SEVERIDAD:" -ForegroundColor Cyan
        Write-Host "   🔴 Crítico: $critical" -ForegroundColor Red
        Write-Host "   🟠 Alto: $high" -ForegroundColor DarkRed
        Write-Host "   🟡 Medio: $(($detections | Where-Object { $_.Severity -eq 'MEDIUM' }).Count)" -ForegroundColor Yellow
        Write-Host "   🟢 Bajo: $(($detections | Where-Object { $_.Severity -eq 'LOW' }).Count)" -ForegroundColor DarkYellow
        
        if ($critical -gt 0) {
            Write-Host ""
            Write-Host "⚠️  DETECCIONES CRÍTICAS:" -ForegroundColor Red
            $detections | Where-Object { $_.Severity -eq "CRITICAL" } | 
                Select-Object -First 5 | 
                ForEach-Object {
                    Write-Host "   • $($_.Category): " -NoNewline -ForegroundColor Red
                    Write-Host $_.Detail -ForegroundColor White
                }
        }
    }
    
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "📁 Reporte guardado en:" -ForegroundColor Cyan
    Write-Host "   $outputDir" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    # Opciones post-escaneo
    Write-Host "OPCIONES:" -ForegroundColor Yellow
    Write-Host "  [1] Abrir carpeta de resultados" -ForegroundColor Gray
    Write-Host "  [2] Abrir reporte HTML" -ForegroundColor Gray
    Write-Host "  [3] Ver log completo" -ForegroundColor Gray
    Write-Host "  [4] Salir" -ForegroundColor Gray
    Write-Host ""
    
    do {
        $option = Read-Host "Seleccione una opción (1-4)"
        
        switch ($option) {
            "1" { 
                Start-Process explorer.exe $outputDir
                Write-Host "✅ Carpeta abierta" -ForegroundColor Green
            }
            "2" { 
                Start-Process "$outputDir\NEXUS_Report.html"
                Write-Host "✅ Reporte HTML abierto" -ForegroundColor Green
            }
            "3" { 
                Start-Process notepad.exe "$outputDir\NEXUS_MASTER_LOG.txt"
                Write-Host "✅ Log abierto" -ForegroundColor Green
            }
            "4" {
                Write-Host ""
                Write-Host "Gracias por usar NEXUS AntiCheat v5.0" -ForegroundColor Cyan
                Write-Host "Presione cualquier tecla para salir..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                return
            }
            default {
                Write-Host "❌ Opción inválida" -ForegroundColor Red
            }
        }
        
        Write-Host ""
    } while ($true)
}

# ============================================
# EJECUCIÓN PRINCIPAL
# ============================================

try {
    Start-NexusAntiCheat
} catch {
    Write-Host ""
    Write-Host "❌ ERROR CRÍTICO:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    Write-Log "ERROR CRÍTICO: $($_.Exception.Message)" "Red" "ERROR"
    Write-Host "Presione cualquier tecla para salir..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ============================================
# FIN DEL SCRIPT
# ============================================
