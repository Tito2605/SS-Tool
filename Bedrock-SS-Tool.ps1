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
$totalChecks = 20
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