# 🛑 Enumeración NTP en Active Directory

---

## 📝 ¿Qué es la enumeración NTP?

| Concepto      | Descripción                                                                                                      |
|---------------|-----------------------------------------------------------------------------------------------------------------|
| **Definición**| Técnica de reconocimiento que permite a un atacante obtener información sobre servidores NTP, configuraciones de tiempo y posibles vulnerabilidades en la sincronización temporal del dominio. |
| **Requisito** | Acceso de red al puerto 123 (NTP) y capacidad de enviar consultas UDP al servidor objetivo. |

---

## 🛠️ ¿Cómo funciona el ataque?

| Fase                | Acción                                                                                                 |
|---------------------|--------------------------------------------------------------------------------------------------------|
| **Descubrimiento**  | El atacante identifica servidores NTP activos en la red mediante escaneo del puerto 123.              |
| **Consulta básica** | Utiliza ntpq para obtener información del estado del servidor y peers configurados.                   |
| **Enumeración detallada** | Usa ntpdate y herramientas específicas para extraer versión, configuración y vulnerabilidades.  |
| **Reconocimiento**  | Mapea infraestructura de tiempo, identifica servidores críticos y posibles vectores de ataque.       |

---

## 💻 Ejemplo práctico

### ntpq - Consulta de estado del servidor NTP
```bash
# Consultar estado básico del servidor
ntpq -p 192.168.1.10

# Consultar información detallada del sistema
ntpq -c "rv" 192.168.1.10

# Listar asociaciones (peers) del servidor
ntpq -c "as" 192.168.1.10

# Consultar variables del sistema
ntpq -c "readlist" 192.168.1.10

# Obtener información de configuración
ntpq -c "mrulist" 192.168.1.10
```

### ntpdate - Sincronización y diagnóstico
```bash
# Consultar servidor sin sincronizar (modo debug)
ntpdate -q 192.168.1.10

# Consultar con información detallada
ntpdate -d 192.168.1.10

# Probar múltiples servidores
ntpdate -q 192.168.1.10 192.168.1.11 192.168.1.12

# Consultar con timeout personalizado
ntpdate -t 10 -q 192.168.1.10
```

### Consultas avanzadas con ntpq
```bash
# Consultar estadísticas del servidor
ntpq -c "iostats" 192.168.1.10

# Verificar configuración de restricciones
ntpq -c "reslist" 192.168.1.10

# Consultar información de versión
ntpq -c "version" 192.168.1.10

# Listar clientes recientes
ntpq -c "mrulist" 192.168.1.10

# Consultar offset y jitter
ntpq -c "pe" 192.168.1.10
```

---

## 📊 Detección en logs y SIEM

| Campo clave                   | Descripción                                                                                      |
|-------------------------------|-------------------------------------------------------------------------------------------------|
| **Source Port**               | Puerto origen de la consulta NTP (aleatorio).                                                   |
| **Destination Port**          | Puerto 123 (NTP).                                                                               |
| **Source IP**                 | IP origen de la consulta NTP.                                                                   |
| **Query Type**                | Tipo de consulta NTP (status, peers, version, etc.).                                           |
| **Query Count**               | Número de consultas desde la misma fuente.                                                      |

### Ejemplo de eventos relevantes

```
Source IP: 192.168.57.151
Destination Port: 123
Protocol: UDP
Query Type: ntpq status request

Source IP: 192.168.57.151
Destination Port: 123
NTP Mode: Client request
Stratum: Query for stratum information
```

---

## 🔎 Queries Splunk para hunting

### 1. Detección de consultas masivas NTP

```splunk
index=network_logs dest_port=123 protocol=UDP
| bucket _time span=10m
| stats count as total_consultas by src_ip, _time
| where total_consultas > 20
| eval severity="MEDIUM", technique="NTP Enumeration"
| table _time, src_ip, total_consultas, severity
```

### 2. Detección de escaneo de servidores NTP

```splunk
index=network_logs dest_port=123 protocol=UDP
| bucket _time span=5m
| stats count as consultas, dc(dest_ip) as servidores_unicos by src_ip, _time
| where servidores_unicos > 10 OR consultas > 50
| eval severity="HIGH", technique="NTP Server Scanning"
| table _time, src_ip, consultas, servidores_unicos, severity
```

### 3. Correlación con herramientas de enumeración NTP

```splunk
index=endpoint_logs (process_name="ntpq*" OR process_name="ntpdate*" OR process_name="ntp*")
| rex field=command_line "(?<target_ip>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)"
| join src_ip [
    search index=network_logs dest_port=123 
    | eval src_ip=source_ip
    | table _time, src_ip, dest_ip, dest_port
]
| table _time, src_ip, process_name, command_line, target_ip, dest_ip
```

### 4. Detección de consultas NTP desde redes externas

```splunk
index=network_logs dest_port=123 protocol=UDP
| search NOT (src_ip="10.*" OR src_ip="192.168.*" OR src_ip="172.16.*" OR src_ip="172.17.*" OR src_ip="172.18.*" OR src_ip="172.19.*" OR src_ip="172.20.*" OR src_ip="172.21.*" OR src_ip="172.22.*" OR src_ip="172.23.*" OR src_ip="172.24.*" OR src_ip="172.25.*" OR src_ip="172.26.*" OR src_ip="172.27.*" OR src_ip="172.28.*" OR src_ip="172.29.*" OR src_ip="172.30.*" OR src_ip="172.31.*")
| stats count by src_ip, dest_ip, _time
| eval severity="HIGH", technique="External NTP Enumeration"
| table _time, src_ip, dest_ip, count, severity
```

---

## ⚡️ Alertas recomendadas

| Alerta                                  | Descripción                                                                                 |
|------------------------------------------|---------------------------------------------------------------------------------------------|
| **Alerta 1**                            | Más de 20 consultas NTP desde la misma IP en 10 minutos.                                   |
| **Alerta 2**                            | Escaneo de múltiples servidores NTP (>10 IPs únicas) desde la misma fuente.                |
| **Alerta 3**                            | Consultas NTP desde redes externas no autorizadas.                                          |

---

## 🛡️ Detección con Windows Defender for Endpoint

### Reglas de detección personalizadas

```kql
// NTP Enumeration - Múltiples consultas desde misma fuente
DeviceNetworkEvents
| where RemotePort == 123
| where ActionType == "ConnectionAttempt"
| summarize QueryCount = count(), UniqueTargets = dcount(RemoteIP) by InitiatingProcessAccountName, bin(Timestamp, 10m)
| where QueryCount > 20 or UniqueTargets > 10
| order by QueryCount desc
```

```kql
// Detección de herramientas de enumeración NTP
DeviceProcessEvents
| where ProcessCommandLine has_any ("ntpq", "ntpdate", "ntpdc") 
| where ProcessCommandLine has_any ("-p", "-c", "-q", "readlist", "peers")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

```kql
// Detección de consultas NTP anómalas
DeviceNetworkEvents
| where RemotePort == 123 and Protocol == "Udp"
| summarize NTPConnections = count() by DeviceId, RemoteIP, AccountName, bin(Timestamp, 5m)
| where NTPConnections > 15
| order by NTPConnections desc
```

### Alertas recomendadas

| Regla | Descripción | Severidad |
|-------|-------------|-----------|
| **NTP Query Spike** | Más de 20 consultas NTP o 10 objetivos únicos en 10 minutos | Media |
| **NTP Enum Tools** | Detección de herramientas de enumeración NTP | Media |
| **Abnormal NTP Activity** | Múltiples conexiones NTP fuera de patrón normal | Baja |

---

## 🦅 Detección con CrowdStrike Falcon

### Hunting queries (Event Search)

```sql
-- Detección de enumeración NTP masiva
event_platform=Win event_simpleName=NetworkConnectIP4
| search RemotePort=123
| bin _time span=10m
| stats count as ntp_queries, dc(RemoteAddressIP4) as unique_targets by ComputerName, UserName, _time
| where ntp_queries > 30 OR unique_targets > 15
| sort - ntp_queries
```

```sql
-- Detección de herramientas de enumeración NTP
event_platform=Win event_simpleName=ProcessRollup2 
| search (CommandLine=*ntpq* OR CommandLine=*ntpdate* OR CommandLine=*ntpdc*)
| table _time, ComputerName, UserName, FileName, CommandLine, SHA256HashData
| sort - _time
```

```sql
-- Detección de consultas NTP desde procesos inusuales
event_platform=Win event_simpleName=NetworkConnectIP4
| search RemotePort=123
| join ProcessId [
    search event_simpleName=ProcessRollup2
    | table ProcessId, FileName, CommandLine
]
| where NOT FileName IN ("w32tm.exe", "ntpdate.exe", "chronyd.exe")
| stats count by ComputerName, FileName, CommandLine, RemoteAddressIP4
| sort - count
```

### Custom IOAs (Indicators of Attack)

```sql
-- IOA para detectar escaneo masivo de servidores NTP
event_platform=Win event_simpleName=NetworkConnectIP4
| search RemotePort=123
| bin _time span=15m
| stats dc(RemoteAddressIP4) as target_count, count as connection_count by ComputerName, UserName, _time
| where target_count > 20 OR connection_count > 100
```

---

## 🔍 Queries KQL para Microsoft Sentinel

### Detección de NTP Enumeration

```kql
// Query principal para detectar enumeración NTP
DeviceNetworkEvents
| where RemotePort == 123
| summarize ConnectionCount = count(), UniqueTargets = dcount(RemoteIP) by DeviceId, DeviceName, InitiatingProcessAccountName, bin(TimeGenerated, 10m)
| where ConnectionCount > 15 or UniqueTargets > 8
| order by ConnectionCount desc
```

```kql
// Correlación con herramientas de enumeración
DeviceProcessEvents
| where ProcessCommandLine contains "ntpq" or ProcessCommandLine contains "ntpdate" or ProcessCommandLine contains "ntpdc"
| join kind=inner (
    DeviceNetworkEvents
    | where RemotePort == 123
    | project TimeGenerated, DeviceId, RemoteIP, LocalPort
) on DeviceId
| project TimeGenerated, DeviceName, ProcessCommandLine, RemoteIP, LocalPort
```

### Hunting avanzado

```kql
// Detección de enumeración NTP desde redes externas
DeviceNetworkEvents
| where RemotePort == 123
| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168." and RemoteIP !startswith "172."
| summarize ExternalNTPQueries = count() by DeviceId, DeviceName, RemoteIP, bin(TimeGenerated, 30m)
| where ExternalNTPQueries > 5
| order by ExternalNTPQueries desc
```

```kql
// Detección de patrones anómalos en consultas NTP
DeviceNetworkEvents
| where RemotePort == 123
| summarize QueryCount = count(), MinTime = min(TimeGenerated), MaxTime = max(TimeGenerated) by DeviceId, RemoteIP
| extend Duration = datetime_diff('minute', MaxTime, MinTime)
| where QueryCount > 10 and Duration < 5  // Muchas consultas en poco tiempo
| order by QueryCount desc
```

---

## 🦾 Hardening y mitigación

| Medida                                   | Descripción                                                                                 |
|-------------------------------------------|---------------------------------------------------------------------------------------------|
| **Configurar restricciones NTP**         | Limita acceso a consultas NTP solo desde redes y hosts autorizados.                        |
| **Deshabilitar comandos de consulta**    | Bloquea comandos ntpq de información sensible para usuarios no autorizados.                |
| **Configurar rate limiting**             | Limita el número de consultas NTP por IP/cliente en ventanas de tiempo.                    |
| **Monitorización de consultas**          | Implementa logging detallado de consultas NTP y patrones anómalos.                         |
| **Segmentación de red**                  | Restringe acceso NTP solo a redes de gestión y administración.                             |
| **Autenticación NTP**                    | Implementa autenticación simétrica para consultas NTP críticas.                            |
| **Configuración segura de tiempo**       | Usa fuentes de tiempo confiables y redundantes con validación.                             |
| **Firewall específico**                  | Configura reglas de firewall específicas para tráfico NTP.                                 |

---

## 🔧 Parches y actualizaciones

| Parche/Update | Descripción                                                                                  |
|---------------|----------------------------------------------------------------------------------------------|
| **KB5025238** | Windows 11/10 - Mejoras en servicio de tiempo de Windows y protección contra enumeración.   |
| **KB5022906** | Windows Server 2022 - Fortalecimiento del servicio W32Time y auditoría mejorada.            |
| **KB5022845** | Windows Server 2019 - Correcciones en configuraciones NTP por defecto y rate limiting.      |
| **KB4580390** | Windows Server 2016 - Parches para vulnerabilidades en sincronización de tiempo.            |
| **KB5003173** | Patch crítico para vulnerabilidades NTP amplification (CVE-2021-31166).                     |
| **W32Time Updates** | Actualizaciones específicas del servicio de tiempo de Windows.                         |

### Configuraciones de registro críticas

```powershell
# Configurar restricciones de acceso NTP
w32tm /config /manualpeerlist:"time.windows.com,time.nist.gov" /syncfromflags:manual

# Configurar W32Time para mayor seguridad
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Name "AnnounceFlags" -Value 5
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer" -Name "Enabled" -Value 0

# Habilitar auditoría de eventos de tiempo
auditpol /set /subcategory:"Time Change" /success:enable /failure:enable

# Configurar logging detallado de W32Time
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Name "EventLogFlags" -Value 3

# Restringir acceso a comandos NTP
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name "NtpServerDenyClients" -Value 1 -PropertyType DWord
```

### Configuraciones de firewall para NTP

```powershell
# Configurar firewall restrictivo para NTP
New-NetFirewallRule -DisplayName "Block External NTP Queries" -Direction Inbound -Protocol UDP -LocalPort 123 -RemoteAddress "Internet" -Action Block
New-NetFirewallRule -DisplayName "Allow Internal NTP" -Direction Inbound -Protocol UDP -LocalPort 123 -RemoteAddress "LocalSubnet" -Action Allow

# Permitir solo servidores NTP autorizados
New-NetFirewallRule -DisplayName "Allow Authorized NTP Servers" -Direction Outbound -Protocol UDP -RemotePort 123 -RemoteAddress "time.windows.com,time.nist.gov" -Action Allow
New-NetFirewallRule -DisplayName "Block Other NTP" -Direction Outbound -Protocol UDP -RemotePort 123 -Action Block
```

### Scripts de validación y detección

```powershell
# Verificar configuraciones NTP seguras
function Test-NTPSecurity {
    # Verificar configuración de W32Time
    $w32timeConfig = w32tm /query /configuration
    Write-Host "=== Configuración W32Time ===" -ForegroundColor Cyan
    Write-Host $w32timeConfig
    
    # Verificar estado del servicio
    $w32timeStatus = Get-Service W32Time
    if ($w32timeStatus.Status -eq "Running") {
        Write-Host "✓ Servicio W32Time ejecutándose" -ForegroundColor Green
    } else {
        Write-Host "✗ Servicio W32Time NO ejecutándose" -ForegroundColor Red
    }
    
    # Verificar fuentes de tiempo configuradas
    $timeSources = w32tm /query /peers
    Write-Host "`n=== Fuentes de Tiempo ===" -ForegroundColor Cyan
    Write-Host $timeSources
    
    # Verificar configuración de servidor NTP
    $ntpServer = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer" -Name "Enabled" -ErrorAction SilentlyContinue
    if ($ntpServer.Enabled -eq 0) {
        Write-Host "✓ Servidor NTP deshabilitado (más seguro)" -ForegroundColor Green
    } else {
        Write-Host "⚠ Servidor NTP habilitado - verificar si es necesario" -ForegroundColor Yellow
    }
    
    # Verificar auditoría de tiempo
    $auditPolicy = auditpol /get /subcategory:"Time Change"
    if ($auditPolicy -like "*Success*") {
        Write-Host "✓ Auditoría de cambios de tiempo habilitada" -ForegroundColor Green
    } else {
        Write-Host "✗ Auditoría de cambios de tiempo DESHABILITADA" -ForegroundColor Red
    }
}

# Detectar consultas NTP sospechosas
function Monitor-NTPQueries {
    # Monitorear conexiones UDP puerto 123
    $ntpConnections = Get-NetUDPEndpoint | Where-Object {$_.LocalPort -eq 123}
    if ($ntpConnections.Count -gt 0) {
        Write-Host "Conexiones NTP activas:" -ForegroundColor Yellow
        $ntpConnections | ForEach-Object {
            Write-Host "  Local: $($_.LocalAddress):$($_.LocalPort)" -ForegroundColor Cyan
        }
    }
    
    # Revisar logs de W32Time
    $recentEvents = Get-WinEvent -LogName System -MaxEvents 50 | 
                   Where-Object {$_.ProviderName -eq "Microsoft-Windows-Time-Service"}
    
    if ($recentEvents.Count -gt 0) {
        Write-Host "`nEventos recientes de W32Time:" -ForegroundColor Yellow
        $recentEvents | Select-Object TimeCreated, Id, LevelDisplayName, Message | 
                       Format-Table -Wrap
    }
}

# Auditar configuración de tiempo
function Audit-TimeConfiguration {
    Write-Host "=== Auditoría de Configuración de Tiempo ===" -ForegroundColor Cyan
    
    # Verificar sincronización actual
    $timeInfo = w32tm /query /status
    Write-Host "`n=== Estado de Sincronización ===" -ForegroundColor Cyan
    Write-Host $timeInfo
    
    # Verificar peers configurados
    $peers = w32tm /query /peers /verbose
    Write-Host "`n=== Peers Detallados ===" -ForegroundColor Cyan
    Write-Host $peers
    
    # Verificar configuración del registro
    Write-Host "`n=== Configuración del Registro ===" -ForegroundColor Cyan
    $regKeys = @(
        "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config",
        "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters",
        "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer"
    )
    
    foreach ($key in $regKeys) {
        if (Test-Path $key) {
            Write-Host "Clave: $key" -ForegroundColor Yellow
            Get-ItemProperty -Path $key | Format-List
        }
    }
    
    # Verificar reglas de firewall NTP
    $ntpRules = Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*NTP*" -or $_.DisplayName -like "*123*"}
    if ($ntpRules.Count -gt 0) {
        Write-Host "`n=== Reglas de Firewall NTP ===" -ForegroundColor Cyan
        $ntpRules | Select-Object DisplayName, Direction, Action, Enabled | Format-Table
    }
}

# Ejecutar auditoría completa
Test-NTPSecurity
Monitor-NTPQueries
Audit-TimeConfiguration
```

### Actualizaciones críticas de seguridad

- **CVE-2021-31166**: Vulnerabilidad en HTTP.sys que afecta servicios de tiempo (KB5003173)
- **CVE-2016-9311**: NTP amplification attack vulnerability (múltiples patches)
- **CVE-2020-15778**: Vulnerabilidad en sincronización NTP (actualizaciones W32Time)
- **CVE-2019-8936**: NTP daemon vulnerability affecting Windows time sync

### Herramientas de monitorización avanzadas

```powershell
# Script para detectar enumeración NTP en tiempo real
function Monitor-NTPEnumeration {
    # Monitorear conexiones entrantes puerto 123
    $ntpConnections = Get-NetTCPConnection | Where-Object {$_.LocalPort -eq 123}
    $ntpConnections | Group-Object RemoteAddress | Where-Object Count -gt 10 |
    ForEach-Object {
        Write-Warning "IP con múltiples conexiones NTP: $($_.Name) - $($_.Count) conexiones"
    }
    
    # Monitorear procesos que usan herramientas NTP
    Get-Process | Where-Object {$_.ProcessName -match "(ntpq|ntpdate|ntpdc|w32tm)"} |
    ForEach-Object {
        Write-Warning "Herramienta de tiempo/NTP detectada: $($_.ProcessName) PID:$($_.Id)"
        try {
            $cmd = (Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine
            Write-Host "Comando: $cmd" -ForegroundColor Yellow
        } catch {
            Write-Host "No se pudo obtener línea de comandos" -ForegroundColor Red
        }
    }
    
    # Revisar eventos de sincronización anómalos
    $timeEvents = Get-WinEvent -LogName System -MaxEvents 100 |
                 Where-Object {$_.ProviderName -eq "Microsoft-Windows-Time-Service" -and $_.LevelDisplayName -eq "Warning"}
    
    if ($timeEvents.Count -gt 0) {
        Write-Warning "Eventos de advertencia en sincronización de tiempo:"
        $timeEvents | Select-Object TimeCreated, Id, Message | Format-Table -Wrap
    }
}

# Alert para consultas NTP anómalas
function Alert-NTPAnomalies {
    # Revisar eventos de red UDP puerto 123
    $recentTime = (Get-Date).AddMinutes(-15)
    
    # Simular detección de tráfico NTP (requiere logging de red habilitado)
    Write-Host "Monitoreando actividad NTP..." -ForegroundColor Cyan
    
    # Verificar cambios de configuración NTP
    $configChanges = Get-WinEvent -LogName Security -MaxEvents 100 |
                    Where-Object {$_.Id -eq 4719 -and $_.Message -like "*W32Time*"}
    
    if ($configChanges.Count -gt 0) {
        Write-Alert "Cambios de configuración W32Time detectados:"
        $configChanges | Select-Object TimeCreated, Message | Format-List
    }
    
    # Verificar intentos de modificación del servicio
    $serviceChanges = Get-WinEvent -LogName System -MaxEvents 100 |
                     Where-Object {$_.ProviderName -eq "Service Control Manager" -and $_.Message -like "*W32Time*"}
    
    if ($serviceChanges.Count -gt 0) {
        Write-Alert "Cambios en servicio W32Time:"
        $serviceChanges | Select-Object TimeCreated, Id, Message | Format-List
    }
}

# Ejecutar monitoreo
Monitor-NTPEnumeration
Alert-NTPAnomalies
```

---

## 🚨 Respuesta ante incidentes

### Procedimientos de respuesta inmediata

1. **Identificación del ataque de enumeración NTP:**
   - Confirmar consultas masivas NTP desde IP específica
   - Verificar uso de herramientas ntpq/ntpdate con parámetros de enumeración
   - Correlacionar con patrones de escaneo de múltiples servidores NTP

2. **Contención inmediata:**
   - Bloquear la IP origen del ataque en firewalls
   - Restringir temporalmente acceso NTP a redes no autorizadas
   - Deshabilitar comandos de consulta NTP si no son necesarios

3. **Análisis de impacto:**
   - Determinar qué información NTP fue enumerada
   - Evaluar la criticidad de los servidores NTP consultados
   - Verificar si hubo intentos de modificación de configuración temporal

4. **Investigación forense:**
   - Buscar herramientas de enumeración NTP en el endpoint origen
   - Analizar logs de W32Time para identificar patrones anómalos
   - Revisar configuraciones NTP para determinar exposición de información

5. **Recuperación y endurecimiento:**
   - Implementar configuraciones NTP más restrictivas
   - Configurar rate limiting para consultas NTP
   - Fortalecer monitoreo de sincronización temporal

### Scripts de respuesta automatizada

```powershell
# Script de respuesta para enumeración NTP
function Respond-NTPEnumerationAttack {
    param($AttackerIP, $QueriedServers, $AffectedSystems)
    
    # Bloquear IP atacante
    New-NetFirewallRule -DisplayName "Block NTP Enumeration IP" -Direction Inbound -RemoteAddress $AttackerIP -Action Block
    
    # Restringir servidor NTP si está habilitado
    $ntpServerEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer" -Name "Enabled"
    if ($ntpServerEnabled.Enabled -eq 1) {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer" -Name "Enabled" -Value 0
        Restart-Service W32Time
        Write-EventLog -LogName System -Source "NTPSecurity" -EventId 9007 -Message "NTP server disabled after enumeration attack from $AttackerIP"
    }
    
    # Auditar servidores consultados
    foreach ($server in $QueriedServers) {
        Write-EventLog -LogName System -Source "NTPSecurity" -EventId 9008 -Message "NTP server enumerated: $server by $AttackerIP"
        
        # Verificar si el servidor es crítico
        $criticalServers = @("time.windows.com", "pool.ntp.org", "time.nist.gov")
        if ($server -in $criticalServers) {
            Write-Warning "Critical NTP server enumerated: $server"
        }
    }
    
    # Configurar rate limiting básico vía firewall
    New-NetFirewallRule -DisplayName "NTP Rate Limit" -Direction Inbound -Protocol UDP -LocalPort 123 -DynamicTarget Any -Action Allow -Enabled True
    
    # Habilitar auditoría mejorada de tiempo
    auditpol /set /subcategory:"Time Change" /success:enable /failure:enable
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Name "EventLogFlags" -Value 3
    
    # Notificar al equipo de seguridad
    Send-MailMessage -To "security-team@company.com" -Subject "ALERT: NTP Enumeration Attack Detected" -Body "NTP enumeration from $AttackerIP targeting servers: $($QueriedServers -join ', '). NTP server access restricted and IP blocked."
}

# Script para auditar y remediar configuraciones NTP vulnerables
function Audit-NTPVulnerabilities {
    Write-Host "=== NTP Security Audit ===" -ForegroundColor Cyan
    
    # Verificar si el servidor NTP está habilitado
    Write-Host "`n=== Servidor NTP ===" -ForegroundColor Cyan
    $ntpServer = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer" -Name "Enabled" -ErrorAction SilentlyContinue
    if ($ntpServer.Enabled -eq 1) {
        Write-Host "⚠ Servidor NTP HABILITADO - revisar si es necesario" -ForegroundColor Yellow
        Write-Host "  Considerar: Deshabilitar si no se requiere servir tiempo a otros sistemas" -ForegroundColor Yellow
        
        # Verificar configuración de acceso
        $announceFlags = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Name "AnnounceFlags" -ErrorAction SilentlyContinue
        if ($announceFlags.AnnounceFlags -eq 5) {
            Write-Host "✓ AnnounceFlags configurado correctamente (5)" -ForegroundColor Green
        } else {
            Write-Host "✗ AnnounceFlags no optimizado (actual: $($announceFlags.AnnounceFlags))" -ForegroundColor Red
        }
    } else {
        Write-Host "✓ Servidor NTP deshabilitado" -ForegroundColor Green
    }
    
    # Verificar fuentes de tiempo
    Write-Host "`n=== Fuentes de Tiempo ===" -ForegroundColor Cyan
    $timeStatus = w32tm /query /status /verbose
    if ($timeStatus -like "*Source:*") {
        Write-Host "✓ Fuente de tiempo configurada" -ForegroundColor Green
        $timeStatus -split "`n" | Where-Object {$_ -like "*Source:*"} | ForEach-Object {
            Write-Host "  $_" -ForegroundColor Cyan
        }
    } else {
        Write-Host "✗ Fuente de tiempo NO configurada correctamente" -ForegroundColor Red
    }
    
    # Verificar configuración de peers
    $peers = w32tm /query /peers
    $peerCount = ($peers -split "`n" | Where-Object {$_ -like "*Peer:*"}).Count
    Write-Host "Peers configurados: $peerCount" -ForegroundColor Cyan
    
    # Verificar auditoría
    Write-Host "`n=== Auditoría ===" -ForegroundColor Cyan
    $auditPolicy = auditpol /get /subcategory:"Time Change"
    if ($auditPolicy -like "*Success*Enable*") {
        Write-Host "✓ Auditoría de cambios de tiempo habilitada" -ForegroundColor Green
    } else {
        Write-Host "✗ Auditoría de cambios de tiempo DESHABILITADA" -ForegroundColor Red
        Write-Host "  Ejecutar: auditpol /set /subcategory:`"Time Change`" /success:enable /failure:enable" -ForegroundColor Yellow
    }
    
    # Verificar logging de W32Time
    $eventLogFlags = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Name "EventLogFlags" -ErrorAction SilentlyContinue
    if ($eventLogFlags.EventLogFlags -gt 0) {
        Write-Host "✓ Logging W32Time habilitado (Nivel: $($eventLogFlags.EventLogFlags))" -ForegroundColor Green
    } else {
        Write-Host "✗ Logging W32Time DESHABILITADO" -ForegroundColor Red
        Write-Host "  Ejecutar: Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config' -Name 'EventLogFlags' -Value 3" -ForegroundColor Yellow
    }
    
    # Verificar reglas de firewall
    Write-Host "`n=== Firewall NTP ===" -ForegroundColor Cyan
    $ntpRules = Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*NTP*" -or ($_.LocalPort -contains 123)}
    if ($ntpRules.Count -gt 0) {
        Write-Host "Reglas de firewall NTP configuradas: $($ntpRules.Count)" -ForegroundColor Green
        $ntpRules | Select-Object DisplayName, Direction, Action, Enabled | Format-Table
    } else {
        Write-Host "⚠ No hay reglas específicas de firewall para NTP" -ForegroundColor Yellow
    }
    
    return @{
        NTPServerEnabled = ($ntpServer.Enabled -eq 1)
        TimeSourceConfigured = ($timeStatus -like "*Source:*")
        AuditingEnabled = ($auditPolicy -like "*Success*Enable*")
        LoggingEnabled = ($eventLogFlags.EventLogFlags -gt 0)
        PeerCount = $peerCount
        FirewallRules = $ntpRules.Count
    }
}
```

### Checklist de respuesta a incidentes

- [ ] **Detección confirmada**: Validar consultas NTP masivas o herramientas de enumeración
- [ ] **Contención**: Bloquear IP atacante y restringir acceso NTP no autorizado
- [ ] **Auditoría**: Revisar configuraciones de W32Time y servidores NTP
- [ ] **Hardening**: Deshabilitar servidor NTP si no es necesario y configurar rate limiting
- [ ] **Monitoreo**: Configurar alertas para futuras consultas NTP sospechosas
- [ ] **Documentación**: Registrar servidores consultados y medidas implementadas
- [ ] **Seguimiento**: Monitorear por 30 días cambios en configuración temporal
- [ ] **Política**: Actualizar políticas de sincronización de tiempo y acceso NTP

---

## 🧑‍💻 ¿Cómo probar enumeración NTP en laboratorio?

### Configuración de entorno de pruebas

```bash
# En el servidor NTP objetivo (solo para laboratorio):
# Habilitar servidor NTP en Windows
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer" -Name "Enabled" -Value 1
w32tm /config /announce:yes
Restart-Service W32Time

# Probar enumeración desde Kali Linux:
ntpq -p 192.168.1.10
ntpq -c "rv" 192.168.1.10
ntpdate -q 192.168.1.10
```

### Validación de detección

```powershell
# Verificar que la enumeración genera actividad detectable
Get-WinEvent -LogName System -MaxEvents 20 |
Where-Object {$_.ProviderName -eq "Microsoft-Windows-Time-Service" -and $_.TimeCreated -gt (Get-Date).AddMinutes(-10)} |
Select-Object TimeCreated, Id, LevelDisplayName, Message |
Format-Table -Wrap

# Monitorear conexiones NTP
Get-NetUDPEndpoint | Where-Object {$_.LocalPort -eq 123} |
Select-Object LocalAddress, LocalPort, CreationTime
```

---

## 📚 Referencias

- [ntpq Manual Page](https://linux.die.net/man/8/ntpq)
- [ntpdate Documentation](https://linux.die.net/man/8/ntpdate)  
- [Windows Time Service](https://docs.microsoft.com/en-us/windows-server/networking/windows-time-service/)
- [NTP Security Best Practices](https://www.ntp.org/ntpfaq/NTP-s-def.htm)
- [MITRE ATT&CK T1018 - Remote System Discovery](https://attack.mitre.org/techniques/T1018/)
- [CVE-2016-9311 - NTP Amplification](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-9311)