# 🛡️ Password Spray por Kerberos en Active Directory

---

## 📝 ¿Qué es un password spray por Kerberos?

| Concepto      | Descripción                                                                                    |
|---------------|------------------------------------------------------------------------------------------------|
| **Definición**| Ataque donde un adversario prueba una sola contraseña común contra muchos usuarios de dominio, usando Kerberos como vector. Evita bloqueos por umbral y maximiza el sigilo. |
| **Requisito** | Acceso en red al puerto Kerberos (88) del controlador de dominio. Los usuarios pueden ser enumerados previamente o deducidos.|

---

## 🛠️ ¿Cómo funciona el ataque?

| Fase               | Acción                                                                                                   |
|--------------------|----------------------------------------------------------------------------------------------------------|
| **Enumeración**    | El atacante recopila usuarios válidos del dominio (LDAP, scripts, dumps, OSINT, etc).                    |
| **Automatización** | Herramientas como Rubeus, CrackMapExec, Kerbrute, Impacket, Python o scripts caseros lanzan miles de tickets TGT (AS-REQ). |
| **Validación**     | El DC responde: si el usuario existe y la contraseña es correcta, éxito; si no, error específico (4768/4771). |
| **Evasión**        | El atacante alterna usuarios y contraseñas para evitar bloqueos y detección por volumen.                  |

---

## 💻 Ejemplo práctico

```bash
kerbrute passwordspray -d essos.local --users usuarios.txt --passwords passwords.txt --no-save-cred 192.168.1.5
```
o con CrackMapExec:
```bash
cme kerberos 192.168.1.5 -u usuarios.txt -p passwords.txt --no-bruteforce-lockout
```

---

## 📊 Detección en logs y SIEM

| Campo clave                   | Descripción                                                                                      |
|-------------------------------|-------------------------------------------------------------------------------------------------|
| **EventCode = 4768**          | Solicitud de TGT (AS-REQ). Fallos y éxitos de autenticación Kerberos.                           |
| **EventCode = 4771**          | Fallos de autenticación Kerberos (preautenticación fallida, contraseña incorrecta, usuario no existe...). |
| **Client_Address/IP**         | IP origen del intento de autenticación.                                                         |
| **Account_Name/User**         | Usuario objetivo del intento de login.                                                          |
| **Failure_Code/Result_Code**  | Motivo del fallo (usuario no existe: 0x6, password incorrecta: 0x18, cuenta bloqueada: 0x12...).|

### Ejemplo de eventos relevantes

```
EventCode=4768
Client Address: 192.168.57.151
Account Name: daenerys.targaryen
Result Code: 0x6

EventCode=4771
Client Address: 192.168.57.151
Account Name: drogon
Failure Code: 0x18
```

---

## 🔎 Queries Splunk para hunting

### 1. Detección de password spray (muchos 4768/4771 por IP/usuario en poco tiempo)

```splunk
index=dc_logs (EventCode=4768 OR EventCode=4771)
| eval tipo=case(EventCode==4768,"solicitud_kerberos", EventCode==4771,"fallo_kerberos")
| eval src_ip=coalesce(Client_Address, ip)
| eval usuario=coalesce(Account_Name, user)
| bucket _time span=3m
| stats count as total_intentos, values(tipo) as tipos, values(Failure_Code) as fallos by _time, src_ip, usuario
| where total_intentos > 10
| sort -_time
```
> _Alerta si en 3 minutos hay más de 10 intentos Kerberos para el mismo usuario/IP._

### 2. Cuentas inexistentes o patrones de diccionario

```splunk
index=dc_logs (EventCode=4768 OR EventCode=4771)
| rex field=Message "Result Code:\s+(?<ResultCode>0x[0-9A-Fa-f]+)"
| eval user_no_existe=if(ResultCode=="0x6",1,0)
| where user_no_existe=1 OR match(Account_Name, "\.(txt|csv|docx|log|ini)$") OR match(Account_Name, "^[0-9]+$") OR match(Account_Name, "^[\.\-_]")
| stats count by _time, src_ip, Account_Name
```
> _Ideal para detectar password spray tosco: si ves nombres tipo .txt/.csv o muchas cuentas inexistentes, tienes ataque automatizado claro._

---

## ⚡️ Alertas recomendadas

| Alerta                                  | Descripción                                                                                 |
|------------------------------------------|--------------------------------------------------------------------------------------------|
| **Alerta 1**                            | Más de 10 eventos 4768/4771 por la misma IP/usuario en 3 minutos.                          |
| **Alerta 2**                            | Secuencia de cuentas inexistentes o nombres de diccionario en intentos Kerberos.           |


---

## 🛡️ Detección con Windows Defender for Endpoint

### Reglas de detección personalizadas

```kql
// Kerberos Brute Force - Detección de intentos masivos
DeviceLogonEvents
| where ActionType == "LogonFailed"
| where Protocol == "Kerberos"
| summarize FailedAttempts = count() by RemoteIP, AccountName, bin(Timestamp, 3m)
| where FailedAttempts > 10
| order by FailedAttempts desc
```

```kql
// Detección de herramientas de fuerza bruta Kerberos
DeviceProcessEvents
| where ProcessCommandLine has_any ("kerbrute", "rubeus", "kerberoast", "krb5-user")
| where ProcessCommandLine has_any ("bruteforce", "passwordspray", "userenum")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

```kql
// Detección de patrones de spray de contraseñas
DeviceLogonEvents
| where ActionType == "LogonFailed" and Protocol == "Kerberos"
| summarize UniqueAccounts = dcount(AccountName), FailedAttempts = count() by RemoteIP, bin(Timestamp, 5m)
| where UniqueAccounts > 5 and FailedAttempts > 20
| order by UniqueAccounts desc
```

### Alertas recomendadas

| Regla | Descripción | Severidad |
|-------|-------------|-----------|
| **Kerberos Brute Force** | Más de 10 fallos Kerberos desde una IP en 3 minutos | Alta |
| **Password Spray** | Intentos contra múltiples cuentas desde una IP | Alta |
| **Kerberos Tools** | Detección de herramientas de fuerza bruta | Media |

---

## 🦅 Detección con CrowdStrike Falcon

### Hunting queries (Event Search)

```sql
-- Detección de fuerza bruta Kerberos
event_platform=Win event_simpleName=UserLogonFailed
| search FailureReason=*Kerberos* OR LogonType=3
| bin _time span=3m
| stats count as failed_attempts, dc(UserName) as unique_users by ComputerName, SourceIP, _time
| where failed_attempts > 15 OR unique_users > 5
| sort - failed_attempts
```

```sql
-- Detección de herramientas de fuerza bruta
event_platform=Win event_simpleName=ProcessRollup2 
| search (FileName=*kerbrute* OR CommandLine=*kerbrute* OR CommandLine=*passwordspray*)
| table _time, ComputerName, UserName, FileName, CommandLine, SHA256HashData
| sort - _time
```

```sql
-- Detección de patrones de enumeración de usuarios
event_platform=Win event_simpleName=AuthActivityAuditLog
| search LogonType=* FailureReason=*user*
| bin _time span=2m
| stats count as enum_attempts by ComputerName, SourceIP, _time
| where enum_attempts > 20
| sort - enum_attempts
```

### Custom IOAs (Indicators of Attack)

```sql
-- IOA para detectar spray de contraseñas distribuido
event_platform=Win event_simpleName=UserLogonFailed
| search FailureReason=*password* OR FailureReason=*credential*
| bin _time span=5m
| stats dc(ComputerName) as unique_targets, count as total_attempts by SourceIP, _time
| where unique_targets > 3 AND total_attempts > 30
```

---

## 🔍 Queries KQL para Microsoft Sentinel

### Detección de Kerberos Brute Force

```kql
// Query principal para detectar fuerza bruta Kerberos
SecurityEvent
| where EventID in (4768, 4771, 4625)
| where FailureReason has "Kerberos" or AuthenticationPackageName == "Kerberos"
| summarize FailedAttempts = count(), UniqueAccounts = dcount(TargetUserName) by IpAddress, bin(TimeGenerated, 3m)
| where FailedAttempts > 15 or UniqueAccounts > 5
| order by FailedAttempts desc
```

```kql
// Correlación con herramientas de ataque
DeviceProcessEvents
| where ProcessCommandLine contains "kerbrute" or ProcessCommandLine contains "passwordspray"
| join kind=inner (
    SecurityEvent
    | where EventID in (4768, 4771) and FailureReason != ""
    | project TimeGenerated, Computer, TargetUserName, IpAddress
) on $left.DeviceName == $right.Computer
| project TimeGenerated, DeviceName, ProcessCommandLine, TargetUserName, IpAddress
```

### Hunting avanzado

```kql
// Detección de spray de contraseñas coordinado
SecurityEvent
| where EventID == 4625 and FailureReason has_any ("password", "credential")
| summarize FailedAttempts = count(), UniqueComputers = dcount(Computer), UniqueAccounts = dcount(TargetUserName) by IpAddress, bin(TimeGenerated, 10m)
| where FailedAttempts > 50 or (UniqueComputers > 3 and UniqueAccounts > 10)
| order by FailedAttempts desc
```

```kql
// Detección de enumeración de usuarios válidos
SecurityEvent
| where EventID == 4768 // TGT request
| where FailureReason == ""
| summarize SuccessfulRequests = count() by IpAddress, bin(TimeGenerated, 5m)
| join kind=inner (
    SecurityEvent
    | where EventID == 4771 // Pre-auth failed
    | summarize FailedPreAuth = count() by IpAddress, bin(TimeGenerated, 5m)
) on IpAddress, TimeGenerated
| where FailedPreAuth > 20 and SuccessfulRequests > 5
| project TimeGenerated, IpAddress, SuccessfulRequests, FailedPreAuth
```

---

## 🦾 Hardening y mitigación

| Medida                                   | Descripción                                                                                 |
|-------------------------------------------|--------------------------------------------------------------------------------------------|
| **Bloqueo por umbral**                    | Si una IP/usuario supera X intentos fallidos en Y minutos, bloquea temporalmente.          |
| **Deshabilitar cuentas trampa/legacy**    | Elimina cuentas antiguas o crea honeypots para detectar actividad anómala.                 |
| **Obligar contraseñas robustas**          | Minimiza el riesgo de éxito en password spray.                                             |
| **Normalización de logs**                 | Unifica formato de usuario/IP para no perder correlaciones.                                |
| **Segmentación de red**                   | Restringe acceso Kerberos solo a lo necesario.                                             |
| **Alertas y dashboards en SIEM**          | Implementa alertas específicas y paneles de intentos Kerberos sospechosos.                 |
| **Lista negra temporal**                  | IPs que repitan patrón de ataque, a watchlist para seguimiento proactivo.                  |

---

## 🧑‍💻 ¿Cómo probar password spray Kerberos en laboratorio?

```bash
kerbrute passwordspray -d essos.local --users usuarios.txt --passwords passwords.txt 192.168.1.5
```
o con CrackMapExec:
```bash
cme kerberos 192.168.1.5 -u usuarios.txt -p passwords.txt
```

---

## 🔧 Parches y actualizaciones

| Parche/Update | Descripción                                                                                  |
|---------------|----------------------------------------------------------------------------------------------|
| **KB5025238** | Windows 11 22H2 - Mejoras en protección contra ataques de fuerza bruta Kerberos.           |
| **KB5025221** | Windows 10 22H2 - Fortalecimiento de políticas de bloqueo de cuenta y auditoría.           |
| **KB5022906** | Windows Server 2022 - Mejoras en detección de patrones de autenticación anómalos.          |
| **KB5022845** | Windows Server 2019 - Correcciones en manejo de políticas de contraseñas y bloqueos.       |
| **KB4580390** | Windows Server 2016 - Parches para mejor logging de intentos de autenticación fallidos.    |
| **RSAT Updates** | Herramientas actualizadas para gestión de políticas de cuenta y auditoría.          |

### Configuraciones de registro recomendadas

```powershell
# Configurar políticas de bloqueo de cuenta robustas
Set-ADDefaultDomainPasswordPolicy -LockoutDuration "00:30:00" -LockoutObservationWindow "00:30:00" -LockoutThreshold 3

# Habilitar auditoría detallada de autenticación
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Configurar logging extendido para eventos 4625
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "AuditBaseObjects" -Value 1
```

### Configuraciones de GPO críticas

```powershell
# Política de contraseñas robusta
Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 12 -PasswordHistoryCount 12 -MaxPasswordAge "90.00:00:00"

# Configurar Smart Card authentication donde sea posible
Set-ADUser -Identity "usuario_critico" -SmartcardLogonRequired $true
```

### Actualizaciones críticas de seguridad

- **CVE-2022-37958**: Vulnerabilidad en validación de autenticación Kerberos (noviembre 2022)
- **CVE-2021-42287**: sAMAccountName spoofing que puede facilitar bypass de bloqueos (KB5008102)
- **CVE-2020-1472**: Zerologon - bypass completo de autenticación (KB4556836)
- **CVE-2019-1384**: Vulnerabilidad en autenticación que permite bypass de políticas (KB4524244)

### Herramientas de monitorizacion mejoradas

```powershell
# Script para detectar patrones de brute force en tiempo real
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 100
$events | Group-Object Properties[5] | Where-Object Count -gt 5 | Select-Object Name, Count
```

---

## 📚 Referencias

- [Kerberos Password Spray Detection - SigmaHQ](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_kerberos_password_spray.yml)
- [Kerbrute](https://github.com/ropnop/kerbrute)
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
