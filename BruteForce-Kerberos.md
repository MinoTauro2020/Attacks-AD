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

## 🚨 Respuesta ante incidentes

### Procedimientos de respuesta inmediata

1. **Identificación del ataque Kerberos Brute Force:**
   - Confirmar patrones de eventos 4768/4771 masivos desde IPs específicas
   - Verificar intentos contra múltiples cuentas en ventanas de tiempo cortas
   - Correlacionar con herramientas de fuerza bruta detectadas (kerbrute, CME)

2. **Contención inmediata:**
   - Bloquear inmediatamente las IPs origen del ataque en firewalls y proxies
   - Implementar rate limiting temporal en el puerto 88 (Kerberos) para IPs sospechosas
   - Habilitar bloqueo automático de cuentas si no está activado

3. **Evaluación de impacto:**
   - Identificar si alguna cuenta fue comprometida exitosamente
   - Revisar si hay autenticaciones exitosas (4768 exitosos) tras intentos fallidos
   - Evaluar la lista de cuentas objetivo para determinar su criticidad

4. **Investigación forense:**
   - Analizar logs para identificar el vector de acceso inicial del atacante
   - Buscar herramientas de enumeración previas (LDAP, SMB, etc.)
   - Verificar si existen credenciales válidas obtenidas del ataque

5. **Recuperación y endurecimiento:**
   - Resetear contraseñas de cuentas que tuvieron intentos exitosos
   - Reforzar políticas de contraseñas y bloqueo de cuentas
   - Implementar monitoreo avanzado de eventos Kerberos

### Scripts de respuesta automatizada

```powershell
# Script de respuesta para Kerberos Brute Force
function Respond-KerberosBruteForce {
    param($AttackerIPs, $TargetedAccounts, $AffectedDCs)
    
    # Bloquear IPs atacantes en firewall
    foreach ($ip in $AttackerIPs) {
        New-NetFirewallRule -DisplayName "Block Kerberos BF $ip" -Direction Inbound -RemoteAddress $ip -Protocol TCP -LocalPort 88 -Action Block
        New-NetFirewallRule -DisplayName "Block Kerberos BF $ip UDP" -Direction Inbound -RemoteAddress $ip -Protocol UDP -LocalPort 88 -Action Block
        Write-EventLog -LogName Security -Source "KerberosBFResponse" -EventId 9008 -Message "Blocked IP $ip due to Kerberos brute force attack"
    }
    
    # Evaluar cuentas comprometidas potencialmente
    foreach ($account in $TargetedAccounts) {
        # Verificar si hubo autenticación exitosa tras fallos
        $successAfterFails = Get-WinEvent -FilterHashtable @{
            LogName='Security'
            ID=4768
            StartTime=(Get-Date).AddHours(-1)
        } | Where-Object {
            $_.Message -match "Account Name:\s+$account" -and 
            $_.Message -notmatch "Result Code:\s+0x"
        }
        
        if ($successAfterFails) {
            # Cambiar contraseña inmediatamente
            $newPassword = -join ((33..126) | Get-Random -Count 32 | % {[char]$_})
            Set-ADAccountPassword -Identity $account -NewPassword (ConvertTo-SecureString $newPassword -AsPlainText -Force) -Reset
            Write-EventLog -LogName Security -Source "KerberosBFResponse" -EventId 9009 -Message "Password reset for account $account after successful authentication during brute force"
            
            # Revocar sesiones activas
            Get-ADUser -Identity $account | Set-ADUser -Replace @{userAccountControl=([int](Get-ADUser -Identity $account -Properties userAccountControl).userAccountControl -bor 0x0002)}
            Start-Sleep -Seconds 5
            Get-ADUser -Identity $account | Set-ADUser -Replace @{userAccountControl=([int](Get-ADUser -Identity $account -Properties userAccountControl).userAccountControl -band -bnot 0x0002)}
        }
    }
    
    # Configurar monitoreo intensivo temporal
    $monitorScript = @"
# Monitor temporal para ataques Kerberos continuos
Register-WmiEvent -Query "SELECT * FROM Win32_NTLogEvent WHERE LogFile='Security' AND EventCode IN (4768,4771)" -Action {
    `$Event = `$Event.SourceEventArgs.NewEvent
    if (`$Event.Message -match "Client Address:\s+(\S+)") {
        `$clientIP = `$matches[1]
        if ('$($AttackerIPs -join "','" -replace "'","'''")' -contains `$clientIP) {
            Write-EventLog -LogName Application -Source "KerberosBFMonitor" -EventId 2002 -Message "Continued Kerberos attack attempt from blocked IP `$clientIP"
        }
    }
}
"@
    
    # Notificar al equipo de seguridad
    Send-MailMessage -To "security-team@company.com" -Subject "ALERT: Kerberos Brute Force Attack Detected" -Body "Kerberos brute force from IPs: $($AttackerIPs -join ', ') targeting accounts: $($TargetedAccounts -join ', '). IPs blocked and monitoring enabled."
}

# Script para fortalecer políticas anti-brute force
function Implement-AntiBruteForceDefenses {
    # Configurar políticas de bloqueo robustas
    Set-ADDefaultDomainPasswordPolicy -LockoutDuration "01:00:00" -LockoutObservationWindow "00:15:00" -LockoutThreshold 3
    
    # Implementar políticas de contraseñas fuertes
    Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14 -ComplexityEnabled $true -PasswordHistoryCount 24
    
    # Configurar auditoría extendida
    auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
    auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
    
    # Crear script de monitoreo automático
    $scheduledScript = @"
# Script de monitoreo programado cada 5 minutos
`$events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4771; StartTime=(Get-Date).AddMinutes(-5)} -ErrorAction SilentlyContinue
`$grouped = `$events | Group-Object {(`$_.Message | Select-String -Pattern 'Client Address:\s+(\S+)').Matches[0].Groups[1].Value}
`$attacks = `$grouped | Where-Object Count -gt 10
if (`$attacks) {
    foreach (`$attack in `$attacks) {
        Write-EventLog -LogName Application -Source "AutoKerbBFDetector" -EventId 3001 -Message "Potential Kerberos brute force: `$(`$attack.Count) attempts from `$(`$attack.Name) in last 5 minutes"
        # Opcional: bloqueo automático
        # New-NetFirewallRule -DisplayName "Auto-block `$(`$attack.Name)" -Direction Inbound -RemoteAddress `$attack.Name -Action Block
    }
}
"@
    
    # Programar task de monitoreo
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-WindowStyle Hidden -Command `"$scheduledScript`""
    $trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) -At (Get-Date) -RepetitionDuration (New-TimeSpan -Days 365)
    Register-ScheduledTask -TaskName "KerberosBruteForceMonitor" -Action $action -Trigger $trigger -RunLevel Highest
    
    Write-Host "Anti-brute force defenses implemented successfully" -ForegroundColor Green
}
```

### Checklist de respuesta a incidentes

- [ ] **Detección confirmada**: Validar eventos 4768/4771 masivos indicando brute force
- [ ] **Contención**: Bloquear IPs atacantes en firewall y sistemas de seguridad
- [ ] **Evaluación**: Identificar cuentas objetivo y verificar autenticaciones exitosas
- [ ] **Protección**: Cambiar contraseñas de cuentas potencialmente comprometidas
- [ ] **Monitoreo**: Implementar vigilancia intensiva de eventos Kerberos
- [ ] **Endurecimiento**: Reforzar políticas de bloqueo y contraseñas
- [ ] **Documentación**: Registrar IPs atacantes y patrones identificados
- [ ] **Seguimiento**: Monitorear durante 48 horas actividad relacionada

### Patrones de detección avanzada

```powershell
# Script para detectar patrones sofisticados de brute force
function Detect-AdvancedKerberosBruteForce {
    $timeWindow = (Get-Date).AddHours(-1)
    
    # 1. Detectar ataques distribuidos (múltiples IPs, mismas cuentas)
    $distributedAttacks = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4771; StartTime=$timeWindow} |
    ForEach-Object {
        $message = $_.Message
        $ip = if ($message -match 'Client Address:\s+(\S+)') { $matches[1] } else { 'Unknown' }
        $account = if ($message -match 'Account Name:\s+(\S+)') { $matches[1] } else { 'Unknown' }
        [PSCustomObject]@{IP=$ip; Account=$account; Time=$_.TimeCreated}
    } | Group-Object Account | Where-Object {
        ($_.Group | Group-Object IP).Count -gt 3 -and $_.Count -gt 20
    }
    
    # 2. Detectar spray lento (evadiendo umbrales temporales)
    $slowSpray = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4771; StartTime=$timeWindow} |
    ForEach-Object {
        $message = $_.Message
        $ip = if ($message -match 'Client Address:\s+(\S+)') { $matches[1] } else { 'Unknown' }
        $account = if ($message -match 'Account Name:\s+(\S+)') { $matches[1] } else { 'Unknown' }
        [PSCustomObject]@{IP=$ip; Account=$account; Time=$_.TimeCreated}
    } | Group-Object IP | Where-Object {
        ($_.Group | Group-Object Account).Count -gt 10 -and 
        ($_.Group | Group-Object {$_.Time.ToString("yyyy-MM-dd HH:mm")} | Measure-Object).Count -gt 30
    }
    
    # 3. Detectar técnicas de validación de usuarios
    $userEnum = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4768; StartTime=$timeWindow} |
    Where-Object { $_.Message -notmatch 'Result Code:' } |
    ForEach-Object {
        $message = $_.Message
        $ip = if ($message -match 'Client Address:\s+(\S+)') { $matches[1] } else { 'Unknown' }
        $account = if ($message -match 'Account Name:\s+(\S+)') { $matches[1] } else { 'Unknown' }
        [PSCustomObject]@{IP=$ip; Account=$account; Type='ValidUser'}
    } | Group-Object IP | Where-Object { $_.Count -gt 50 }
    
    # Reportar hallazgos
    if ($distributedAttacks) {
        Write-Warning "Distributed brute force detected against accounts: $($distributedAttacks.Name -join ', ')"
    }
    if ($slowSpray) {
        Write-Warning "Slow password spray detected from IPs: $($slowSpray.Name -join ', ')"
    }
    if ($userEnum) {
        Write-Warning "User enumeration detected from IPs: $($userEnum.Name -join ', ')"
    }
    
    return @{
        DistributedAttacks = $distributedAttacks
        SlowSpray = $slowSpray
        UserEnumeration = $userEnum
    }
}
```

---

## 📚 Referencias

- [Kerberos Password Spray Detection - SigmaHQ](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_kerberos_password_spray.yml)
- [Kerbrute](https://github.com/ropnop/kerbrute)
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
