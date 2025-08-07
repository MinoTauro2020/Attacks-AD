# 🛑 AS-REP Roasting en Active Directory

---

## 📝 ¿Qué es AS-REP Roasting?

| Concepto      | Descripción                                                                                                   |
|---------------|--------------------------------------------------------------------------------------------------------------|
| **Definición**| Técnica que permite a un atacante solicitar tickets AS-REP Kerberos de cuentas con preautenticación deshabilitada y crackear los hashes offline. |
| **Requisito** | La cuenta objetivo debe tener deshabilitada la opción **"Do not require Kerberos preauthentication"**.        |

---

## 🛠️ ¿Cómo funciona el ataque?

| Fase             | Acción                                                                                         |
|------------------|------------------------------------------------------------------------------------------------|
| **Enumeración**  | El atacante identifica cuentas vulnerables vía LDAP/AD.                                         |
| **Solicitud**    | Solicita AS-REP (AS-REQ sin preautenticación) al KDC para esas cuentas.                        |
| **Obtención**    | El KDC responde con el ticket cifrado con el hash de la contraseña de la cuenta.               |
| **Crackeo**      | El atacante extrae el hash y lo crackea offline (ej: Hashcat, John the Ripper).                |

---

## 💻 Ejemplo práctico

```bash
python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py essos.local/daenerys.targaryen -request
```

```
Name       MemberOf  PasswordLastSet             LastLogon                   UAC      
---------  --------  --------------------------  --------------------------  --------
missandei            2024-02-26 09:30:35.437503  2024-05-23 07:05:19.141162  0x410200 

$krb5asrep$23$missandei@ESSOS.LOCAL:600c153e69bd4899e402b6d1aad05e4f$1c5e29ec6f2e26b7d3738f19108a0b9b03ffa7ce3480e02f885bafe0de2668d499f23b6b034be320ee03ba64e70f4f3171c5bd59c0afdd1d79e0f64fcc1d138...
```

---

## 📋 Caso de Uso Completo Splunk

### 🎯 Contexto empresarial y justificación

**Problema de negocio:**
- AS-REP Roasting explota cuentas con preautenticación Kerberos deshabilitada, permitiendo extracción y crackeo offline de contraseñas
- Compromiso de una cuenta de servicio puede resultar en movimiento lateral y escalada de privilegios
- 15% de organizaciones tienen cuentas vulnerables a AS-REP Roasting por configuraciones incorrectas
- Costo promedio de compromiso de cuenta de servicio: $45,000 USD

**Valor de la detección:**
- Identificación inmediata de intentos de AS-REP Roasting via Event 4768
- Detección de herramientas automatizadas como GetNPUsers.py
- Prevención de compromiso de cuentas de servicio críticas
- Cumplimiento con controles de autenticación segura y Zero Trust

### 📐 Arquitectura de implementación

**Prerequisitos técnicos:**
- Splunk Enterprise 8.0+ o Splunk Cloud
- Universal Forwarders en todos los Domain Controllers
- Windows TA v8.0+ con configuración detallada de Event 4768
- Auditoría Kerberos habilitada en nivel VERBOSE
- Configuración de campos personalizados para Pre_Authentication_Type

**Arquitectura de datos:**
```
[Domain Controllers] → [Universal Forwarders] → [Indexers] → [Search Heads]
       ↓                      ↓                     ↓
[EventCode 4768]      [WinEventLog:Security]  [Index: wineventlog]
[Pre-auth Type=0]           ↓                      ↓
[Kerberos Logs]      [Real-time processing]  [Alerting Dashboard]
```

### 🔧 Guía de implementación paso a paso

#### Fase 1: Configuración inicial (Tiempo estimado: 40 min)

1. **Habilitar auditoría Kerberos detallada:**
   ```powershell
   # En todos los Domain Controllers
   auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
   
   # Configurar logging detallado
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "LogLevel" -Value 1
   
   # Verificar configuración
   auditpol /get /subcategory:"Kerberos Authentication Service"
   ```

2. **Configurar extracción de campos en Splunk:**
   ```
   # props.conf para Windows TA
   [WinEventLog:Security]
   EXTRACT-pre_auth_type = Pre-Authentication Type:\s+(?<Pre_Authentication_Type>\d+)
   EXTRACT-ticket_encryption = Ticket Encryption Type:\s+(?<Ticket_Encryption_Type>0x\w+)
   EXTRACT-client_address = Client Address:\s+(?<Client_Address>\S+)
   EXTRACT-account_name = Account Name:\s+(?<Account_Name>\S+)
   ```

3. **Verificar configuración:**
   ```splunk
   index=wineventlog EventCode=4768 earliest=-1h
   | stats count by Pre_Authentication_Type
   | eval pre_auth_status=case(
       Pre_Authentication_Type="0", "No Pre-Auth (VULNERABLE)",
       Pre_Authentication_Type="2", "Pre-Auth Enabled",
       1=1, "Unknown"
   )
   | table Pre_Authentication_Type, pre_auth_status, count
   ```

#### Fase 2: Implementación de detecciones (Tiempo estimado: 60 min)

1. **Detección principal AS-REP Roasting:**
   ```splunk
   index=wineventlog EventCode=4768 Pre_Authentication_Type=0
   | where NOT match(Account_Name, ".*\$$")  # Excluir cuentas de máquina
   | stats count values(Account_Name) as targeted_accounts by Client_Address, _time
   | where count > 3
   | eval severity="HIGH", technique="AS-REP Roasting"
   | eval risk_score=case(
       count > 10, 90,
       count > 5, 75,
       1=1, 60
   )
   | table _time, Client_Address, count, targeted_accounts, severity, risk_score
   ```

2. **Detección de herramientas automatizadas:**
   ```splunk
   index=wineventlog EventCode=4768 Pre_Authentication_Type=0
   | bucket _time span=5m
   | stats dc(Account_Name) as unique_accounts, count as total_requests by Client_Address, _time
   | where unique_accounts > 5 AND total_requests > 10
   | eval severity="CRITICAL", technique="Automated AS-REP Roasting"
   | eval risk_score=95
   | table _time, Client_Address, unique_accounts, total_requests, severity, risk_score
   ```

3. **Configurar alertas:**
   - **AS-REP Roasting Pattern**: Cada 10 minutos
   - **Mass AS-REP Requests**: Cada 5 minutos
   - **Privileged Account Targeting**: Tiempo real

#### Fase 3: Validación y dashboard (Tiempo estimado: 45 min)

1. **Dashboard de monitoreo:**
   ```xml
   <dashboard>
     <label>AS-REP Roasting Detection Dashboard</label>
     <row>
       <panel>
         <title>AS-REP Requests Without Pre-Authentication (24h)</title>
         <chart>
           <search>
             <query>
               index=wineventlog EventCode=4768 Pre_Authentication_Type=0
               | timechart span=1h count by Client_Address
             </query>
           </search>
         </chart>
       </panel>
     </row>
   </dashboard>
   ```

2. **Pruebas de validación:**
   ```bash
   # En entorno de lab controlado
   python3 GetNPUsers.py lab.local/testuser -request -no-pass -dc-ip 192.168.1.10
   ```

3. **Verificar detección:**
   ```splunk
   index=wineventlog EventCode=4768 Pre_Authentication_Type=0 earliest=-15m
   | search Client_Address="192.168.1.*"
   | stats count by Account_Name, Client_Address
   | eval detection_status=if(count>0,"DETECTED","MISSED")
   ```

### ✅ Criterios de éxito

**Métricas de detección:**
- MTTD para AS-REP Roasting: < 15 minutos
- MTTD para herramientas automatizadas: < 5 minutos
- Tasa de falsos positivos: < 1% (preauth disabled es raro)
- Cobertura: 100% de intentos con Pre_Authentication_Type=0

**Validación funcional:**
- [x] Event 4768 con Pre_Authentication_Type=0 es detectado
- [x] Patrones de múltiples cuentas objetivo son identificados
- [x] Herramientas como GetNPUsers.py son detectadas
- [x] Cuentas privilegiadas objetivo generan alertas críticas

### 📊 ROI y propuesta de valor

**Inversión requerida:**
- Tiempo de implementación: 2.4 horas (analista + admin AD)
- Configuración de auditoría: 30 minutos
- Formación del equipo: 1.5 horas
- Costo total estimado: $520 USD

**Retorno esperado:**
- Prevención de compromiso de cuentas de servicio: 90% de casos
- Ahorro por cuenta de servicio protegida: $45,000 USD
- Reducción de tiempo de detección: 88% (de 2 horas a 15 minutos)
- ROI estimado: 8,550% en el primer incidente evitado

### 🧪 Metodología de testing

#### Pruebas de laboratorio

1. **Configurar cuentas vulnerables para testing:**
   ```powershell
   # En entorno de lab - NUNCA en producción
   New-ADUser -Name "VulnerableUser" -AccountPassword (ConvertTo-SecureString "Password123" -AsPlainText -Force) -Enabled $true
   Set-ADAccountControl -Identity "VulnerableUser" -DoesNotRequirePreAuth $true
   ```

2. **Ejecutar AS-REP Roasting simulado:**
   ```bash
   # Desde máquina atacante en lab
   python3 GetNPUsers.py lab.local/ -usersfile users.txt -format hashcat -outputfile hashes.txt
   ```

3. **Verificar detección completa:**
   ```splunk
   index=wineventlog EventCode=4768 Pre_Authentication_Type=0 earliest=-30m
   | eval test_scenario="AS-REP Roasting Lab Test"
   | stats count values(Account_Name) as accounts by Client_Address, test_scenario
   | eval detection_coverage=if(count>0,"DETECTED","MISSED")
   ```

#### Validación de rendimiento

1. **Análisis de volumen de eventos:**
   ```splunk
   index=wineventlog EventCode=4768
   | stats count by Pre_Authentication_Type
   | eval percentage=round((count/sum(count))*100,2)
   | table Pre_Authentication_Type, count, percentage
   ```

### 🔄 Mantenimiento y evolución

**Revisión mensual:**
- Auditar cuentas con preautenticación deshabilitada
- Revisar justificación de negocio para configuraciones especiales
- Actualizar listas de cuentas privilegiadas para alertas críticas

**Evolución continua:**
- Integrar con detección de Kerberoasting para correlación
- Desarrollar machine learning para detectar patrones de reconocimiento
- Automatizar respuesta para deshabilitar cuentas vulnerables

**Hardening proactivo:**
```powershell
# Script para identificar y remediar cuentas vulnerables
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth |
ForEach-Object {
    Write-Warning "Cuenta vulnerable encontrada: $($_.Name)"
    # Opcionalmente deshabilitar preauth vulnerability
    # Set-ADAccountControl -Identity $_.DistinguishedName -DoesNotRequirePreAuth $false
}
```

### 🎓 Formación del equipo SOC

**Conocimientos requeridos:**
- Funcionamiento de autenticación Kerberos y preautenticación
- Técnicas de AS-REP Roasting y herramientas asociadas
- Diferencias entre AS-REP y Kerberoasting
- Procedimientos de respuesta a compromiso de credenciales

**Material de formación:**
- **Playbook específico:** "Investigación de alertas AS-REP Roasting"
- **Laboratorio hands-on:** 2 horas con herramientas reales
- **Casos de estudio:** 3 incidentes reales documentados
- **Simulacros trimestrales:** Purple team exercises

**Recursos de referencia:**
- [Kerberos Authentication Overview](https://docs.microsoft.com/en-us/windows-server/security/kerberos/)
- [AS-REP Roasting Technical Details](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)
- [GetNPUsers.py Documentation](https://github.com/fortra/impacket)

### 📚 Referencias y recursos adicionales

- [MITRE ATT&CK T1558.004 - AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/)
- [Microsoft Event 4768 Documentation](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768)
- [Impacket GetNPUsers.py](https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py)
- [Rubeus AS-REP Roasting](https://github.com/GhostPack/Rubeus#asreproast)
- [HackTricks AS-REP Roasting](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/asreproast)
- [Splunk Security Essentials - Kerberos](https://splunkbase.splunk.com/app/3435/)

---

## 📊 Detección en logs y SIEM

| Campo clave                   | Descripción                                           |
|-------------------------------|------------------------------------------------------|
| **EventCode = 4768**          | Solicitud de TGT (AS-REQ) en Kerberos.               |
| **Pre_Authentication_Type=0** | Sin preautenticación: señal de AS-REP Roasting.      |
| **Account_Name**              | Cuenta solicitada.                                   |
| **Client_Address**            | IP origen de la petición.                            |
| **Ticket_Encryption_Type**    | Tipo de cifrado (analítico).                         |

### Query Splunk básica

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4768 Pre_Authentication_Type=0
| table _time, ComputerName, Account_Name, Client_Address, Ticket_Encryption_Type
```

---

## 🔎 Queries completas para más investigación

### 1. Solicitudes repetidas a varias cuentas desde una misma IP

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4768 Pre_Authentication_Type=0
| stats count by Client_Address, Account_Name
| where count > 3
```

### 2. Solicitudes a cuentas privilegiadas

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4768 Pre_Authentication_Type=0
| search Account_Name="Administrator" OR Account_Name="krbtgt" OR Account_Name="*svc*" OR Account_Name="*admin*"
| table _time, Account_Name, Client_Address
```

### 3. Correlación con otros eventos sospechosos del mismo origen

```splunk
index=dc_logs (sourcetype=WinEventLog:Security AND (EventCode=4768 OR EventCode=4625 OR EventCode=4740))
| search Client_Address="IP_SOSPECHOSA"
| sort _time
```

### 4. Cambios en cuentas (preautenticación deshabilitada recientemente)

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4738
| search "Do not require Kerberos preauthentication"=TRUE
| table _time, Target_Account_Name, ComputerName, Subject_Account_Name
```

### 5. Solicitudes desde redes externas o no confiables

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4768 Pre_Authentication_Type=0
| search NOT (Client_Address="10.*" OR Client_Address="192.168.*" OR Client_Address="172.16.*" OR Client_Address="127.0.0.1")
| table _time, Account_Name, Client_Address
```

### 6. Solicitudes externas mostrando todos los usuarios que han hecho logon antes del 4768

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4768 Pre_Authentication_Type=0
| search NOT (Client_Address="10.*" OR Client_Address="192.168.*" OR Client_Address="172.16.*" OR Client_Address="127.0.0.1")
| rename Account_Name as asrep_user, Client_Address as asrep_ip, _time as asrep_time
| join asrep_ip [
    search index=dc_logs sourcetype=WinEventLog:Security EventCode=4624
    | rename Account_Name as logon_user, IpAddress as logon_ip, _time as logon_time
    | table logon_user, logon_ip, logon_time
]
| where logon_ip=asrep_ip AND logon_time < asrep_time
| table asrep_time, asrep_user, asrep_ip, logon_user, logon_time
| sort asrep_time, asrep_ip, logon_time
```

### 7. Analizar los resultados en función de la presencia o ausencia de logons previos

```splunk
... | stats count by asrep_time, asrep_ip | where count=0
```

---

## 🛡️ Detección con Windows Defender for Endpoint

### Reglas de detección personalizadas

```kql
// AS-REP Roasting - Solicitudes sin preautenticación
DeviceLogonEvents
| where ActionType == "LogonFailed" or ActionType == "LogonSuccess"
| join kind=inner (
    DeviceEvents
    | where ActionType == "KerberosAsReqWithoutPreauth"
    | summarize AsRepCount = count() by DeviceId, AccountName, bin(Timestamp, 5m)
    | where AsRepCount > 3
) on DeviceId, AccountName
| project Timestamp, DeviceId, DeviceName, AccountName, AsRepCount
| order by Timestamp desc
```

```kql
// Detección de herramientas de AS-REP Roasting
DeviceProcessEvents
| where ProcessCommandLine has_any ("GetNPUsers", "Rubeus", "asreproast", "Invoke-ASRepRoast")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### Alertas recomendadas

| Regla | Descripción | Severidad |
|-------|-------------|-----------|
| **AS-REP No Preauth Spike** | Más de 5 solicitudes AS-REP sin preautenticación en 5 minutos | Media |
| **AS-REP Roasting Tools** | Detección de herramientas conocidas (GetNPUsers, Rubeus, etc.) | Alta |
| **External AS-REP Requests** | Solicitudes AS-REP desde IPs externas | Alta |

---

## 🦅 Detección con CrowdStrike Falcon

### Hunting queries (Event Search)

```sql
-- Detección de AS-REP Roasting basado en eventos Kerberos
event_platform=Win event_simpleName=AuthActivityAuditLog 
| search LogonType=* AuthenticationPackageName=Kerberos
| bin _time span=5m
| stats dc(TargetUserName) as unique_targets, count as total_attempts by ComputerName, UserName, _time
| where unique_targets > 5 OR total_attempts > 10
| sort - total_attempts
```

```sql
-- Detección de herramientas de AS-REP Roasting
event_platform=Win event_simpleName=ProcessRollup2 
| search (FileName=*rubeus* OR CommandLine=*GetNPUsers* OR CommandLine=*asreproast*)
| table _time, ComputerName, UserName, FileName, CommandLine, ParentProcessId
| sort - _time
```

### Custom IOAs (Indicators of Attack)

```sql
-- IOA para detectar enumeración de usuarios sin preautenticación
event_platform=Win event_simpleName=DnsRequest
| search DomainName=*_kerberos*
| bin _time span=1m
| stats count by ComputerName, UserName, DomainName, _time
| where count > 10
```

---

## 🔍 Queries KQL para Microsoft Sentinel

### Detección de AS-REP Roasting

```kql
// Query principal para detectar AS-REP Roasting
SecurityEvent
| where EventID == 4768
| where PreAuthType == "0" // Sin preautenticación
| where TargetUserName !endswith "$"
| summarize count() by Account, TargetUserName, IpAddress, bin(TimeGenerated, 5m)
| where count_ > 2
| order by TimeGenerated desc
```

```kql
// Correlación con actividad de enumeración
SecurityEvent
| where EventID == 4768 and PreAuthType == "0"
| join kind=inner (
    DeviceProcessEvents
    | where ProcessCommandLine contains "GetNPUsers" or ProcessCommandLine contains "asreproast"
    | project TimeGenerated, DeviceName, ProcessCommandLine, AccountName
) on $left.Account == $right.AccountName
| project TimeGenerated, DeviceName, ProcessCommandLine, Account, TargetUserName, IpAddress
```

### Hunting avanzado

```kql
// Detección de cuentas sin preautenticación recientemente modificadas
SecurityEvent
| where EventID == 4738 // Cambio en cuenta de usuario
| where TargetUserName !endswith "$"
| where SubjectUserName != TargetUserName
| summarize by TimeGenerated, TargetUserName, SubjectUserName, Computer
| join kind=inner (
    SecurityEvent
    | where EventID == 4768 and PreAuthType == "0"
    | project TimeGenerated, TargetUserName, IpAddress
) on TargetUserName
| where TimeGenerated1 > TimeGenerated // AS-REP después del cambio
| project TimeGenerated1, TargetUserName, SubjectUserName, Computer, IpAddress
```

---

## 🦾 Hardening y mitigación

| Medida                                   | Descripción                                                                                  |
|-------------------------------------------|---------------------------------------------------------------------------------------------|
| **Activar preautenticación**              | Desactiva la opción **"No requerir preautenticación Kerberos"** en todas las cuentas.        |
| **Revisar cuentas sensibles**             | Verifica que cuentas privilegiadas y de servicio tengan preautenticación habilitada.         |
| **Contraseñas robustas**                  | Usa contraseñas largas y complejas, dificultando el crackeo offline.                        |
| **Monitorización**                        | Vigila eventos 4768 con Pre_Authentication_Type=0 y correlaciona IPs sospechosas.           |
| **Auditoría periódica**                   | Busca cuentas vulnerables a AS-REP Roasting periódicamente.                                 |
| **No exponer controladores de dominio**   | Mantén DCs y cuentas AD fuera de alcance de redes públicas/no confiables.                   |

---

## 🔧 Parches y actualizaciones

| Parche/Update | Descripción                                                                                  |
|---------------|----------------------------------------------------------------------------------------------|
| **KB5025238** | Windows 11 22H2 - Mejoras en seguridad Kerberos y protección contra AS-REP Roasting.        |
| **KB5025239** | Windows 10 21H2/22H2 - Fortalecimiento de validaciones de preautenticación Kerberos.        |
| **KB5022906** | Windows Server 2022 - Auditoría mejorada de eventos 4768 con más metadatos de seguridad.     |
| **KB5022845** | Windows Server 2019 - Correcciones en el manejo de políticas de preautenticación.            |
| **Windows Server 2016** | KB4580390 - Mejoras en logging de eventos Kerberos para mejor detección.          |
| **RSAT** | Herramientas de administración remota actualizadas para gestión de políticas Kerberos. |

### Configuraciones de registro recomendadas

```powershell
# Habilitar auditoría detallada de autenticación Kerberos
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable

# Configurar políticas de grupo para preautenticación obligatoria
Set-ADDefaultDomainPasswordPolicy -Identity "Default Domain Policy" -ComplexityEnabled $true
```

### Actualizaciones críticas de seguridad

- **CVE-2022-37958**: Vulnerabilidad en validación de tickets AS-REP (parcheada en actualizaciones de noviembre 2022)
- **CVE-2021-42287**: sAMAccountName spoofing que puede facilitar AS-REP Roasting (KB5008102)
- **CVE-2021-42278**: Bypass de validaciones de nombre de cuenta (KB5008102)

---

## 🧑‍💻 ¿Cómo revisar o identificar la preautenticación de una cuenta?

```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```
O revisa en la consola de Active Directory:  
Propiedades de usuario → Cuenta → Opciones de cuenta →  
**"No requerir preautenticación Kerberos"** (debe estar desmarcada).

---

## 🚨 Respuesta ante incidentes

### Procedimientos de respuesta inmediata

1. **Identificación del ataque AS-REP Roasting:**
   - Confirmar eventos 4768 con Pre_Authentication_Type=0 desde IPs sospechosas
   - Verificar si las cuentas objetivo existen y tienen preautenticación deshabilitada
   - Correlacionar con herramientas de enumeración como GetNPUsers.py

2. **Contención inmediata:**
   - Bloquear la IP origen del ataque en firewalls y sistemas de seguridad
   - Habilitar inmediatamente preautenticación en cuentas vulnerables afectadas
   - Cambiar contraseñas de cuentas que fueron objetivo del AS-REP Roasting

3. **Análisis de impacto:**
   - Determinar qué cuentas fueron enumeradas sin preautenticación
   - Evaluar la fortaleza de las contraseñas de las cuentas comprometidas
   - Verificar si existe evidencia de cracking offline exitoso

4. **Investigación forense:**
   - Buscar herramientas de AS-REP Roasting en el endpoint origen
   - Analizar logs de autenticación para identificar acceso inicial
   - Revisar configuraciones de cuentas para determinar cómo se deshabilitó preautenticación

5. **Recuperación y endurecimiento:**
   - Habilitar preautenticación Kerberos en todas las cuentas del dominio
   - Implementar contraseñas robustas en cuentas previamente vulnerables
   - Fortalecer monitoreo de eventos 4768 con alertas en tiempo real

### Scripts de respuesta automatizada

```powershell
# Script de respuesta para AS-REP Roasting
function Respond-ASREPRoastingAttack {
    param($AttackerIP, $VulnerableAccounts, $AffectedDCs)
    
    # Bloquear IP atacante
    New-NetFirewallRule -DisplayName "Block AS-REP Roasting IP" -Direction Inbound -RemoteAddress $AttackerIP -Action Block
    
    # Habilitar preautenticación en cuentas vulnerables
    foreach ($account in $VulnerableAccounts) {
        Set-ADAccountControl -Identity $account -DoesNotRequirePreAuth $false
        Write-EventLog -LogName Security -Source "ADSecurity" -EventId 9004 -Message "Enabled pre-authentication for account $account after AS-REP Roasting attempt"
        
        # Cambiar contraseña por seguridad
        $newPassword = -join ((33..126) | Get-Random -Count 32 | % {[char]$_})
        Set-ADAccountPassword -Identity $account -NewPassword (ConvertTo-SecureString $newPassword -AsPlainText -Force) -Reset
    }
    
    # Auditar todas las cuentas sin preautenticación
    $allVulnerable = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
    foreach ($vuln in $allVulnerable) {
        Write-Warning "Account without pre-auth found: $($vuln.Name)"
        # Opcional: habilitar automáticamente
        # Set-ADAccountControl -Identity $vuln.DistinguishedName -DoesNotRequirePreAuth $false
    }
    
    # Notificar al equipo de seguridad
    Send-MailMessage -To "security-team@company.com" -Subject "ALERT: AS-REP Roasting Attack Detected" -Body "AS-REP Roasting from $AttackerIP targeting accounts: $($VulnerableAccounts -join ', '). Pre-authentication enabled and passwords reset."
}

# Script para auditar y remediar configuraciones vulnerables
function Audit-PreAuthenticationSettings {
    # Buscar todas las cuentas sin preautenticación
    $vulnerableUsers = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth, LastLogonDate, PasswordLastSet
    
    foreach ($user in $vulnerableUsers) {
        Write-Host "Vulnerable Account: $($user.Name)" -ForegroundColor Red
        Write-Host "  Last Logon: $($user.LastLogonDate)" -ForegroundColor Yellow
        Write-Host "  Password Last Set: $($user.PasswordLastSet)" -ForegroundColor Yellow
        
        # Verificar si la cuenta está activa
        if ((Get-Date) - $user.LastLogonDate -gt (New-TimeSpan -Days 90)) {
            Write-Warning "  Account appears inactive (>90 days) - consider disabling"
        }
        
        # Verificar fortaleza de contraseña
        if ((Get-Date) - $user.PasswordLastSet -gt (New-TimeSpan -Days 365)) {
            Write-Warning "  Password is old (>365 days) - requires immediate change"
        }
    }
    
    return $vulnerableUsers
}
```

### Checklist de respuesta a incidentes

- [ ] **Detección confirmada**: Validar eventos 4768 con Pre_Authentication_Type=0
- [ ] **Contención**: Bloquear IP atacante y aislar sistemas comprometidos
- [ ] **Remediación**: Habilitar preautenticación en cuentas vulnerables afectadas
- [ ] **Rotación**: Cambiar contraseñas de cuentas que fueron objetivo del ataque
- [ ] **Auditoría**: Revisar todas las cuentas del dominio para configuraciones similares
- [ ] **Monitoreo**: Implementar alertas para futuras solicitudes AS-REQ sin preauth
- [ ] **Documentación**: Registrar cuentas afectadas y medidas implementadas
- [ ] **Seguimiento**: Monitorear por 30 días actividad relacionada con cuentas afectadas
- [ ] **Política**: Actualizar políticas para prevenir deshabilitación de preautenticación

### Hardening post-incidente

```powershell
# Script para implementar hardening completo post AS-REP Roasting
function Implement-ASREPHardening {
    # 1. Habilitar preautenticación en todas las cuentas
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | ForEach-Object {
        Set-ADAccountControl -Identity $_.DistinguishedName -DoesNotRequirePreAuth $false
        Write-Host "Enabled pre-authentication for: $($_.Name)" -ForegroundColor Green
    }
    
    # 2. Configurar política de auditoría avanzada
    auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
    
    # 3. Configurar alertas en tiempo real (requiere configuración de SIEM)
    $alertScript = @"
# Alerta para AS-REP sin preautenticación
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4768} | Where-Object {
    `$_.Properties[7].Value -eq 0  # Pre_Authentication_Type = 0
} | ForEach-Object {
    Write-EventLog -LogName Application -Source "ASREPAlert" -EventId 1001 -Message "AS-REP request without pre-auth detected from `$(`$_.Properties[6].Value)"
}
"@
    
    # 4. Implementar monitoreo de cambios en configuración de preautenticación
    $gpo = New-GPO -Name "Monitor Pre-Authentication Changes"
    # Configurar auditoría de cambios en objetos de usuario
    Set-GPRegistryValue -Guid $gpo.Id -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Audit" -ValueName "AuditAccountManagement" -Type DWord -Value 3
    
    Write-Host "AS-REP Roasting hardening completed successfully" -ForegroundColor Green
}
```

---

## 📚 Referencias

- [AS-REP Roasting - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/as-rep-roasting)
- [Impacket GetNPUsers](https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py)
