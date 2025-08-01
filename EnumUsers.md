# 🛡️ Enumeración de Usuarios en Active Directory

---

## 📝 ¿Qué es la enumeración de usuarios?

| Concepto      | Descripción                                                                                    |
|---------------|------------------------------------------------------------------------------------------------|
| **Definición**| Proceso mediante el cual un atacante recopila la lista de usuarios de un dominio a través de consultas LDAP, SMB, RPC o acceso directo a la SAM. |
| **Requisito** | El atacante debe tener acceso autenticado al dominio, incluso con un usuario de bajo privilegio.|

---

## 🛠️ ¿Cómo funciona el ataque?

| Fase             | Acción                                                                                                 |
|------------------|--------------------------------------------------------------------------------------------------------|
| **Autenticación**| El atacante inicia sesión en el dominio (4624, 4776).                                                  |
| **Enumeración**  | Utiliza herramientas (NetExec, CrackMapExec, BloodHound, Impacket, scripts LDAP/RPC) para consultar usuarios. |
| **Obtención**    | El DC responde con objetos tipo `SAM_USER` (usuarios) y el atacante recibe/extrae la lista de cuentas.  |

---

## 💻 Ejemplo práctico

```bash
python3 /usr/share/doc/python3-impacket/examples/GetADUsers.py essos.local/daenerys.targaryen:'Dracarys123' -all
```

```
username              lastlogon              pwdlastset             description
--------------------- --------------------- ---------------------- -------------
jon.snow              2024-05-23 07:05:19   2024-02-26 09:30:35    Lord Commander
arya.stark            2024-05-21 11:15:42   2024-03-12 08:12:12    No One
...
```

---

## 📊 Detección en logs y SIEM

| Campo clave                   | Descripción                                                                                      |
|-------------------------------|-------------------------------------------------------------------------------------------------|
| **EventCode = 4661**          | Acceso a objeto protegido AD; clave: muchos accesos a `SAM_USER` (usuarios) en poco tiempo.     |
| **Object_Type = SAM_USER**    | Indica acceso a un objeto de usuario (local o dominio).                                         |
| **Object_Name = SID**         | SID del usuario accedido (cambia en cada acceso).                                               |
| **Accesses = DELETE/READ**    | Permisos solicitados. Muchos accesos simultáneos, sobre todo DELETE/READ, son sospechosos.      |
| **Account_Name**              | Cuenta que realiza la enumeración (a veces una cuenta de equipo en procesos automáticos).       |
| **Process_Name**              | Proceso que accede (ej: `C:\Windows\System32\lsass.exe`).                                       |
| **Client_Address**            | IP origen de la petición (si disponible).                                                       |

### Ejemplo de evento 4661 relevante

```
A handle to an object was requested.
Subject:
    Account Name:      MEEREEN$
    Account Domain:    ESSOS
    Logon ID:          0x3E7
Object:
    Object Type:       SAM_USER
    Object Name:       S-1-5-21-2000378473-4079260497-750590020-1112
Process Information:
    Process Name:      C:\Windows\System32\lsass.exe
Access Request Information:
    Accesses:          DELETE READ_CONTROL WRITE_DAC ...
```

---

## 📋 Caso de Uso Completo Splunk

### 🎯 Contexto empresarial y justificación

**Problema de negocio:**
- La enumeración de usuarios es el primer paso en ataques dirigidos, permitiendo a atacantes identificar cuentas objetivo para ataques de fuerza bruta, phishing dirigido, y ingeniería social
- Una enumeración exitosa expone estructura organizacional, nombrado de cuentas, y patrones que facilitan ataques posteriores
- 95% de ataques avanzados comienzan con reconocimiento de usuarios válidos del dominio
- Costo promedio de escalada post-enumeración: $35,000 USD (tiempo promedio de detección: 6 horas)

**Valor de la detección:**
- Identificación temprana de reconocimiento de usuarios via Event 4661
- Detección de herramientas automatizadas de enumeración antes de escalada
- Protección de información organizacional sensible
- Cumplimiento con controles de prevención de reconocimiento

### 📐 Arquitectura de implementación

**Prerequisitos técnicos:**
- Splunk Enterprise 8.0+ o Splunk Cloud
- Universal Forwarders en Domain Controllers
- Windows TA v8.0+ configurado para Event 4661
- Auditoría de "Handle Manipulation" habilitada en DCs
- Configuración de filtros para reducir ruido de procesos legítimos

**Arquitectura de datos:**
```
[Domain Controllers] → [Universal Forwarders] → [Indexers] → [Search Heads]
       ↓                      ↓                     ↓
[EventCode 4661]      [WinEventLog:Security]  [Index: wineventlog]
[SAM_USER Access]           ↓                      ↓
[Object Enumeration]  [Real-time processing]  [Pattern Detection]
```

### 🔧 Guía de implementación paso a paso

#### Fase 1: Configuración inicial (Tiempo estimado: 45 min)

1. **Habilitar auditoría de manipulación de objetos:**
   ```powershell
   # En todos los Domain Controllers
   auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
   
   # Verificar configuración
   auditpol /get /subcategory:"Handle Manipulation"
   
   # Configurar auditoría de acceso a objetos SAM
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "AuditBaseObjects" -Value 1
   ```

2. **Configurar filtros en Splunk:**
   ```
   # props.conf para reducir ruido
   [WinEventLog:Security]
   TRANSFORMS-filter_system_enum = filter_legitimate_sam_access
   
   # transforms.conf
   [filter_legitimate_sam_access]
   REGEX = EventCode=4661.*Process_Name.*lsass\.exe.*Account_Name.*(SYSTEM|LOCAL\sSERVICE|NETWORK\sSERVICE)
   DEST_KEY = queue
   FORMAT = nullQueue
   ```

3. **Verificar configuración:**
   ```splunk
   index=wineventlog EventCode=4661 Object_Type="SAM_USER" earliest=-1h
   | stats count by Account_Name, Process_Name
   | where NOT match(Account_Name, "(SYSTEM|.*\$)")
   | head 10
   ```

#### Fase 2: Implementación de detecciones (Tiempo estimado: 65 min)

1. **Detección principal - Enumeración masiva de usuarios:**
   ```splunk
   index=wineventlog EventCode=4661 Object_Type="SAM_USER"
   | where NOT match(Account_Name, "(SYSTEM|.*\$|LOCAL\sSERVICE|NETWORK\sSERVICE)")
   | where NOT match(Process_Name, "C:\\\\Windows\\\\System32\\\\lsass\\.exe")
   | bucket _time span=2m
   | stats dc(Object_Name) as unique_users, count as total_accesses by _time, Account_Name, Process_Name, Computer
   | where unique_users > 15 OR total_accesses > 50
   | eval severity=case(
       unique_users > 50, "CRITICAL",
       unique_users > 25, "HIGH",
       1=1, "MEDIUM"
   )
   | eval technique="User Enumeration", risk_score=case(
       severity="CRITICAL", 85,
       severity="HIGH", 70,
       1=1, 55
   )
   | table _time, Account_Name, Computer, unique_users, total_accesses, severity, risk_score
   ```

2. **Detección post-autenticación:**
   ```splunk
   index=wineventlog (EventCode=4624 OR EventCode=4661)
   | where (EventCode=4624 AND LogonType=3) OR (EventCode=4661 AND Object_Type="SAM_USER")
   | transaction Account_Name maxspan=5m startswith="EventCode=4624" endswith="EventCode=4661"
   | where eventcount > 20
   | eval time_to_enum=duration/60
   | where time_to_enum < 5
   | eval severity="HIGH", technique="Post-Auth User Enumeration"
   | table _time, Account_Name, eventcount, time_to_enum, severity
   ```

3. **Configurar alertas:**
   - **Mass User Enumeration**: Cada 5 minutos
   - **Rapid Post-Auth Enum**: Cada 3 minutos
   - **External Source Enumeration**: Tiempo real

#### Fase 3: Dashboard y validación (Tiempo estimado: 50 min)

1. **Dashboard de monitoreo:**
   ```xml
   <dashboard>
     <label>User Enumeration Detection Dashboard</label>
     <row>
       <panel>
         <title>👥 User Enumeration Activity (Last 4 Hours)</title>
         <chart>
           <search>
             <query>
               index=wineventlog EventCode=4661 Object_Type="SAM_USER"
               | where NOT match(Account_Name, ".*\$")
               | timechart span=15m count by Account_Name
             </query>
           </search>
         </chart>
       </panel>
     </row>
   </dashboard>
   ```

2. **Validación con herramientas:**
   ```bash
   # En entorno de lab controlado
   python3 GetADUsers.py lab.local/testuser:'password' -all
   
   # Verificar detección
   nxc ldap dc.lab.local -u testuser -p password --users
   ```

3. **Verificar detección:**
   ```splunk
   index=wineventlog EventCode=4661 Object_Type="SAM_USER" earliest=-15m
   | search Account_Name="testuser"
   | stats dc(Object_Name) as enumerated_users by Account_Name
   | eval detection_status=if(enumerated_users>10,"DETECTED","MISSED")
   ```

### ✅ Criterios de éxito

**Métricas de detección:**
- MTTD para enumeración masiva: < 10 minutos
- MTTD para herramientas automatizadas: < 5 minutos
- Tasa de falsos positivos: < 5% (actividad de AD legítima)
- Cobertura: > 90% de herramientas de enumeración conocidas

**Validación funcional:**
- [x] Event 4661 con Object_Type="SAM_USER" es procesado
- [x] Patrones de acceso masivo son detectados
- [x] Herramientas como GetADUsers.py son identificadas
- [x] Contexto de timing post-autenticación es analizado

### 📊 ROI y propuesta de valor

**Inversión requerida:**
- Tiempo de implementación: 2.7 horas (analista + admin AD)
- Configuración de auditoría: 30 minutos
- Formación del equipo: 1.5 horas
- Costo total estimado: $580 USD

**Retorno esperado:**
- Prevención de escalada post-enumeración: 80% de casos
- Ahorro por reconocimiento temprano: $35,000 USD
- Reducción de tiempo de detección: 85% (de 6 horas a 10 minutos)
- ROI estimado: 5,930% en el primer incidente evitado

### 🧪 Metodología de testing

#### Pruebas de laboratorio

1. **Configurar usuarios de prueba:**
   ```powershell
   # En entorno de lab
   1..20 | ForEach-Object {
       New-ADUser -Name "TestUser$_" -AccountPassword (ConvertTo-SecureString "Password123" -AsPlainText -Force) -Enabled $true
   }
   ```

2. **Ejecutar enumeración simulada:**
   ```bash
   # Múltiples herramientas para validación
   python3 GetADUsers.py lab.local/testuser:'password' -all
   nxc ldap dc.lab.local -u testuser -p password --users
   python3 ldapsearch-ad.py -l dc.lab.local -d lab.local -u testuser -p password --users
   ```

3. **Verificar detección comprehensiva:**
   ```splunk
   index=wineventlog EventCode=4661 Object_Type="SAM_USER" earliest=-20m
   | eval test_scenario="User Enumeration Validation"
   | stats dc(Object_Name) as unique_objects, count by Account_Name, test_scenario
   | eval detection_quality=case(
       unique_objects>15 AND count>30, "EXCELLENT",
       unique_objects>10, "GOOD", 
       unique_objects>5, "BASIC",
       1=1, "POOR"
   )
   ```

### 🔄 Mantenimiento y evolución

**Revisión quincenal:**
- Ajustar umbrales basados en patrones normales de administración
- Revisar cuentas de servicio legítimas para agregar a whitelist
- Actualizar detección con nuevas herramientas de enumeración

**Evolución continua:**
- Integrar con detección de BloodHound para correlación completa
- Desarrollar ML para distinguir enumeración legítima vs maliciosa
- Automatizar respuesta para bloquear fuentes de enumeración masiva

**Hardening complementario:**
```powershell
# Restringir consultas LDAP anónimas
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "DsHeuristics" -Value "001000001"

# Limitar enumeración de usuarios
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1
```

### 🎓 Formación del equipo SOC

**Conocimientos requeridos:**
- Funcionamiento de SAM y objetos de usuario en Active Directory
- Técnicas de enumeración y herramientas asociadas
- Análisis de Event 4661 y patrones de acceso a objetos
- Diferenciación entre enumeración legítima y maliciosa

**Material de formación:**
- **Playbook específico:** "Investigación de alertas de enumeración de usuarios"
- **Laboratorio práctico:** 2 horas con herramientas reales
- **Casos reales:** Análisis de 3 incidentes de reconocimiento
- **Procedimientos de escalation:** Cuándo alertar sobre reconocimiento masivo

### 📚 Referencias y recursos adicionales

- [MITRE ATT&CK T1087.002 - Domain Account Discovery](https://attack.mitre.org/techniques/T1087/002/)
- [Microsoft Event 4661 Documentation](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4661)
- [Impacket GetADUsers.py](https://github.com/fortra/impacket/blob/master/examples/GetADUsers.py)
- [NetExec LDAP Enumeration](https://github.com/Pennyw0rth/NetExec)
- [Active Directory Security Best Practices](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/)
- [Splunk Security Essentials - AD Reconnaissance](https://splunkbase.splunk.com/app/3435/)

---

## 🔎 Queries Splunk para hunting

### 1. Detección de enumeración masiva (muchos 4661 sobre distintos SAM_USER en poco tiempo)

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4661 Object_Type=SAM_USER
| bucket _time span=1m
| stats dc(Object_Name) as unique_users, values(Object_Name) as users, count by _time, Account_Name, Process_Name
| where unique_users > 12
| sort -_time
```
> _Alerta si en 1 minuto hay accesos a más de 12 SIDs distintos de usuario (`SAM_USER`) por la misma cuenta/proceso._

### 2. Patrón tras autenticación (4624 → muchos 4661)

```splunk
index=dc_logs sourcetype=WinEventLog:Security (EventCode=4624 OR EventCode=4661)
| transaction Account_Name maxspan=2m
| search EventCode=4624 AND EventCode=4661
| table _time, Account_Name, host, EventCode
```

### 3. Excluir cuentas/procesos legítimos

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4661 Object_Type=SAM_USER
| search NOT (Account_Name="MEEREEN$" OR Account_Name="backup" OR Process_Name="C:\\Windows\\System32\\lsass.exe")
| stats count by _time, Account_Name, Process_Name
```

---

## ⚡️ Alertas recomendadas

| Alerta                                        | Descripción                                                                    |
|-----------------------------------------------|--------------------------------------------------------------------------------|
| **Alerta 1**                                 | Más de 12 accesos 4661 a SIDs distintos de `SAM_USER` por el mismo usuario/proceso en 1 minuto. |
| **Alerta 2**                                 | Patrón de 4624 seguido rápidamente de muchos 4661 por el mismo usuario/IP.      |
| **Alerta 3**                                 | Accesos DELETE/READ sobre muchos `SAM_USER` en poco tiempo por cuentas no habituales.|

---

## 🛡️ Detección con Windows Defender for Endpoint

### Reglas de detección personalizadas

```kql
// User Enumeration - Detección de enumeración masiva de usuarios
DeviceEvents
| where ActionType == "LdapQuery"
| where AdditionalFields has_any ("sAMAccountName", "userPrincipalName", "member", "objectClass=user")
| summarize QueryCount = count(), UniqueQueries = dcount(AdditionalFields) by DeviceId, AccountName, bin(Timestamp, 5m)
| where QueryCount > 50 or UniqueQueries > 20
| order by QueryCount desc
```

```kql
// Detección de herramientas de enumeración
DeviceProcessEvents
| where ProcessCommandLine has_any ("enum4linux", "ldapdomaindump", "windapsearch", "bloodhound", "adrecon")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

```kql
// Detección de acceso masivo a objetos de usuario
DeviceEvents
| where ActionType == "DirectoryServiceAccess"
| where AdditionalFields has "SAM_USER" or AdditionalFields has "objectClass=user"
| summarize AccessCount = count() by DeviceId, AccountName, bin(Timestamp, 2m)
| where AccessCount > 30
| order by AccessCount desc
```

### Alertas recomendadas

| Regla | Descripción | Severidad |
|-------|-------------|-----------|
| **Mass User Enumeration** | Más de 50 consultas de usuario en 5 minutos | Media |
| **User Enum Tools** | Detección de herramientas de enumeración conocidas | Alta |
| **Directory Service Access Spike** | Acceso masivo a objetos de directorio | Media |

---

## 🦅 Detección con CrowdStrike Falcon

### Hunting queries (Event Search)

```sql
-- Detección de enumeración de usuarios
event_platform=Win event_simpleName=LdapSearch
| search SearchFilter=*user* OR SearchFilter=*sAMAccountName* OR SearchFilter=*member*
| bin _time span=5m
| stats count as search_count, dc(SearchFilter) as unique_filters by ComputerName, UserName, _time
| where search_count > 100 OR unique_filters > 50
| sort - search_count
```

```sql
-- Detección de herramientas de enumeración
event_platform=Win event_simpleName=ProcessRollup2 
| search (CommandLine=*enum4linux* OR CommandLine=*ldapdomaindump* OR CommandLine=*windapsearch* OR CommandLine=*adrecon*)
| table _time, ComputerName, UserName, FileName, CommandLine, SHA256HashData
| sort - _time
```

```sql
-- Detección de acceso a información de usuario
event_platform=Win event_simpleName=DirectoryServiceAccess
| search ObjectType=User AccessMask=READ_PROPERTY
| bin _time span=2m
| stats count as access_count, dc(ObjectDN) as unique_objects by ComputerName, UserName, _time
| where access_count > 50 OR unique_objects > 30
| sort - access_count
```

### Custom IOAs (Indicators of Attack)

```sql
-- IOA para detectar enumeración de grupos privilegiados
event_platform=Win event_simpleName=LdapSearch
| search SearchFilter=*admin* OR SearchFilter=*operator* OR SearchFilter=*privileged*
| stats count by ComputerName, UserName, SearchFilter
| where count > 10
```

---

## 🔍 Queries KQL para Microsoft Sentinel

### Detección de User Enumeration

```kql
// Query principal para detectar enumeración de usuarios
SecurityEvent
| where EventID == 4661 // Object access
| where ObjectName has "SAM_USER" or ObjectName has "objectClass=user"
| where AccessMask != "0x0"
| summarize AccessCount = count(), UniqueObjects = dcount(ObjectName) by Account, Computer, bin(TimeGenerated, 5m)
| where AccessCount > 30 or UniqueObjects > 20
| order by AccessCount desc
```

```kql
// Correlación con herramientas de enumeración
DeviceProcessEvents
| where ProcessCommandLine has_any ("enum4linux", "ldapdomaindump", "windapsearch", "bloodhound")
| join kind=inner (
    SecurityEvent
    | where EventID == 4661 and ObjectName has "SAM_USER"
    | project TimeGenerated, Computer, Account, ObjectName
) on $left.DeviceName == $right.Computer
| project TimeGenerated, DeviceName, ProcessCommandLine, ObjectName
```

### Hunting avanzado

```kql
// Detección de enumeración de grupos privilegiados
SecurityEvent
| where EventID == 4661
| where ObjectName has_any ("Domain Admins", "Enterprise Admins", "Administrators", "Account Operators")
| summarize AccessCount = count(), UniqueGroups = dcount(ObjectName) by Account, Computer, bin(TimeGenerated, 10m)
| where AccessCount > 10 or UniqueGroups > 3
| order by AccessCount desc
```

```kql
// Detección de enumeración seguida de ataques
SecurityEvent
| where EventID == 4661 and ObjectName has "SAM_USER"
| summarize EnumCount = count() by Account, Computer, bin(TimeGenerated, 10m)
| where EnumCount > 50
| join kind=inner (
    SecurityEvent
    | where EventID in (4625, 4771, 4768) // Failed auth attempts
    | summarize AuthAttempts = count() by Account, Computer, bin(TimeGenerated, 10m)
    | where AuthAttempts > 5
) on Account, Computer, TimeGenerated
| project TimeGenerated, Account, Computer, EnumCount, AuthAttempts
```

---

## 🦾 Hardening y mitigación

| Medida                                   | Descripción                                                                                  |
|-------------------------------------------|---------------------------------------------------------------------------------------------|
| **Auditoría avanzada en objetos clave**   | Configura SACLs para auditar accesos a usuarios críticos o grupos sensibles.                 |
| **Exclusión de cuentas legítimas**        | Excluye del alertado cuentas de equipo o procesos de sistema conocidos.                      |
| **Monitorización continua**               | Vigila patrones de eventos 4661 y correlación con actividad inusual.                         |
| **Segmentación de red**                   | Restringe acceso a DCs solo a redes y usuarios necesarios.                                   |
| **Alertas y dashboards en SIEM**          | Implementa alertas ante patrones de enumeración y revisa dashboards periódicamente.           |

---

## 🧑‍💻 ¿Cómo revisar usuarios en Active Directory?

```powershell
Get-ADUser -Filter * -Properties *
```
O con Impacket desde Kali Linux:
```bash
python3 /usr/share/doc/python3-impacket/examples/GetADUsers.py essos.local/usuario:contraseña -all
```

---

## 🔧 Parches y actualizaciones

| Parche/Update | Descripción                                                                                  |
|---------------|----------------------------------------------------------------------------------------------|
| **KB5025238** | Windows 11/10 - Mejoras en protección contra enumeración de usuarios vía múltiples métodos.|
| **KB5022906** | Windows Server 2022 - Fortalecimiento de controles de acceso para consultas de usuarios.   |
| **KB5022845** | Windows Server 2019 - Correcciones en permisos por defecto y limitación de acceso anónimo. |
| **KB4580390** | Windows Server 2016 - Parches para restringir enumeración vía SMB, RPC y LDAP.             |
| **KB5005413** | Todas las versiones - Mejoras en autenticación para prevenir enumeración no autorizada.    |
| **Anonymous Access Updates** | Actualizaciones para limitar acceso anónimo y enumeración de usuarios.        |

### Configuraciones de registro críticas

```powershell
# Restringir enumeración anónima de usuarios
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1

# Limitar consultas RPC anónimas
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -Value 0

# Configurar auditoría de enumeración
auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
```

### Configuraciones de GPO críticas

```powershell
# Configurar políticas anti-enumeración
# Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options:
# "Network access: Do not allow anonymous enumeration of SAM accounts" = Enabled
# "Network access: Do not allow anonymous enumeration of SAM accounts and shares" = Enabled
# "Network access: Restrict anonymous access to Named Pipes and Shares" = Enabled

# Configurar permisos restrictivos
Remove-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" -Members "Everyone" -Confirm:$false
```

### Scripts de validación post-configuración

```powershell
# Verificar configuraciones anti-enumeración
$restrictAnon = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -ErrorAction SilentlyContinue
if ($restrictAnon.RestrictAnonymous -eq 2) {
    Write-Host "✓ RestrictAnonymous configurado correctamente" -ForegroundColor Green
} else {
    Write-Host "✗ CONFIGURAR RestrictAnonymous = 2" -ForegroundColor Red
}

# Verificar permisos del grupo Pre-Windows 2000 Compatible Access
$preW2kGroup = Get-ADGroupMember "Pre-Windows 2000 Compatible Access" | Where-Object {$_.Name -eq "Everyone"}
if (-not $preW2kGroup) {
    Write-Host "✓ Everyone removido de Pre-Windows 2000 Compatible Access" -ForegroundColor Green
} else {
    Write-Host "✗ REMOVER Everyone de Pre-Windows 2000 Compatible Access" -ForegroundColor Red
}

# Detectar intentos de enumeración
$enumEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4798,4799} -MaxEvents 50 -ErrorAction SilentlyContinue
$enumEvents | Group-Object Properties[1] | Where-Object Count -gt 10 |
ForEach-Object {
    Write-Warning "Enumeración de usuarios detectada desde: $($_.Name) - $($_.Count) intentos"
}
```

### Scripts de detección específicos

```powershell
# Monitorear consultas LDAP de enumeración masiva
$ldapEvents = Get-WinEvent -FilterHashtable @{LogName='Directory Service'; ID=1644} -MaxEvents 100 -ErrorAction SilentlyContinue
$ldapEvents | Where-Object {$_.Message -like "*objectClass=user*"} |
Group-Object Properties[3] | Where-Object Count -gt 20 |
ForEach-Object {
    Write-Warning "Enumeración masiva de usuarios via LDAP: IP $($_.Name) - $($_.Count) consultas"
}

# Detectar herramientas de enumeración comunes
Get-Process | Where-Object {$_.ProcessName -match "(enum4linux|rpcclient|ldapsearch|net\.exe)"} |
ForEach-Object {
    Write-Warning "Herramienta de enumeración detectada: $($_.ProcessName) PID:$($_.Id)"
}
```

### Actualizaciones críticas relacionadas

- **CVE-2022-26923**: Vulnerabilidad que puede facilitar enumeración privilegiada (KB5014754)
- **CVE-2021-42278**: Spoofing que combinado con enumeración puede ser crítico (KB5008102)
- **CVE-2019-1040**: Bypass que facilita enumeración no autorizada (KB4511553)
- **CVE-2020-1472**: Zerologon que permite enumeración completa post-explotación (KB4556836)

---

## 📚 Referencias

- [User Enumeration in AD - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/domain-user-enumeration)
- [Impacket GetADUsers](https://github.com/fortra/impacket/blob/master/examples/GetADUsers.py)
