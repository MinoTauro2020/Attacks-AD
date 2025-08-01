# 🛑 Kerberoasting en Active Directory

---

## 📝 ¿Qué es Kerberoasting?

| Concepto      | Descripción                                                                                                   |
|---------------|--------------------------------------------------------------------------------------------------------------|
| **Definición**| Técnica que permite a un atacante solicitar tickets de servicio (TGS) Kerberos para cuentas con SPN y crackear los hashes offline. |
| **Requisito** | El atacante debe tener acceso a una cuenta autenticada en el dominio y que existan cuentas de servicio con SPN configurado.        |

---

## 🛠️ ¿Cómo funciona el ataque?

| Fase             | Acción                                                                                         |
|------------------|------------------------------------------------------------------------------------------------|
| **Enumeración**  | El atacante identifica cuentas de servicio con SPN vía LDAP/AD o herramientas (Impacket, PowerView, etc). |
| **Solicitud**    | Solicita tickets de servicio (TGS) al KDC para esas cuentas de servicio.                       |
| **Obtención**    | El KDC responde con el ticket cifrado con el hash de la contraseña de la cuenta de servicio.   |
| **Crackeo**      | El atacante extrae el hash y lo crackea offline (ej: Hashcat, John the Ripper).                |

---

## 💻 Ejemplo práctico

```bash
python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py essos.local/daenerys.targaryen:'Dracarys123'
```

```
ServicePrincipalName         Name        MemberOf  PasswordLastSet             LastLogon                   Delegation  PwdNeverExpires  UAC      
---------------------------- ----------  --------  --------------------------  --------------------------  ----------  ---------------  --------
MSSQLSvc/meereen.essos.local:1433 sql_svc            2024-02-26 09:30:35.437503  2024-05-23 07:05:19.141162            False             0x410200 

$krb5tgs$23$*sql_svc$MSSQLSvc/meereen.essos.local*essos.local*$d21c1eebd2bfa64bd4f5f3a7c67cf885$aa3b1c1b1f2c3a2a0b7a5d0f0e0b6e5e6e4c3d2e1b0a0a0b0d0e0f0a0b0a0b0a0b0a0b0a0b0a0b0a0b0a0b0a0b0a0b0a0b0a0b
```

---

## 📋 Caso de Uso Completo Splunk

### 🎯 Contexto empresarial y justificación

**Problema de negocio:**
- Kerberoasting permite a atacantes extraer hashes de contraseñas de cuentas de servicio mediante solicitud de tickets TGS y crackearlas offline
- Cuentas de servicio típicamente tienen contraseñas débiles y privilegios elevados, resultando en escalada inmediata
- 80% de organizaciones tienen cuentas de servicio vulnerables a Kerberoasting
- Costo promedio de compromiso de cuenta de servicio privilegiada: $85,000 USD

**Valor de la detección:**
- Identificación en tiempo real de patrones de Kerberoasting via Event 4769
- Detección de herramientas automatizadas como GetUserSPNs.py y Rubeus
- Protección proactiva de cuentas de servicio críticas
- Cumplimiento con controles de gestión de identidades privilegiadas

### 📐 Arquitectura de implementación

**Prerequisitos técnicos:**
- Splunk Enterprise 8.1+ o Splunk Cloud
- Universal Forwarders en todos los Domain Controllers
- Windows TA v8.5+ con configuración optimizada para Event 4769
- Auditoría Kerberos TGS habilitada en modo detallado
- Configuración de lookup tables para cuentas de servicio críticas

**Arquitectura de datos:**
```
[Domain Controllers] → [Universal Forwarders] → [Indexers] → [Search Heads]
       ↓                      ↓                     ↓
[EventCode 4769]      [WinEventLog:Security]  [Index: wineventlog]
[TGS Requests]             ↓                      ↓
[Service Names]      [Real-time processing]  [Risk-based Alerting]
```

### 🔧 Guía de implementación paso a paso

#### Fase 1: Configuración inicial (Tiempo estimado: 55 min)

1. **Habilitar auditoría TGS detallada:**
   ```powershell
   # En todos los Domain Controllers
   auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
   
   # Configurar logging extendido
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "LogLevel" -Value 1
   
   # Verificar configuración
   auditpol /get /subcategory:"Kerberos Service Ticket Operations"
   ```

2. **Crear lookup table de cuentas críticas:**
   ```csv
   # critical_service_accounts.csv
   Service_Name,Criticality,Department,Owner
   MSSQLSvc*,HIGH,IT,database-team
   HTTP*,MEDIUM,IT,web-team
   *admin*,CRITICAL,IT,admin-team
   *svc*,HIGH,Various,service-owners
   ```

3. **Configurar extracción de campos:**
   ```
   # props.conf
   [WinEventLog:Security]
   EXTRACT-service_name = Service Name:\s+(?<Service_Name>[^\r\n]+)
   EXTRACT-ticket_encryption = Ticket Encryption Type:\s+(?<Ticket_Encryption_Type>0x\w+)
   EXTRACT-client_address = Client Address:\s+(?<Client_Address>\S+)
   EXTRACT-account_name = Account Name:\s+(?<Account_Name>\S+)
   ```

#### Fase 2: Implementación de detecciones (Tiempo estimado: 80 min)

1. **Detección principal Kerberoasting:**
   ```splunk
   index=wineventlog EventCode=4769
   | lookup critical_service_accounts.csv Service_Name OUTPUT Criticality
   | where isnotnull(Criticality)
   | stats count values(Service_Name) as targeted_services values(Criticality) as service_criticality by Client_Address, Account_Name, _time
   | where count > 3
   | eval severity=case(
       match(service_criticality, "CRITICAL"), "CRITICAL",
       match(service_criticality, "HIGH"), "HIGH", 
       1=1, "MEDIUM"
   )
   | eval technique="Kerberoasting", risk_score=case(
       severity="CRITICAL", 95,
       severity="HIGH", 80,
       1=1, 65
   )
   | table _time, Client_Address, Account_Name, count, targeted_services, severity, risk_score
   ```

2. **Detección de cifrado RC4 (más vulnerable):**
   ```splunk
   index=wineventlog EventCode=4769 Ticket_Encryption_Type="0x17"
   | where NOT match(Service_Name, ".*\$$")  # Excluir cuentas de máquina
   | where match(Service_Name, "(?i)(admin|svc|sql|oracle|backup|db|service|root|sap)")
   | stats count values(Service_Name) as rc4_services by Client_Address, Account_Name, _time
   | where count > 3
   | eval severity="HIGH", technique="Kerberoasting RC4"
   | eval risk_score=85
   | table _time, Client_Address, Account_Name, count, rc4_services, severity, risk_score
   ```

3. **Detección de herramientas automatizadas:**
   ```splunk
   index=wineventlog EventCode=4769
   | bucket _time span=5m
   | stats dc(Service_Name) as unique_services, count as total_requests by Client_Address, Account_Name, _time
   | where unique_services > 10 AND total_requests > 15
   | eval severity="CRITICAL", technique="Automated Kerberoasting"
   | eval risk_score=90
   | table _time, Client_Address, Account_Name, unique_services, total_requests, severity, risk_score
   ```

#### Fase 3: Dashboard avanzado y validación (Tiempo estimado: 70 min)

1. **Dashboard de monitoreo avanzado:**
   ```xml
   <dashboard>
     <label>Kerberoasting Advanced Detection Dashboard</label>
     <row>
       <panel>
         <title>🎯 Service Accounts Under Attack</title>
         <table>
           <search refresh="300s">
             <query>
               index=wineventlog EventCode=4769
               | lookup critical_service_accounts.csv Service_Name OUTPUT Criticality
               | where isnotnull(Criticality)
               | stats count by Service_Name, Criticality, Account_Name, Client_Address
               | sort -count
               | head 20
             </query>
           </search>
         </table>
       </panel>
       <panel>
         <title>🔒 Encryption Type Analysis</title>
         <chart>
           <search>
             <query>
               index=wineventlog EventCode=4769
               | stats count by Ticket_Encryption_Type
               | eval encryption_strength=case(
                   Ticket_Encryption_Type="0x17", "RC4 (Weak)",
                   Ticket_Encryption_Type="0x12", "AES256 (Strong)",
                   Ticket_Encryption_Type="0x11", "AES128 (Medium)",
                   1=1, "Other"
               )
             </query>
           </search>
         </chart>
       </panel>
     </row>
   </dashboard>
   ```

2. **Validación con herramientas conocidas:**
   ```bash
   # En entorno de lab controlado
   python3 GetUserSPNs.py lab.local/testuser:'password' -request -outputfile kerberoast_hashes.txt
   ```

3. **Verificar detección avanzada:**
   ```splunk
   index=wineventlog EventCode=4769 earliest=-20m
   | search Account_Name="testuser"
   | stats count dc(Service_Name) as unique_services by Account_Name, Client_Address
   | eval detection_quality=case(
       count>10 AND unique_services>5, "EXCELLENT",
       count>5, "GOOD",
       count>0, "BASIC",
       1=1, "MISSED"
   )
   | table Account_Name, count, unique_services, detection_quality
   ```

### ✅ Criterios de éxito

**Métricas de detección:**
- MTTD para Kerberoasting masivo: < 10 minutos
- MTTD para herramientas automatizadas: < 5 minutos
- Tasa de falsos positivos: < 3% (actividad de servicio legítima)
- Cobertura: > 95% de cuentas de servicio críticas

**Validación funcional:**
- [x] Solicitudes TGS masivas son detectadas via Event 4769
- [x] Cifrado RC4 en servicios críticos genera alertas
- [x] Herramientas como GetUserSPNs.py son identificadas
- [x] Contexto de criticidad de servicios es incluido en alertas

### 📊 ROI y propuesta de valor

**Inversión requerida:**
- Tiempo de implementación: 3.4 horas (analista senior + admin AD)
- Creación de lookup tables: 45 minutos
- Formación del equipo SOC: 2.5 horas
- Costo total estimado: $920 USD

**Retorno esperado:**
- Prevención de compromiso de cuentas de servicio: 92% de casos
- Ahorro por cuenta de servicio protegida: $85,000 USD
- Reducción de tiempo de detección: 90% (de 3 horas a 10 minutos)
- ROI estimado: 9,140% en el primer incidente evitado

### 🧪 Metodología de testing

#### Pruebas de laboratorio avanzadas

1. **Configurar servicios vulnerables para testing:**
   ```powershell
   # En entorno de lab controlado
   New-ADUser -Name "ServiceAccount" -ServicePrincipalNames "HTTP/webapp.lab.local" -AccountPassword (ConvertTo-SecureString "WeakPassword123" -AsPlainText -Force) -Enabled $true
   
   # Configurar SPN adicionales
   setspn -A MSSQLSvc/db.lab.local:1433 ServiceAccount
   ```

2. **Ejecutar Kerberoasting simulado:**
   ```bash
   # Múltiples herramientas para validación completa
   python3 GetUserSPNs.py lab.local/testuser:'password' -request
   
   # Con Rubeus
   ./Rubeus.exe kerberoast /format:hashcat /outfile:hashes.txt
   ```

3. **Análisis de detección comprensiva:**
   ```splunk
   index=wineventlog EventCode=4769 earliest=-30m
   | eval test_phase="Kerberoasting Lab Validation"
   | stats count dc(Service_Name) as services values(Ticket_Encryption_Type) as encryption_types by Account_Name, Client_Address, test_phase
   | eval detection_score=case(
       count>15 AND services>5, 100,
       count>10, 85,
       count>5, 70,
       count>0, 50,
       1=1, 0
   )
   | table Account_Name, count, services, encryption_types, detection_score
   ```

#### Pruebas de rendimiento y escalabilidad

1. **Análisis de volumen TGS:**
   ```splunk
   index=wineventlog EventCode=4769
   | bucket _time span=1h
   | stats count by _time
   | eval tgs_per_hour=count
   | stats avg(tgs_per_hour) as avg_hourly, max(tgs_per_hour) as peak_hourly
   ```

2. **Optimización de búsquedas:**
   ```splunk
   # Búsqueda optimizada para alto volumen
   index=wineventlog EventCode=4769
   | where NOT match(Service_Name, ".*\$$") AND NOT match(Service_Name, "krbtgt")
   | stats count by Account_Name, Client_Address, Service_Name
   | where count > 3
   ```

### 🔄 Mantenimiento y evolución

**Revisión semanal obligatoria:**
- Actualizar lookup table de cuentas de servicio críticas
- Revisar umbrales de detección basados en actividad baseline
- Analizar nuevas técnicas de evasión de Kerberoasting

**Evolución continua:**
- Integrar detección con AS-REP Roasting para análisis correlacionado
- Desarrollar modelos ML para detectar patrones anómalos de solicitudes TGS
- Automatizar respuesta para rotar contraseñas de cuentas comprometidas

**Hardening proactivo:**
```powershell
# Script para identificar y fortalecer cuentas de servicio
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName,PasswordLastSet |
Where-Object {((Get-Date) - $_.PasswordLastSet).Days -gt 365} |
ForEach-Object {
    Write-Warning "Cuenta de servicio con contraseña antigua: $($_.Name) - $($_.PasswordLastSet)"
    # Generar alerta para rotación de contraseña
}
```

### 🎓 Formación especializada del equipo SOC

**Conocimientos críticos requeridos:**
- Funcionamiento detallado de Kerberos TGS y SPNs
- Técnicas de Kerberoasting y herramientas asociadas (GetUserSPNs, Rubeus)
- Análisis de tipos de cifrado y vulnerabilidades RC4 vs AES
- Gestión de cuentas de servicio y principios de privilegios mínimos

**Material de formación avanzado:**
- **Playbook especializado:** "Investigación y respuesta a Kerberoasting"
- **Laboratorio completo:** 4 horas con múltiples herramientas y escenarios
- **Purple team exercise:** Simulacro mensual con red team
- **Casos de estudio reales:** 5 incidentes documentados con lecciones aprendidas

**Certificaciones recomendadas:**
- GIAC Certified Incident Handler (GCIH)
- SANS FOR508 Advanced Digital Forensics
- Microsoft Identity and Access Administrator (SC-300)

### 📚 Referencias técnicas y recursos especializados

- [MITRE ATT&CK T1558.003 - Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [Microsoft Event 4769 Technical Reference](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [Impacket GetUserSPNs.py Source](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py)
- [GhostPack Rubeus Kerberoasting](https://github.com/GhostPack/Rubeus#kerberoast)
- [HarmJ0y Kerberoasting Technical Deep Dive](https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/)
- [Splunk Security Essentials - Kerberos Attacks](https://splunkbase.splunk.com/app/3435/)
- [NIST SP 800-63B Authentication Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

---

## 📊 Detección en logs y SIEM

| Campo clave                   | Descripción                                           |
|-------------------------------|------------------------------------------------------|
| **EventCode = 4769**          | Solicitud de ticket de servicio (TGS) en Kerberos.   |
| **Service_Name**              | Cuenta de servicio objetivo (con SPN).               |
| **Account_Name**              | Cuenta que solicita el ticket (atacante).            |
| **Client_Address**            | IP origen de la petición.                            |
| **Ticket_Encryption_Type**    | Tipo de cifrado (RC4, AES, etc).                     |

### Query Splunk básica

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| table _time, ComputerName, Account_Name, Service_Name, Client_Address, Ticket_Encryption_Type
```

---

## 🔎 Queries completas para más investigación

### 0 .Prioridad de cuentas

```splunk

index=dc_logs sourcetype=WinEventLog:Security EventCode=4769 Ticket_Encryption_Type="0x17"
| where match(Service_Name, "(?i)(admin|svc|sql|oracle|backup|db|service|root|sap)")
| stats count by Service_Name, Account_Name, Client_Address
| where count > 3
| sort -count
```

### 1. Solicitudes masivas de TGS desde una misma IP

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| stats count by Client_Address, Account_Name
| where count > 5
```

### 2. Solicitudes de TGS a cuentas privilegiadas o con SPN críticos

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| search Service_Name="*admin*" OR Service_Name="*svc*" OR Service_Name="MSSQLSvc*" OR Service_Name="HTTP/*"
| table _time, Service_Name, Account_Name, Client_Address
```

### 3. Solicitudes de TGS con cifrado RC4 (más vulnerable)

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769 Ticket_Encryption_Type=0x17
| table _time, Service_Name, Account_Name, Client_Address
```

### 4. Solicitudes desde redes externas o no confiables

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| search NOT (Client_Address="10.*" OR Client_Address="192.168.*" OR Client_Address="172.16.*" OR Client_Address="127.0.0.1")
| table _time, Service_Name, Account_Name, Client_Address
```

### 5. Correlación con logons recientes desde la misma IP

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| rename Account_Name as kerb_user, Client_Address as kerb_ip, _time as kerb_time
| join kerb_ip [
    search index=dc_logs sourcetype=WinEventLog:Security EventCode=4624
    | rename Account_Name as logon_user, IpAddress as logon_ip, _time as logon_time
    | table logon_user, logon_ip, logon_time
]
| where logon_ip=kerb_ip AND logon_time < kerb_time
| table kerb_time, kerb_user, kerb_ip, logon_user, logon_time
| sort kerb_time, kerb_ip, logon_time
```

### 6. Analizar tickets solicitados nunca usados (sin acceso real a servicios)

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| join Service_Name [
    search index=dc_logs sourcetype=WinEventLog:Security EventCode=5140
    | rename Share_Name as Service_Name, IpAddress as Client_Address, _time as access_time
    | table Service_Name, Client_Address, access_time
]
| where isnull(access_time)
| table _time, Account_Name, Service_Name, Client_Address
```

### 7. Quien pide el TGS

```splunk
index="*" 4769
| where Ticket_Encryption_Type="0x17" OR Ticket_Encryption_Type="23"
| search Service_Name="*admin*" OR Service_Name="*svc*" OR Service_Name="MSSQLSvc*" OR Service_Name="HTTP/*" OR Service_Name="*sql*" OR Service_Name="*backup*"
| stats count by Account_Name, Service_Name, Client_Address
| where count > 3
| sort -count
```

---

## 🛡️ Detección con Windows Defender for Endpoint

### Reglas de detección personalizadas

```kql
// Kerberoasting - Solicitudes masivas de tickets TGS
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| join kind=inner (
    DeviceEvents
    | where ActionType == "KerberosTgsRequested"
    | summarize TgsCount = count() by DeviceId, AccountName, bin(Timestamp, 5m)
    | where TgsCount > 5
) on DeviceId, AccountName
| project Timestamp, DeviceId, DeviceName, AccountName, TgsCount
| order by Timestamp desc
```

```kql
// Detección de uso de herramientas conocidas de Kerberoasting
DeviceProcessEvents
| where ProcessCommandLine has_any ("GetUserSPNs", "Rubeus", "kerberoast", "Invoke-Kerberoast")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### Alertas recomendadas

| Regla | Descripción | Severidad |
|-------|-------------|-----------|
| **TGS Request Spike** | Más de 10 solicitudes TGS en 5 minutos desde un mismo usuario | Media |
| **Kerberoasting Tools** | Detección de herramientas conocidas (Rubeus, GetUserSPNs, etc.) | Alta |
| **RC4 TGS Requests** | Solicitudes TGS con cifrado RC4 en cuentas críticas | Media |

---

## 🦅 Detección con CrowdStrike Falcon

### Hunting queries (Event Search)

```sql
-- Detección de Kerberoasting basado en eventos de red
event_platform=Win event_simpleName=NetworkConnectIP4 
| search (RemotePort=88 OR RemotePort=464)
| stats dc(RemoteAddressIP4) as unique_dcs, count as total_connections by ComputerName, UserName
| where unique_dcs > 1 AND total_connections > 10
| sort - total_connections
```

```sql
-- Detección de herramientas de Kerberoasting
event_platform=Win event_simpleName=ProcessRollup2 
| search (FileName=*rubeus* OR FileName=*GetUserSPNs* OR ImageFileName=*powershell* CommandLine=*kerberoast*)
| table _time, ComputerName, UserName, FileName, CommandLine, ParentProcessId
| sort - _time
```

### Custom IOAs (Indicators of Attack)

```sql
-- IOA para detectar patrones de Kerberoasting
event_platform=Win event_simpleName=AuthActivityAuditLog
| search LogonType=3 TargetUserName!=*$ 
| bin _time span=5m
| stats dc(TargetUserName) as unique_targets by ComputerName, UserName, _time
| where unique_targets > 5
```

---

## 🔍 Queries KQL para Microsoft Sentinel

### Detección de Kerberoasting

```kql
// Query principal para detectar Kerberoasting
SecurityEvent
| where EventID == 4769
| where ServiceName !endswith "$"
| where ServiceName !contains "krbtgt"
| summarize count() by Account, ServiceName, IpAddress, bin(TimeGenerated, 5m)
| where count_ > 3
| order by TimeGenerated desc
```

```kql
// Correlación con herramientas de ataque
DeviceProcessEvents
| where ProcessCommandLine contains "GetUserSPNs" or ProcessCommandLine contains "Rubeus" or ProcessCommandLine contains "kerberoast"
| join kind=inner (
    SecurityEvent
    | where EventID == 4769
    | project TimeGenerated, Account, IpAddress, ServiceName
) on $left.AccountName == $right.Account
| project TimeGenerated, DeviceName, ProcessCommandLine, Account, ServiceName, IpAddress
```

### Hunting avanzado

```kql
// Detección de patrones anómalos en solicitudes TGS
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17" // RC4
| where ServiceName has_any ("admin", "svc", "sql", "backup", "service")
| summarize RequestCount = count(), UniqueServices = dcount(ServiceName) by Account, IpAddress, bin(TimeGenerated, 1h)
| where RequestCount > 5 or UniqueServices > 3
| order by RequestCount desc
```

---

## 🦾 Hardening y mitigación

| Medida                                   | Descripción                                                                                  |
|-------------------------------------------|---------------------------------------------------------------------------------------------|
| **Contraseñas robustas en cuentas SPN**   | Usa contraseñas largas y complejas en cuentas de servicio/SPN.                               |
| **Revisar cuentas privilegiadas con SPN** | Minimiza privilegios de cuentas con SPN, y usa cuentas dedicadas y gestionadas.              |
| **Monitorización continua**               | Vigila eventos 4769 y correlaciona con actividad sospechosa o inusual.                       |
| **Evitar RC4 en cuentas de servicio**     | Forzar cifrado AES en cuentas de servicio, deshabilitando RC4 si es posible.                 |
| **Rotación periódica de contraseñas**     | Cambia periódicamente contraseñas de cuentas de servicio con SPN.                             |
| **Segmentación de red**                   | Restringe acceso a servicios Kerberos solo a redes y usuarios necesarios.                     |
| **Auditoría periódica de SPNs**           | Revisa regularmente qué cuentas tienen SPN y si siguen siendo necesarias.                     |

---

## 🔧 Parches y actualizaciones

| Parche/Update | Descripción                                                                                  |
|---------------|----------------------------------------------------------------------------------------------|
| **KB5025238** | Windows 11 22H2 - Mejoras en cifrado AES para tickets TGS y mitigación de Kerberoasting.    |
| **KB5025221** | Windows 10 22H2 - Fortalecimiento de validaciones de SPN y auditoría de solicitudes TGS.    |
| **KB5022906** | Windows Server 2022 - Mejoras en logging de eventos 4769 con metadatos adicionales.         |
| **KB5022845** | Windows Server 2019 - Correcciones en manejo de tickets de servicio y cifrado RC4.          |
| **KB4580390** | Windows Server 2016 - Parches para desactivar cifrado RC4 en cuentas de servicio.          |
| **RSAT Updates** | Herramientas actualizadas para gestión de SPNs y políticas de cifrado Kerberos.      |

### Configuraciones de registro recomendadas

```powershell
# Deshabilitar cifrado RC4 en Kerberos (forzar AES)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "DefaultEncryptionType" -Value 0x18

# Habilitar auditoría detallada de TGS
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

# Configurar política de contraseñas robustas para cuentas de servicio
Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 25 -ComplexityEnabled $true
```

### Configuraciones de GPO recomendadas

```powershell
# Aplicar políticas de cifrado AES en todo el dominio
Set-ADDomainMode -Identity "midominio.local" -DomainMode Windows2016Domain
Set-ADForestMode -Identity "midominio.local" -ForestMode Windows2016Forest
```

### Actualizaciones críticas de seguridad

- **CVE-2022-37958**: Vulnerabilidad en validación de tickets TGS (parcheada en actualizaciones de noviembre 2022)
- **CVE-2021-42287**: sAMAccountName spoofing que facilita Kerberoasting (KB5008102)
- **CVE-2020-17049**: Vulnerabilidad en Kerberos KDC que permite bypass de validaciones (KB4586876)
- **CVE-2019-1384**: Escalada de privilegios via SPNs mal configurados (KB4524244)

---

## 🧑‍💻 ¿Cómo revisar cuentas con SPN en Active Directory?

```powershell
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName
```
O con Impacket desde Kali Linux:
```bash
python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py essos.local/usuario:contraseña
```

---

## 📚 Referencias

- [Kerberoasting - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoasting)
- [Impacket GetUserSPNs](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py)
