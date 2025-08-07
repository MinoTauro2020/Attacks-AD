# 🛑 Enumeración DNS en Active Directory

---

## 📝 ¿Qué es la enumeración DNS?

| Concepto      | Descripción                                                                                                      |
|---------------|-----------------------------------------------------------------------------------------------------------------|
| **Definición**| Técnica de reconocimiento que permite a un atacante obtener información detallada sobre la infraestructura DNS del dominio, incluyendo subdominios, registros de servicio y configuraciones que revelan la topología de la red. |
| **Requisito** | Acceso de red al puerto 53 (DNS) y conocimiento del dominio objetivo. |

---

## 🛠️ ¿Cómo funciona el ataque?

| Fase                | Acción                                                                                                 |
|---------------------|--------------------------------------------------------------------------------------------------------|
| **Descubrimiento**  | El atacante identifica servidores DNS y dominios objetivo mediante consultas básicas.                  |
| **Enumeración pasiva** | Utiliza herramientas como dnsrecon para obtener registros DNS sin generar tráfico sospechoso.      |
| **Enumeración activa** | Usa dnsenum y dig para realizar consultas directas y transferencias de zona.                       |
| **Reconocimiento**  | Mapea subdominios, servicios (SRV), controladores de dominio y infraestructura de red.              |

---

## 💻 Ejemplo práctico

### DNSRecon - Reconocimiento completo de DNS
```bash
# Enumeración básica del dominio
dnsrecon -d example.com

# Enumeración con transferencia de zona
dnsrecon -d example.com -a

# Búsqueda de subdominios con diccionario
dnsrecon -d example.com -D /usr/share/wordlists/dnsmap.txt -t brt

# Enumeración de registros específicos de AD
dnsrecon -d example.com -t srv
```

### DNSEnum - Enumeración exhaustiva
```bash
# Enumeración completa con transferencia de zona
dnsenum example.com

# Enumeración con diccionario personalizado
dnsenum --enum example.com -f /usr/share/wordlists/subdomains.txt

# Enumeración con fuerza bruta
dnsenum --noreverse --dnsserver 192.168.1.10 example.com
```

### Dig - Consultas DNS específicas
```bash
# Consultar registros SOA
dig example.com SOA

# Enumerar controladores de dominio
dig _ldap._tcp.example.com SRV

# Consultar registros de servicios Kerberos
dig _kerberos._tcp.example.com SRV

# Intentar transferencia de zona
dig @192.168.1.10 example.com AXFR

# Consultar registros MX (servidores de correo)
dig example.com MX

# Buscar registros TXT (políticas SPF, DKIM)
dig example.com TXT
```

---

## 📊 Detección en logs y SIEM

| Campo clave                   | Descripción                                                                                      |
|-------------------------------|-------------------------------------------------------------------------------------------------|
| **Query Type**                | Tipo de consulta DNS (A, AAAA, SRV, TXT, AXFR, etc.).                                          |
| **Query Name**                | Nombre del dominio o subdominio consultado.                                                     |
| **Source IP**                 | IP origen de la consulta DNS.                                                                   |
| **Response Code**             | Código de respuesta DNS (NOERROR, NXDOMAIN, REFUSED, etc.).                                     |
| **Query Count**               | Número de consultas desde la misma fuente.                                                      |

### Ejemplo de eventos relevantes

```
Query Type: AXFR
Query Name: example.com
Source IP: 192.168.57.151
Response Code: REFUSED

Query Type: SRV
Query Name: _ldap._tcp.example.com
Source IP: 192.168.57.151
Response Code: NOERROR
```

---

## 🔎 Queries Splunk para hunting

### 1. Detección de intentos de transferencia de zona

```splunk
index=dns_logs query_type=AXFR
| stats count values(query_name) as dominios_consultados by src_ip, _time
| where count > 1
| eval severity="HIGH", technique="DNS Zone Transfer Attempt"
| table _time, src_ip, count, dominios_consultados, severity
```

### 2. Detección de enumeración masiva de subdominios

```splunk
index=dns_logs 
| bucket _time span=10m
| stats count as total_consultas, dc(query_name) as dominios_unicos by src_ip, _time
| where dominios_unicos > 50 OR total_consultas > 100
| eval severity="MEDIUM", technique="DNS Subdomain Enumeration"
| table _time, src_ip, total_consultas, dominios_unicos, severity
```

### 3. Detección de consultas a registros de servicios de AD

```splunk
index=dns_logs (query_name="*_ldap._tcp*" OR query_name="*_kerberos._tcp*" OR query_name="*_gc._tcp*")
| stats count values(query_name) as servicios_ad by src_ip, _time
| where count > 5
| eval severity="MEDIUM", technique="AD Service Enumeration"
| table _time, src_ip, count, servicios_ad, severity
```

### 4. Correlación con herramientas de enumeración DNS

```splunk
index=endpoint_logs (process_name="dnsrecon*" OR process_name="dnsenum*" OR process_name="dig*")
| rex field=command_line "(?<target_domain>[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
| join src_ip [
    search index=dns_logs 
    | eval src_ip=source_ip
    | table _time, src_ip, query_name, query_type
]
| table _time, src_ip, process_name, command_line, target_domain, query_name, query_type
```

---

## ⚡️ Alertas recomendadas

| Alerta                                  | Descripción                                                                                 |
|------------------------------------------|---------------------------------------------------------------------------------------------|
| **Alerta 1**                            | Intentos de transferencia de zona (AXFR) desde IPs no autorizadas.                          |
| **Alerta 2**                            | Más de 50 dominios únicos consultados desde la misma IP en 10 minutos.                     |
| **Alerta 3**                            | Consultas masivas a registros SRV de servicios Active Directory.                            |

---

## 🛡️ Detección con Windows Defender for Endpoint

### Reglas de detección personalizadas

```kql
// DNS Enumeration - Múltiples consultas desde misma fuente
DeviceNetworkEvents
| where RemotePort == 53
| where ActionType == "ConnectionSuccess"
| summarize QueryCount = count(), UniqueDomains = dcount(RemoteUrl) by RemoteIP, bin(Timestamp, 10m)
| where QueryCount > 100 or UniqueDomains > 50
| order by QueryCount desc
```

```kql
// Detección de herramientas de enumeración DNS
DeviceProcessEvents
| where ProcessCommandLine has_any ("dnsrecon", "dnsenum", "dig") 
| where ProcessCommandLine has_any ("-d", "-t", "AXFR", "SRV", "-f")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

```kql
// Detección de consultas DNS a servicios de Active Directory
DeviceNetworkEvents
| where RemotePort == 53
| where RemoteUrl has_any ("_ldap._tcp", "_kerberos._tcp", "_gc._tcp", "_kpasswd._tcp")
| summarize ADServiceQueries = count() by DeviceId, RemoteIP, AccountName, bin(Timestamp, 5m)
| where ADServiceQueries > 10
| order by ADServiceQueries desc
```

### Alertas recomendadas

| Regla | Descripción | Severidad |
|-------|-------------|-----------|
| **DNS Enumeration Spike** | Más de 100 consultas DNS o 50 dominios únicos en 10 minutos | Media |
| **DNS Enum Tools** | Detección de herramientas de enumeración DNS | Alta |
| **AD Service Discovery** | Múltiples consultas a servicios de Active Directory | Media |

---

## 🦅 Detección con CrowdStrike Falcon

### Hunting queries (Event Search)

```sql
-- Detección de enumeración DNS masiva
event_platform=Win event_simpleName=DnsRequest
| bin _time span=10m
| stats count as dns_queries, dc(DomainName) as unique_domains by ComputerName, UserName, _time
| where dns_queries > 200 OR unique_domains > 100
| sort - dns_queries
```

```sql
-- Detección de herramientas de enumeración DNS
event_platform=Win event_simpleName=ProcessRollup2 
| search (CommandLine=*dnsrecon* OR CommandLine=*dnsenum* OR CommandLine=*dig* AND CommandLine=*AXFR*)
| table _time, ComputerName, UserName, FileName, CommandLine, SHA256HashData
| sort - _time
```

```sql
-- Detección de consultas a registros SRV de Active Directory
event_platform=Win event_simpleName=DnsRequest
| search DomainName=*_ldap._tcp* OR DomainName=*_kerberos._tcp* OR DomainName=*_gc._tcp*
| bin _time span=5m
| stats count as ad_srv_queries by ComputerName, UserName, DomainName, _time
| where ad_srv_queries > 5
| sort - ad_srv_queries
```

### Custom IOAs (Indicators of Attack)

```sql
-- IOA para detectar transferencia de zona DNS
event_platform=Win event_simpleName=DnsRequest
| search QueryType=AXFR
| stats count by ComputerName, UserName, DomainName
| where count > 0
```

---

## 🔍 Queries KQL para Microsoft Sentinel

### Detección de DNS Enumeration

```kql
// Query principal para detectar enumeración DNS
DnsEvents
| where QueryType in ("AXFR", "ANY") or (QueryType == "SRV" and Name contains "_")
| summarize QueryCount = count(), UniqueQueries = dcount(Name), QueryList = make_set(Name) by ClientIP, bin(TimeGenerated, 10m)
| where QueryCount > 20 or UniqueQueries > 15
| order by QueryCount desc
```

```kql
// Correlación con herramientas de enumeración
DeviceProcessEvents
| where ProcessCommandLine contains "dnsrecon" or ProcessCommandLine contains "dnsenum" or (ProcessCommandLine contains "dig" and ProcessCommandLine contains "AXFR")
| join kind=inner (
    DnsEvents
    | project TimeGenerated, ClientIP, Name, QueryType
) on $left.DeviceName == $right.ClientIP
| project TimeGenerated, DeviceName, ProcessCommandLine, ClientIP, Name, QueryType
```

### Hunting avanzado

```kql
// Detección de enumeración de servicios de Active Directory via DNS
DnsEvents
| where Name has_any ("_ldap._tcp", "_kerberos._tcp", "_gc._tcp", "_kpasswd._tcp")
| summarize ADServiceQueries = count(), ServiceTypes = make_set(Name) by ClientIP, bin(TimeGenerated, 15m)
| where ADServiceQueries > 5
| join kind=inner (
    SecurityEvent
    | where EventID == 4624 and LogonType == 3  // Network logon
    | project TimeGenerated, IpAddress, TargetUserName
) on $left.ClientIP == $right.IpAddress
| project TimeGenerated, ClientIP, ADServiceQueries, ServiceTypes, TargetUserName
| order by ADServiceQueries desc
```

```kql
// Detección de enumeración de subdominios desde redes externas
DnsEvents
| where ClientIP !startswith "10." and ClientIP !startswith "192.168." and ClientIP !startswith "172."
| where Name endswith ".local" or Name endswith ".domain.com"  // Ajustar según dominio
| summarize ExternalQueries = count(), Subdomains = make_set(Name) by ClientIP, bin(TimeGenerated, 30m)
| where ExternalQueries > 10
| order by ExternalQueries desc
```

---

## 🦾 Hardening y mitigación

| Medida                                   | Descripción                                                                                 |
|-------------------------------------------|---------------------------------------------------------------------------------------------|
| **Deshabilitar transferencias de zona**  | Configura DNS para denegar transferencias AXFR a hosts no autorizados.                     |
| **Configurar DNS forwarders seguros**    | Utiliza forwarders DNS confiables y evita resolución recursiva pública.                   |
| **Implementar rate limiting**             | Limita el número de consultas DNS por IP/cliente en ventanas de tiempo.                    |
| **Filtrado de consultas sensibles**      | Bloquea o registra consultas a registros críticos desde fuentes no autorizadas.           |
| **Segmentación DNS**                      | Separa DNS interno del externo y restringe acceso según red de origen.                    |
| **Monitorización avanzada**               | Implementa logging detallado de consultas DNS y alertas automatizadas.                    |
| **Configurar DNS sobre HTTPS/TLS**        | Usa DoH/DoT para cifrar consultas DNS y prevenir interceptación.                          |
| **Validación DNSSEC**                     | Implementa DNSSEC para validar integridad de respuestas DNS.                              |

---

## 🔧 Parches y actualizaciones

| Parche/Update | Descripción                                                                                  |
|---------------|----------------------------------------------------------------------------------------------|
| **KB5025238** | Windows 11/10 - Mejoras en seguridad DNS y protección contra enumeración no autorizada.     |
| **KB5022906** | Windows Server 2022 - Fortalecimiento de servicios DNS y auditoría de consultas.            |
| **KB5022845** | Windows Server 2019 - Correcciones en configuraciones DNS por defecto y rate limiting.      |
| **KB4580390** | Windows Server 2016 - Parches críticos para limitar enumeración vía DNS.                    |
| **KB5014754** | Patch para vulnerabilidades DNS cache poisoning (CVE-2022-21984).                           |
| **DNS Security Updates** | Actualizaciones específicas del servicio DNS para mejor autenticación y logging.   |

### Configuraciones de registro críticas

```powershell
# Deshabilitar transferencias de zona no autorizadas
Set-DnsServerPrimaryZone -Name "example.com" -SecureSecondaries TransferToZoneNameServer

# Configurar rate limiting para consultas DNS
Set-DnsServerRRL -ResponsesPerSec 10 -ErrorsPerSec 10 -WindowInSec 5

# Habilitar auditoría detallada de DNS
Set-DnsServerDiagnostics -All $true
Set-DnsServerDiagnostics -EventLogLevel 4

# Configurar DNS scavenging para limpiar registros obsoletos
Set-DnsServerScavenging -ScavengingState $true -ScavengingInterval 7:00:00:00

# Restringir acceso recursivo
Set-DnsServerRecursion -Enable $false -AdditionalTimeout 10
```

### Configuraciones de GPO críticas

```powershell
# Configurar políticas DNS restrictivas via GPO
# Computer Configuration\Policies\Administrative Templates\Network\DNS Client:
# "Turn off multicast name resolution" = Enabled
# "Configure NetBIOS settings" = Disable NetBIOS over TCP/IP

# Configurar firewall para DNS
New-NetFirewallRule -DisplayName "Block External DNS Queries" -Direction Outbound -Protocol UDP -RemotePort 53 -RemoteAddress "Internet" -Action Block
New-NetFirewallRule -DisplayName "Allow Internal DNS" -Direction Inbound -Protocol UDP -LocalPort 53 -RemoteAddress "LocalSubnet" -Action Allow
```

### Scripts de validación y detección

```powershell
# Verificar configuraciones DNS seguras
function Test-DNSSecurity {
    # Verificar transferencias de zona
    $zones = Get-DnsServerZone | Where-Object {$_.ZoneType -eq "Primary"}
    foreach ($zone in $zones) {
        $zoneConfig = Get-DnsServerPrimaryZone -Name $zone.ZoneName
        if ($zoneConfig.SecureSecondaries -eq "TransferToAnyServer") {
            Write-Host "✗ RIESGO: Zona $($zone.ZoneName) permite transferencias a cualquier servidor" -ForegroundColor Red
        } else {
            Write-Host "✓ Zona $($zone.ZoneName) tiene transferencias restringidas" -ForegroundColor Green
        }
    }
    
    # Verificar rate limiting
    $rrl = Get-DnsServerRRL
    if ($rrl.ResponsesPerSec -gt 0) {
        Write-Host "✓ Rate limiting DNS habilitado: $($rrl.ResponsesPerSec) respuestas/segundo" -ForegroundColor Green
    } else {
        Write-Host "✗ Rate limiting DNS DESHABILITADO" -ForegroundColor Red
    }
    
    # Verificar auditoría
    $diagnostics = Get-DnsServerDiagnostics
    if ($diagnostics.EnableLogFileRollover -and $diagnostics.EventLogLevel -gt 0) {
        Write-Host "✓ Auditoría DNS habilitada (Nivel: $($diagnostics.EventLogLevel))" -ForegroundColor Green
    } else {
        Write-Host "✗ Auditoría DNS DESHABILITADA" -ForegroundColor Red
    }
    
    # Verificar recursión
    $recursion = Get-DnsServerRecursion
    if ($recursion.Enable -eq $false) {
        Write-Host "✓ Recursión DNS deshabilitada" -ForegroundColor Green
    } else {
        Write-Host "⚠ Recursión DNS habilitada - revisar si es necesaria" -ForegroundColor Yellow
    }
}

# Detectar consultas DNS sospechosas en tiempo real
function Monitor-DNSQueries {
    Get-WinEvent -FilterHashtable @{LogName='DNS Server'; ID=256,257} -MaxEvents 100 |
    Where-Object {$_.Message -like "*AXFR*" -or $_.Message -like "*_ldap*" -or $_.Message -like "*_kerberos*"} |
    ForEach-Object {
        Write-Warning "Consulta DNS sospechosa: $($_.Message)"
    }
}

# Auditar configuración de zonas DNS
function Audit-DNSZones {
    $zones = Get-DnsServerZone
    foreach ($zone in $zones) {
        Write-Host "Zona: $($zone.ZoneName)" -ForegroundColor Yellow
        Write-Host "  Tipo: $($zone.ZoneType)" -ForegroundColor Cyan
        Write-Host "  Archivo: $($zone.ZoneFile)" -ForegroundColor Cyan
        
        if ($zone.ZoneType -eq "Primary") {
            $primary = Get-DnsServerPrimaryZone -Name $zone.ZoneName
            Write-Host "  Transferencias seguras: $($primary.SecureSecondaries)" -ForegroundColor Cyan
            
            if ($primary.SecureSecondaries -eq "TransferToAnyServer") {
                Write-Host "  ✗ RIESGO: Permite transferencias a cualquier servidor" -ForegroundColor Red
            }
        }
        
        # Verificar registros sensibles
        $records = Get-DnsServerResourceRecord -ZoneName $zone.ZoneName | 
                   Where-Object {$_.RecordType -in @("SRV", "TXT") -or $_.HostName -like "*_*"}
        
        if ($records.Count -gt 0) {
            Write-Host "  Registros sensibles encontrados: $($records.Count)" -ForegroundColor Yellow
        }
    }
}

# Ejecutar auditoría completa
Test-DNSSecurity
Monitor-DNSQueries
Audit-DNSZones
```

### Actualizaciones críticas de seguridad

- **CVE-2021-24078**: Vulnerabilidad en servidor DNS de Windows (KB5000802)
- **CVE-2022-21984**: DNS cache poisoning vulnerability (KB5014754)
- **CVE-2020-1350**: SIGRed - Ejecución remota de código en DNS (KB4569509)
- **CVE-2019-0708**: BlueKeep afecta también servicios auxiliares DNS (KB4500331)

### Herramientas de monitorización avanzadas

```powershell
# Script para detectar enumeración DNS en tiempo real
$dnsEvents = Get-WinEvent -FilterHashtable @{LogName='DNS Server'; ID=256} -MaxEvents 200
$dnsEvents | Group-Object Properties[7] | Where-Object Count -gt 20 | 
ForEach-Object {
    Write-Warning "IP con múltiples consultas DNS: $($_.Name) - $($_.Count) consultas"
}

# Monitorear uso de herramientas de enumeración
Get-Process | Where-Object {$_.ProcessName -match "(dnsrecon|dnsenum|dig|nslookup)"} |
ForEach-Object {
    Write-Warning "Herramienta de enumeración DNS detectada: $($_.ProcessName) PID:$($_.Id)"
    $cmd = (Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine
    Write-Host "Comando: $cmd" -ForegroundColor Yellow
}

# Alert para intentos de transferencia de zona
Get-WinEvent -FilterHashtable @{LogName='DNS Server'; ID=6001,6002} -MaxEvents 50 |
Where-Object {$_.Message -like "*AXFR*"} |
ForEach-Object {
    Write-Alert "Intento de transferencia de zona desde: $($_.Properties[0].Value)"
}

# Detectar consultas a registros SRV de AD
Get-WinEvent -FilterHashtable @{LogName='DNS Server'; ID=256} -MaxEvents 100 |
Where-Object {$_.Message -like "*_ldap._tcp*" -or $_.Message -like "*_kerberos._tcp*"} |
Group-Object Properties[7] | Where-Object Count -gt 5 |
ForEach-Object {
    Write-Warning "IP consultando servicios AD via DNS: $($_.Name) - $($_.Count) consultas"
}
```

---

## 🚨 Respuesta ante incidentes

### Procedimientos de respuesta inmediata

1. **Identificación del ataque de enumeración DNS:**
   - Confirmar consultas masivas DNS desde IP específica
   - Verificar intentos de transferencia de zona (AXFR)
   - Correlacionar con consultas a servicios de Active Directory

2. **Contención inmediata:**
   - Bloquear la IP origen del ataque en firewalls DNS
   - Restringir temporalmente transferencias de zona
   - Habilitar rate limiting si no estaba activado

3. **Análisis de impacto:**
   - Determinar qué información DNS fue enumerada
   - Evaluar la sensibilidad de los subdominios/servicios expuestos
   - Verificar si hubo transferencias de zona exitosas

4. **Investigación forense:**
   - Buscar herramientas de enumeración en el endpoint origen
   - Analizar logs DNS para identificar patrones de consulta
   - Revisar configuraciones DNS para determinar exposición

5. **Recuperación y endurecimiento:**
   - Implementar configuraciones DNS más restrictivas
   - Configurar monitoreo avanzado de consultas DNS
   - Revisar y actualizar zonas DNS según principio de menor exposición

### Scripts de respuesta automatizada

```powershell
# Script de respuesta para enumeración DNS
function Respond-DNSEnumerationAttack {
    param($AttackerIP, $QueriedDomains, $AffectedServers)
    
    # Bloquear IP atacante
    New-NetFirewallRule -DisplayName "Block DNS Enumeration IP" -Direction Inbound -RemoteAddress $AttackerIP -Action Block
    
    # Restringir transferencias de zona temporalmente
    $zones = Get-DnsServerZone | Where-Object {$_.ZoneType -eq "Primary"}
    foreach ($zone in $zones) {
        Set-DnsServerPrimaryZone -Name $zone.ZoneName -SecureSecondaries TransferToZoneNameServer
        Write-EventLog -LogName "DNS Server" -Source "DNSSecurity" -EventId 9003 -Message "Zone transfer restricted for $($zone.ZoneName) after enumeration attack from $AttackerIP"
    }
    
    # Habilitar rate limiting si no está activado
    $rrl = Get-DnsServerRRL
    if ($rrl.ResponsesPerSec -eq 0) {
        Set-DnsServerRRL -ResponsesPerSec 10 -ErrorsPerSec 5 -WindowInSec 5
        Write-EventLog -LogName "DNS Server" -Source "DNSSecurity" -EventId 9004 -Message "DNS rate limiting enabled after enumeration attack from $AttackerIP"
    }
    
    # Auditar dominios consultados
    foreach ($domain in $QueriedDomains) {
        Write-EventLog -LogName "DNS Server" -Source "DNSSecurity" -EventId 9005 -Message "Domain enumerated: $domain by $AttackerIP"
        
        # Verificar si el dominio contiene información sensible
        if ($domain -like "*_ldap*" -or $domain -like "*_kerberos*") {
            Write-Warning "Sensitive AD service enumerated: $domain"
        }
    }
    
    # Habilitar auditoría completa si no está activada
    $diagnostics = Get-DnsServerDiagnostics
    if ($diagnostics.EventLogLevel -lt 4) {
        Set-DnsServerDiagnostics -EventLogLevel 4 -All $true
        Write-EventLog -LogName "DNS Server" -Source "DNSSecurity" -EventId 9006 -Message "Enhanced DNS logging enabled after enumeration attack from $AttackerIP"
    }
    
    # Notificar al equipo de seguridad
    Send-MailMessage -To "security-team@company.com" -Subject "ALERT: DNS Enumeration Attack Detected" -Body "DNS enumeration from $AttackerIP targeting domains: $($QueriedDomains -join ', '). Rate limiting enabled and zone transfers restricted."
}

# Script para auditar y remediar configuraciones DNS vulnerables
function Audit-DNSVulnerabilities {
    Write-Host "=== DNS Security Audit ===" -ForegroundColor Cyan
    
    # Verificar transferencias de zona
    Write-Host "`n=== Transferencias de Zona ===" -ForegroundColor Cyan
    $zones = Get-DnsServerZone | Where-Object {$_.ZoneType -eq "Primary"}
    $vulnerableZones = 0
    
    foreach ($zone in $zones) {
        $primary = Get-DnsServerPrimaryZone -Name $zone.ZoneName
        if ($primary.SecureSecondaries -eq "TransferToAnyServer") {
            Write-Host "✗ VULNERABLE: $($zone.ZoneName) permite transferencias a cualquier servidor" -ForegroundColor Red
            $vulnerableZones++
        } else {
            Write-Host "✓ SEGURO: $($zone.ZoneName) tiene transferencias restringidas" -ForegroundColor Green
        }
    }
    
    # Verificar rate limiting
    Write-Host "`n=== Rate Limiting ===" -ForegroundColor Cyan
    $rrl = Get-DnsServerRRL
    if ($rrl.ResponsesPerSec -gt 0) {
        Write-Host "✓ Rate limiting habilitado: $($rrl.ResponsesPerSec) respuestas/segundo" -ForegroundColor Green
    } else {
        Write-Host "✗ Rate limiting DESHABILITADO - HABILITAR INMEDIATAMENTE" -ForegroundColor Red
        Write-Host "  Ejecutar: Set-DnsServerRRL -ResponsesPerSec 10 -ErrorsPerSec 5" -ForegroundColor Yellow
    }
    
    # Verificar auditoría
    Write-Host "`n=== Auditoría DNS ===" -ForegroundColor Cyan
    $diagnostics = Get-DnsServerDiagnostics
    if ($diagnostics.EventLogLevel -gt 0 -and $diagnostics.EnableLogFileRollover) {
        Write-Host "✓ Auditoría habilitada (Nivel: $($diagnostics.EventLogLevel))" -ForegroundColor Green
    } else {
        Write-Host "✗ Auditoría DESHABILITADA" -ForegroundColor Red
        Write-Host "  Ejecutar: Set-DnsServerDiagnostics -EventLogLevel 4 -All `$true" -ForegroundColor Yellow
    }
    
    # Verificar recursión
    Write-Host "`n=== Configuración de Recursión ===" -ForegroundColor Cyan
    $recursion = Get-DnsServerRecursion
    if ($recursion.Enable -eq $false) {
        Write-Host "✓ Recursión deshabilitada (más seguro)" -ForegroundColor Green
    } else {
        Write-Host "⚠ Recursión habilitada - verificar si es necesaria" -ForegroundColor Yellow
        Write-Host "  Considerar: Set-DnsServerRecursion -Enable `$false" -ForegroundColor Yellow
    }
    
    # Verificar forwarders
    Write-Host "`n=== Forwarders DNS ===" -ForegroundColor Cyan
    $forwarders = Get-DnsServerForwarder
    if ($forwarders.IPAddress.Count -gt 0) {
        Write-Host "Forwarders configurados:" -ForegroundColor Yellow
        foreach ($fwd in $forwarders.IPAddress) {
            Write-Host "  - $fwd" -ForegroundColor Cyan
        }
    } else {
        Write-Host "⚠ No hay forwarders configurados" -ForegroundColor Yellow
    }
    
    # Buscar registros sensibles expuestos
    Write-Host "`n=== Registros Sensibles ===" -ForegroundColor Cyan
    foreach ($zone in $zones) {
        $sensitiveRecords = Get-DnsServerResourceRecord -ZoneName $zone.ZoneName |
                           Where-Object {$_.RecordType -eq "SRV" -and ($_.HostName -like "*_ldap*" -or $_.HostName -like "*_kerberos*")}
        
        if ($sensitiveRecords.Count -gt 0) {
            Write-Host "Zona $($zone.ZoneName) - Registros AD SRV: $($sensitiveRecords.Count)" -ForegroundColor Yellow
        }
    }
    
    return @{
        VulnerableZones = $vulnerableZones
        RateLimitingEnabled = ($rrl.ResponsesPerSec -gt 0)
        AuditingEnabled = ($diagnostics.EventLogLevel -gt 0)
        RecursionEnabled = $recursion.Enable
        TotalZones = $zones.Count
    }
}
```

### Checklist de respuesta a incidentes

- [ ] **Detección confirmada**: Validar consultas DNS masivas o intentos de transferencia de zona
- [ ] **Contención**: Bloquear IP atacante y restringir transferencias de zona
- [ ] **Auditoría**: Revisar todas las zonas DNS y sus configuraciones de seguridad
- [ ] **Hardening**: Implementar rate limiting y restricciones de transferencia
- [ ] **Monitoreo**: Configurar alertas para futuras consultas DNS sospechosas
- [ ] **Documentación**: Registrar dominios consultados y medidas implementadas
- [ ] **Seguimiento**: Monitorear por 30 días actividad DNS desde redes sospechosas
- [ ] **Política**: Actualizar políticas DNS y configuraciones de seguridad

---

## 🧑‍💻 ¿Cómo probar enumeración DNS en laboratorio?

### Configuración de entorno de pruebas

```bash
# En el servidor DNS objetivo (solo para laboratorio):
# Configurar zona con transferencias permisivas para testing
Add-DnsServerPrimaryZone -Name "testlab.local" -ZoneFile "testlab.local.dns"
Set-DnsServerPrimaryZone -Name "testlab.local" -SecureSecondaries TransferToAnyServer

# Probar enumeración desde Kali Linux:
dnsrecon -d testlab.local
dnsenum testlab.local
dig @192.168.1.10 testlab.local AXFR
dig _ldap._tcp.testlab.local SRV
```

### Validación de detección

```powershell
# Verificar que la enumeración genera eventos de log
Get-WinEvent -FilterHashtable @{LogName='DNS Server'; ID=256,257} -MaxEvents 20 |
Where-Object {$_.TimeCreated -gt (Get-Date).AddMinutes(-10)} |
Select-Object TimeCreated, Id, LevelDisplayName, Message |
Format-Table -Wrap
```

---

## 📚 Referencias

- [DNSRecon - GitHub](https://github.com/darkoperator/dnsrecon)
- [DNSEnum - Kali Tools](https://tools.kali.org/information-gathering/dnsenum)
- [Dig Command Reference](https://linux.die.net/man/1/dig)
- [Windows DNS Server Security](https://docs.microsoft.com/en-us/windows-server/networking/dns/dns-security-guide)
- [MITRE ATT&CK T1590.002 - DNS Enumeration](https://attack.mitre.org/techniques/T1590/002/)
- [DNS Security Best Practices - NIST](https://csrc.nist.gov/publications/detail/sp/800-81/2/final)