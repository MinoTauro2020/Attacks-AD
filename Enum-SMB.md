# 🛑 Enumeración SMB en Active Directory

---

## 📝 ¿Qué es la enumeración SMB?

| Concepto      | Descripción                                                                                                      |
|---------------|-----------------------------------------------------------------------------------------------------------------|
| **Definición**| Técnica de reconocimiento que permite a un atacante obtener información detallada sobre servicios SMB, recursos compartidos, usuarios y grupos del dominio mediante herramientas automatizadas. |
| **Requisito** | Acceso de red al puerto 445 (SMB) y opcionalmente credenciales válidas para enumeración autenticada. |

---

## 🛠️ ¿Cómo funciona el ataque?

| Fase                | Acción                                                                                                 |
|---------------------|--------------------------------------------------------------------------------------------------------|
| **Descubrimiento**  | El atacante identifica hosts con puerto 445 abierto mediante escaneo de red.                           |
| **Enumeración anónima** | Utiliza herramientas como enum4linux o smbclient para extraer información sin autenticación.      |
| **Enumeración autenticada** | Con credenciales válidas, usa smbmap o crackmapexec para obtener información detallada.        |
| **Reconocimiento**  | Mapea recursos compartidos, usuarios, grupos, políticas y configuraciones del dominio.               |

---

## 💻 Ejemplo práctico

### Enum4linux - Enumeración completa
```bash
# Enumeración básica sin credenciales
enum4linux -a 192.168.1.10

# Enumeración con credenciales
enum4linux -u "usuario" -p "contraseña" -a 192.168.1.10
```

### SMBClient - Exploración de recursos compartidos
```bash
# Listar recursos compartidos sin autenticación
smbclient -L //192.168.1.10 -N

# Conectar a un recurso compartido específico
smbclient //192.168.1.10/ADMIN$ -U "usuario%contraseña"
```

### SMBMap - Mapeo detallado de permisos
```bash
# Enumerar con credenciales y mostrar permisos
smbmap -H 192.168.1.10 -u "usuario" -p "contraseña"

# Enumerar recursivamente un recurso específico
smbmap -H 192.168.1.10 -u "usuario" -p "contraseña" -r "SYSVOL"
```

### CrackMapExec - Enumeración masiva
```bash
# Enumerar múltiples hosts
crackmapexec smb 192.168.1.0/24

# Enumerar con credenciales válidas
crackmapexec smb 192.168.1.10 -u "usuario" -p "contraseña" --shares

# Enumerar usuarios del dominio
crackmapexec smb 192.168.1.10 -u "usuario" -p "contraseña" --users
```

---

## 📊 Detección en logs y SIEM

| Campo clave                   | Descripción                                                                                      |
|-------------------------------|-------------------------------------------------------------------------------------------------|
| **EventCode = 5140**          | Acceso a recurso compartido de red - indica conexiones SMB entrantes.                           |
| **EventCode = 5145**          | Detalle de acceso a carpeta compartida específica.                                              |
| **Source_Network_Address**    | IP origen de la conexión SMB.                                                                   |
| **Share_Name**                | Nombre del recurso compartido accedido.                                                         |
| **Account_Name**              | Usuario que realiza la conexión.                                                                |

### Ejemplo de eventos relevantes

```
EventCode=5140
Source_Network_Address: 192.168.57.151
Account_Name: usuario_atacante
Share_Name: \\DC01\IPC$

EventCode=5145
Source_Network_Address: 192.168.57.151
Share_Name: \\DC01\SYSVOL
Access_Mask: 0x1
```

---

## 🔎 Queries Splunk para hunting

### 1. Detección de enumeración masiva de recursos compartidos

```splunk
index=wineventlog (EventCode=5140 OR EventCode=5145)
| eval src_ip=coalesce(Source_Network_Address, Client_Address)
| eval usuario=coalesce(Account_Name, user)
| bucket _time span=10m
| stats count as total_accesos, dc(Share_Name) as recursos_unicos, values(Share_Name) as recursos by _time, src_ip, usuario
| where recursos_unicos > 5 OR total_accesos > 20
| sort -_time
```

### 2. Detección de acceso a recursos administrativos sensibles

```splunk
index=wineventlog (EventCode=5140 OR EventCode=5145)
| search Share_Name="*ADMIN$*" OR Share_Name="*C$*" OR Share_Name="*IPC$*"
| eval src_ip=coalesce(Source_Network_Address, Client_Address)
| stats count by src_ip, Account_Name, Share_Name, _time
| where count > 3
| sort -_time
```

### 3. Correlación con herramientas de enumeración SMB

```splunk
index=endpoint_logs (process_name="enum4linux*" OR process_name="smbclient*" OR process_name="smbmap*" OR process_name="crackmapexec*")
| join src_ip [
    search index=wineventlog EventCode=5140 
    | eval src_ip=Source_Network_Address
    | table _time, src_ip, Account_Name, Share_Name
]
| table _time, src_ip, process_name, command_line, Account_Name, Share_Name
```

---

## ⚡️ Alertas recomendadas

| Alerta                                  | Descripción                                                                                 |
|------------------------------------------|---------------------------------------------------------------------------------------------|
| **Alerta 1**                            | Más de 5 recursos compartidos únicos accedidos desde la misma IP en 10 minutos.             |
| **Alerta 2**                            | Acceso a recursos administrativos (ADMIN$, C$) desde IPs no habituales.                     |
| **Alerta 3**                            | Uso de herramientas de enumeración SMB detectado en endpoints.                               |

---

## 🛡️ Detección con Windows Defender for Endpoint

### Reglas de detección personalizadas

```kql
// SMB Enumeration - Múltiples conexiones desde misma fuente
DeviceNetworkEvents
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
| summarize ConnectionCount = count(), UniqueShares = dcount(RemoteUrl) by RemoteIP, bin(Timestamp, 10m)
| where ConnectionCount > 15 or UniqueShares > 5
| order by ConnectionCount desc
```

```kql
// Detección de herramientas de enumeración SMB
DeviceProcessEvents
| where ProcessCommandLine has_any ("enum4linux", "smbclient", "smbmap", "crackmapexec") 
| where ProcessCommandLine has_any ("-L", "-a", "-H", "--shares", "--users")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

```kql
// Acceso anómalo a recursos administrativos SMB
DeviceNetworkEvents
| where RemotePort == 445 and RemoteUrl has_any ("ADMIN$", "C$", "IPC$")
| summarize AdminAccessCount = count() by DeviceId, RemoteIP, AccountName, bin(Timestamp, 5m)
| where AdminAccessCount > 5
| order by AdminAccessCount desc
```

### Alertas recomendadas

| Regla | Descripción | Severidad |
|-------|-------------|-----------|
| **SMB Enumeration Spike** | Más de 15 conexiones SMB o 5 recursos únicos en 10 minutos | Media |
| **SMB Enum Tools** | Detección de herramientas de enumeración SMB | Alta |
| **Admin Share Access** | Múltiples accesos a recursos administrativos | Alta |

---

## 🦅 Detección con CrowdStrike Falcon

### Hunting queries (Event Search)

```sql
-- Detección de enumeración SMB masiva
event_platform=Win event_simpleName=NetworkConnectIP4
| search RemotePort=445
| bin _time span=10m
| stats count as smb_connections, dc(RemoteAddressIP4) as unique_targets by ComputerName, UserName, _time
| where smb_connections > 20 OR unique_targets > 10
| sort - smb_connections
```

```sql
-- Detección de herramientas de enumeración SMB
event_platform=Win event_simpleName=ProcessRollup2 
| search (CommandLine=*enum4linux* OR CommandLine=*smbclient* OR CommandLine=*smbmap* OR CommandLine=*crackmapexec*)
| table _time, ComputerName, UserName, FileName, CommandLine, SHA256HashData
| sort - _time
```

```sql
-- Detección de acceso a recursos compartidos administrativos
event_platform=Win event_simpleName=SmbClientAccessAttempt
| search ShareName IN ("ADMIN$", "C$", "IPC$")
| bin _time span=5m
| stats count as admin_access_attempts by ComputerName, UserName, ShareName, RemoteHost, _time
| where admin_access_attempts > 3
| sort - admin_access_attempts
```

### Custom IOAs (Indicators of Attack)

```sql
-- IOA para detectar spray de enumeración SMB
event_platform=Win event_simpleName=NetworkConnectIP4
| search RemotePort=445
| bin _time span=15m
| stats dc(RemoteAddressIP4) as target_count, count as connection_count by ComputerName, UserName, _time
| where target_count > 50 OR connection_count > 100
```

---

## 🔍 Queries KQL para Microsoft Sentinel

### Detección de SMB Enumeration

```kql
// Query principal para detectar enumeración SMB
SecurityEvent
| where EventID in (5140, 5145)
| where ShareName != "\\*\\print$" // Excluir impresoras
| summarize ConnectionCount = count(), UniqueShares = dcount(ShareName), ShareList = make_set(ShareName) by SourceIP = IpAddress, Account = AccountName, bin(TimeGenerated, 10m)
| where ConnectionCount > 10 or UniqueShares > 5
| order by ConnectionCount desc
```

```kql
// Correlación con herramientas de enumeración
DeviceProcessEvents
| where ProcessCommandLine contains "enum4linux" or ProcessCommandLine contains "smbclient" or ProcessCommandLine contains "smbmap" or ProcessCommandLine contains "crackmapexec"
| join kind=inner (
    SecurityEvent
    | where EventID == 5140
    | project TimeGenerated, IpAddress, AccountName, ShareName
) on $left.DeviceName == $right.Computer
| project TimeGenerated, DeviceName, ProcessCommandLine, AccountName, ShareName, IpAddress
```

### Hunting avanzado

```kql
// Detección de enumeración de usuarios via SMB
SecurityEvent
| where EventID == 5140 and ShareName endswith "$IPC$"
| where AccountName != "ANONYMOUS LOGON"
| summarize IPCConnections = count() by SourceIP = IpAddress, Account = AccountName, bin(TimeGenerated, 5m)
| where IPCConnections > 5
| join kind=inner (
    SecurityEvent
    | where EventID == 4624 and LogonType == 3  // Network logon
    | project TimeGenerated, IpAddress, TargetUserName
) on $left.SourceIP == $right.IpAddress
| project TimeGenerated, SourceIP, Account, IPCConnections, TargetUserName
| order by IPCConnections desc
```

```kql
// Detección de acceso a recursos sensibles desde redes externas
SecurityEvent
| where EventID in (5140, 5145)
| where ShareName has_any ("ADMIN$", "C$", "SYSVOL", "NETLOGON")
| where IpAddress !startswith "10." and IpAddress !startswith "192.168." and IpAddress !startswith "172."
| summarize ExternalAccess = count(), ShareList = make_set(ShareName) by SourceIP = IpAddress, Account = AccountName, bin(TimeGenerated, 15m)
| where ExternalAccess > 1
| order by ExternalAccess desc
```

---

## 🦾 Hardening y mitigación

| Medida                                   | Descripción                                                                                 |
|-------------------------------------------|---------------------------------------------------------------------------------------------|
| **Deshabilitar SMBv1**                   | Elimina el protocolo SMBv1 vulnerable y fuerza uso de versiones más seguras.               |
| **Configurar SMB signing**                | Habilita firma SMB obligatoria para prevenir ataques man-in-the-middle.                    |
| **Restringir acceso anónimo**             | Bloquea el acceso sin autenticación a recursos compartidos y servicios.                     |
| **Limitar recursos compartidos**          | Mantiene solo los recursos compartidos estrictamente necesarios.                            |
| **Configurar permisos restrictivos**      | Implementa principio de menor privilegio en recursos compartidos.                           |
| **Segmentación de red**                   | Restringe acceso SMB solo a redes autorizadas mediante firewalls.                          |
| **Monitorización avanzada**               | Implementa logging detallado de accesos SMB y alertas automatizadas.                       |
| **Autenticación multifactor**             | Requiere MFA para accesos administrativos a recursos compartidos críticos.                 |

---

## 🔧 Parches y actualizaciones

| Parche/Update | Descripción                                                                                  |
|---------------|----------------------------------------------------------------------------------------------|
| **KB5025221** | Windows 11/10 - Mejoras en seguridad SMB y protección contra enumeración no autorizada.     |
| **KB5022906** | Windows Server 2022 - Fortalecimiento de protocolos SMB y auditoría de accesos.             |
| **KB5022845** | Windows Server 2019 - Correcciones en configuraciones SMB por defecto y acceso restringido. |
| **KB4580390** | Windows Server 2016 - Parches críticos para limitar enumeración vía SMB.                    |
| **KB4013389** | Patch para EternalBlue (CVE-2017-0144) - Crítico para seguridad SMB.                        |
| **SMB Hardening Updates** | Actualizaciones específicas del subsistema SMB para mejor autenticación.          |

### Configuraciones de registro críticas

```powershell
# Deshabilitar SMBv1 completamente
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# Habilitar SMB signing obligatorio
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force

# Restringir acceso anónimo a recursos compartidos
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" -Name "RestrictNullSessAccess" -Value 1

# Configurar auditoría detallada de acceso a objetos
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable

# Limitar interfaces de red para SMB
Set-SmbServerConfiguration -AnnounceServer $false -Force
```

### Configuraciones de GPO críticas

```powershell
# Configurar políticas SMB restrictivas via GPO
# Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options:
# "Microsoft network server: Digitally sign communications (always)" = Enabled
# "Microsoft network server: Digitally sign communications (if client agrees)" = Enabled
# "Network access: Restrict anonymous access to Named Pipes and Shares" = Enabled

# Configurar firewall para SMB
New-NetFirewallRule -DisplayName "Block SMB from Internet" -Direction Inbound -Protocol TCP -LocalPort 445 -RemoteAddress "Internet" -Action Block
New-NetFirewallRule -DisplayName "Allow SMB Internal Only" -Direction Inbound -Protocol TCP -LocalPort 445 -RemoteAddress "LocalSubnet" -Action Allow
```

### Scripts de validación y detección

```powershell
# Verificar configuraciones SMB seguras
function Test-SMBSecurity {
    # Verificar SMBv1 deshabilitado
    $smb1 = Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
    if ($smb1.EnableSMB1Protocol -eq $false) {
        Write-Host "✓ SMBv1 deshabilitado correctamente" -ForegroundColor Green
    } else {
        Write-Host "✗ DESHABILITAR SMBv1" -ForegroundColor Red
    }
    
    # Verificar SMB signing
    $smbSigning = Get-SmbServerConfiguration | Select-Object RequireSecuritySignature
    if ($smbSigning.RequireSecuritySignature -eq $true) {
        Write-Host "✓ SMB signing obligatorio habilitado" -ForegroundColor Green
    } else {
        Write-Host "✗ HABILITAR SMB signing obligatorio" -ForegroundColor Red
    }
    
    # Verificar recursos compartidos expuestos
    $shares = Get-SmbShare | Where-Object {$_.Name -notin @("ADMIN$", "C$", "IPC$", "print$")}
    if ($shares.Count -eq 0) {
        Write-Host "✓ No hay recursos compartidos adicionales expuestos" -ForegroundColor Green
    } else {
        Write-Host "⚠ Recursos compartidos encontrados: $($shares.Name -join ', ')" -ForegroundColor Yellow
    }
}

# Detectar conexiones SMB sospechosas en tiempo real
function Monitor-SMBConnections {
    Get-SmbConnection | Where-Object {$_.ServerName -notlike "*.*"} |
    Group-Object ClientComputerName | Where-Object Count -gt 10 |
    ForEach-Object {
        Write-Warning "Cliente con múltiples conexiones SMB: $($_.Name) - $($_.Count) conexiones"
    }
}

# Auditar permisos de recursos compartidos
function Audit-SharePermissions {
    Get-SmbShare | ForEach-Object {
        $shareName = $_.Name
        $shareAccess = Get-SmbShareAccess -Name $shareName
        
        Write-Host "Recurso: $shareName" -ForegroundColor Yellow
        $shareAccess | ForEach-Object {
            if ($_.AccessRight -eq "Full" -and $_.AccountName -like "*Everyone*") {
                Write-Host "  ✗ RIESGO: Everyone con acceso completo" -ForegroundColor Red
            } elseif ($_.AccessRight -eq "Full") {
                Write-Host "  ⚠ Acceso completo: $($_.AccountName)" -ForegroundColor Yellow
            } else {
                Write-Host "  ✓ $($_.AccountName): $($_.AccessRight)" -ForegroundColor Green
            }
        }
    }
}

# Ejecutar auditoría completa
Test-SMBSecurity
Monitor-SMBConnections
Audit-SharePermissions
```

### Actualizaciones críticas de seguridad

- **CVE-2017-0144**: EternalBlue - Ejecución remota de código vía SMBv1 (KB4013389)
- **CVE-2020-0796**: SMBGhost - Vulnerabilidad de compresión SMBv3 (KB4551762)
- **CVE-2021-31166**: Vulnerabilidad en driver HTTP.sys que afecta SMB (KB5003173)
- **CVE-2022-22717**: Bypass de autenticación SMB (KB5010793)

### Herramientas de monitorización avanzadas

```powershell
# Script para detectar enumeración SMB en tiempo real
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5140,5145} -MaxEvents 50
$events | Group-Object Properties[5] | Where-Object Count -gt 10 | 
ForEach-Object {
    Write-Warning "IP con múltiples accesos SMB: $($_.Name) - $($_.Count) accesos"
}

# Monitorear uso de herramientas de enumeración
Get-Process | Where-Object {$_.ProcessName -match "(enum4linux|smbclient|smbmap|crackmapexec)"} |
ForEach-Object {
    Write-Warning "Herramienta de enumeración SMB detectada: $($_.ProcessName) PID:$($_.Id)"
}

# Alert para accesos a recursos administrativos
$adminShares = @("ADMIN$", "C$")
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5140} -MaxEvents 100 |
Where-Object {$adminShares -contains ($_.Properties[3].Value)} |
ForEach-Object {
    Write-Alert "Acceso a recurso administrativo: $($_.Properties[3].Value) desde $($_.Properties[5].Value)"
}
```

---

## 🚨 Respuesta ante incidentes

### Procedimientos de respuesta inmediata

1. **Identificación del ataque de enumeración SMB:**
   - Confirmar eventos 5140/5145 con patrones sospechosos (múltiples recursos desde misma IP)
   - Verificar uso de herramientas de enumeración (enum4linux, smbclient, etc.)
   - Correlacionar con accesos a recursos administrativos o sensibles

2. **Contención inmediata:**
   - Bloquear la IP origen del ataque en firewalls y sistemas de seguridad
   - Deshabilitar temporalmente recursos compartidos no críticos
   - Revisar y fortalecer permisos de recursos compartidos accedidos

3. **Análisis de impacto:**
   - Determinar qué recursos compartidos fueron enumerados
   - Evaluar la sensibilidad de la información expuesta
   - Verificar si hubo acceso real a datos críticos

4. **Investigación forense:**
   - Buscar herramientas de enumeración en el endpoint origen
   - Analizar logs de autenticación para identificar credenciales utilizadas
   - Revisar configuraciones de recursos compartidos para determinar exposición

5. **Recuperación y endurecimiento:**
   - Implementar configuraciones SMB más restrictivas
   - Habilitar SMB signing obligatorio si no estaba activado
   - Fortalecer permisos de recursos compartidos según principio de menor privilegio

### Scripts de respuesta automatizada

```powershell
# Script de respuesta para enumeración SMB
function Respond-SMBEnumerationAttack {
    param($AttackerIP, $AccessedShares, $AffectedSystems)
    
    # Bloquear IP atacante
    New-NetFirewallRule -DisplayName "Block SMB Enumeration IP" -Direction Inbound -RemoteAddress $AttackerIP -Action Block
    
    # Auditar recursos compartidos accedidos
    foreach ($share in $AccessedShares) {
        Write-EventLog -LogName Security -Source "SMBSecurity" -EventId 9001 -Message "SMB share enumerated: $share by $AttackerIP"
        
        # Revisar permisos del recurso
        $shareAccess = Get-SmbShareAccess -Name $share
        if ($shareAccess | Where-Object {$_.AccountName -like "*Everyone*" -and $_.AccessRight -eq "Full"}) {
            Write-Warning "Share $share has Everyone with Full access - IMMEDIATE REVIEW REQUIRED"
            # Opcional: Remover acceso Everyone automáticamente
            # Revoke-SmbShareAccess -Name $share -AccountName "Everyone" -Force
        }
    }
    
    # Habilitar SMB signing si no está activado
    $smbConfig = Get-SmbServerConfiguration
    if (-not $smbConfig.RequireSecuritySignature) {
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
        Write-EventLog -LogName Security -Source "SMBSecurity" -EventId 9002 -Message "SMB signing enabled after enumeration attack from $AttackerIP"
    }
    
    # Auditar todas las configuraciones SMB
    $smbShares = Get-SmbShare | Where-Object {$_.Name -notin @("print$")}
    foreach ($share in $smbShares) {
        $permissions = Get-SmbShareAccess -Name $share.Name
        Write-Warning "Share: $($share.Name) - Permissions: $($permissions | ConvertTo-Json -Compress)"
    }
    
    # Notificar al equipo de seguridad
    Send-MailMessage -To "security-team@company.com" -Subject "ALERT: SMB Enumeration Attack Detected" -Body "SMB enumeration from $AttackerIP targeting shares: $($AccessedShares -join ', '). SMB signing enforced and IP blocked."
}

# Script para auditar y remediar configuraciones SMB vulnerables
function Audit-SMBConfigurations {
    Write-Host "=== SMB Security Audit ===" -ForegroundColor Cyan
    
    # Verificar SMBv1
    $smb1Status = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
    if ($smb1Status.State -eq "Enabled") {
        Write-Host "✗ SMBv1 está habilitado - DESHABILITAR INMEDIATAMENTE" -ForegroundColor Red
        # Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
    } else {
        Write-Host "✓ SMBv1 está deshabilitado" -ForegroundColor Green
    }
    
    # Verificar SMB signing
    $smbServer = Get-SmbServerConfiguration
    if ($smbServer.RequireSecuritySignature) {
        Write-Host "✓ SMB signing obligatorio está habilitado" -ForegroundColor Green
    } else {
        Write-Host "✗ SMB signing obligatorio está DESHABILITADO" -ForegroundColor Red
        Write-Host "  Ejecutar: Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force" -ForegroundColor Yellow
    }
    
    # Auditar recursos compartidos
    Write-Host "`n=== Recursos Compartidos ===" -ForegroundColor Cyan
    $shares = Get-SmbShare | Where-Object {$_.Name -notin @("ADMIN$", "C$", "IPC$", "print$")}
    
    foreach ($share in $shares) {
        Write-Host "Recurso: $($share.Name)" -ForegroundColor Yellow
        $access = Get-SmbShareAccess -Name $share.Name
        
        foreach ($permission in $access) {
            $color = "Green"
            $risk = "✓"
            
            if ($permission.AccountName -like "*Everyone*") {
                $color = "Red"
                $risk = "✗ RIESGO ALTO"
            } elseif ($permission.AccessRight -eq "Full") {
                $color = "Yellow"
                $risk = "⚠ REVISAR"
            }
            
            Write-Host "  $risk $($permission.AccountName): $($permission.AccessRight)" -ForegroundColor $color
        }
    }
    
    # Verificar configuraciones de registro
    Write-Host "`n=== Configuraciones de Registro ===" -ForegroundColor Cyan
    
    $restrictNull = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" -Name "RestrictNullSessAccess" -ErrorAction SilentlyContinue
    if ($restrictNull.RestrictNullSessAccess -eq 1) {
        Write-Host "✓ Acceso nulo restringido" -ForegroundColor Green
    } else {
        Write-Host "✗ Acceso nulo NO restringido" -ForegroundColor Red
    }
    
    return @{
        SMBv1Enabled = ($smb1Status.State -eq "Enabled")
        SMBSigningRequired = $smbServer.RequireSecuritySignature
        VulnerableShares = ($shares | Where-Object {(Get-SmbShareAccess -Name $_.Name | Where-Object {$_.AccountName -like "*Everyone*"})}).Count
        TotalShares = $shares.Count
    }
}
```

### Checklist de respuesta a incidentes

- [ ] **Detección confirmada**: Validar eventos 5140/5145 con patrones de enumeración
- [ ] **Contención**: Bloquear IP atacante y limitar acceso a recursos compartidos
- [ ] **Auditoría**: Revisar todos los recursos compartidos y sus permisos
- [ ] **Hardening**: Implementar SMB signing y deshabilitar SMBv1
- [ ] **Monitoreo**: Configurar alertas para futuros intentos de enumeración SMB
- [ ] **Documentación**: Registrar recursos accedidos y medidas implementadas
- [ ] **Seguimiento**: Monitorear por 30 días actividad relacionada con recursos afectados
- [ ] **Política**: Actualizar políticas de recursos compartidos y acceso de red

---

## 🧑‍💻 ¿Cómo probar enumeración SMB en laboratorio?

### Configuración de entorno de pruebas

```bash
# Configurar objetivo con recursos compartidos vulnerables
# En Windows Server (solo para laboratorio):
New-SmbShare -Name "TestShare" -Path "C:\TestShare" -FullAccess "Everyone"

# Probar enumeración desde Kali Linux:
enum4linux -a 192.168.1.10
smbclient -L //192.168.1.10 -N
smbmap -H 192.168.1.10 -u guest
crackmapexec smb 192.168.1.10 --shares
```

### Validación de detección

```powershell
# Verificar que la enumeración genera eventos de log
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5140,5145} -MaxEvents 10 |
Select-Object TimeCreated, Id, LevelDisplayName, Message |
Format-Table -Wrap
```

---

## 📚 Referencias

- [enum4linux - GitHub](https://github.com/CiscoCXSecurity/enum4linux)
- [SMBClient - Samba documentation](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
- [SMBMap - GitHub](https://github.com/ShawnDEvans/smbmap)
- [CrackMapExec - GitHub](https://github.com/byt3bl33d3r/CrackMapExec)
- [SMB Security Best Practices - Microsoft](https://docs.microsoft.com/en-us/windows-server/storage/file-server/best-practices-analyzer/smb-security-best-practices)
- [MITRE ATT&CK T1135 - Network Share Discovery](https://attack.mitre.org/techniques/T1135/)