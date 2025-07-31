# 🛑 Movimiento lateral y ejecución remota en Windows vía svcctl (SMB)

---

## 📝 ¿Qué es svcctl y por qué es tan crítico?

| Concepto      | Descripción                                                                                                 |
|---------------|------------------------------------------------------------------------------------------------------------|
| **Definición**| Canalización nombrada (named pipe) utilizada por el Service Control Manager para gestionar servicios de Windows de forma remota. Permite crear, modificar, arrancar o eliminar servicios vía SMB. |
| **Uso**       | Herramientas ofensivas como CrackMapExec, nxc, Impacket, PsExec y similares abusan de svcctl para ejecutar comandos y moverse lateralmente en la red. |

---

## 🛠️ ¿Cómo funciona el ataque? (paso a paso real)

| Fase             | Acción                                                                                                          |
|------------------|-----------------------------------------------------------------------------------------------------------------|
| **Reconocimiento**| El atacante valida credenciales y busca shares administrativos accesibles (C$, ADMIN$, IPC$).                  |
| **Acceso**       | Conecta a \\host\IPC$ y accede a la canalización svcctl.                                                        |
| **Ejecución**    | Crea un servicio remoto (temporal o persistente) que ejecuta el comando/malware deseado en la máquina objetivo. |
| **Movimiento**   | Repite la operación en otras máquinas usando credenciales robadas o delegación de privilegios.                   |
| **Limpieza**     | Borra el servicio creado para intentar borrar huellas.                                                          |

---

## 💻 Ejemplo ofensivo (comandos reales)

```bash
# Enumerar shares y permisos con nxc
nxc smb 192.168.1.10 -u usuario -p 'contraseña' 

# Ejecución remota usando svcctl
nxc smb 192.168.1.10 -u usuario -p 'contraseña' -x 'whoami'

# Movimiento lateral con CrackMapExec
crackmapexec smb 192.168.1.10 -u usuario -p 'contraseña' -x 'net user'

# Ejecución remota con Impacket/psexec
psexec.py dominio/usuario:'contraseña'@192.168.1.10
```

---

## 📊 Detección en Splunk

| Evento clave | Descripción                                                                                                   |
|--------------|--------------------------------------------------------------------------------------------------------------|
| **4776**     | Autenticación NTLM solicitada por el atacante.                                                               |
| **4624**     | Inicio de sesión exitoso (tipo 3/red) con las credenciales usadas.                                           |
| **5140**     | Acceso a recursos compartidos administrativos (C$, ADMIN$, IPC$).                                            |
| **5145**     | Acceso a objetos críticos: canalización svcctl, especialmente con WriteData o Execute.                       |
| **4672/4674**| Privilegios especiales asignados o uso de privilegios elevados (si la cuenta es admin).                      |
| **7045**     | Creación de servicios remotos (persistencia/ejecución remota).                                               |
| **4634**     | Cierre de sesión.                                                                                            |

### Query Splunk esencial

```splunk
index=dc_logs (EventCode=5140 OR EventCode=5145)
| search (Share_Name="*IPC$" OR Share_Name="*C$" OR Share_Name="*ADMIN$" OR Relative_Target_Name="svcctl")
| search Accesses="*WriteData*" OR Accesses="*Execute*"
| stats count by _time, Account_Name, Source_Address, ComputerName, Relative_Target_Name, Accesses
```

### Query para correlacionar secuencias sospechosas

```splunk
index=dc_logs (EventCode=4776 OR EventCode=4624 OR EventCode=5140 OR EventCode=5145)
| stats list(EventCode) as Secuencia, min(_time) as Primer_Evento, max(_time) as Ultimo_Evento by Account_Name, Source_Address, ComputerName
| search Secuencia="*5140*" Secuencia="*5145*"
| table Primer_Evento, Ultimo_Evento, Account_Name, Source_Address, ComputerName, Secuencia
```

---

## 🛡️ Detección con Windows Defender for Endpoint

### Reglas de detección personalizadas

```kql
// NetExec Lateral Movement - Detección de movimiento lateral con nxc
DeviceNetworkEvents
| where RemotePort in (445, 135, 139)
| where ActionType == "ConnectionSuccess"
| summarize ConnectionCount = count(), UniqueTargets = dcount(RemoteIP) by DeviceId, bin(Timestamp, 5m)
| where ConnectionCount > 10 or UniqueTargets > 5
| order by ConnectionCount desc
```

```kql
// Detección de herramientas NetExec
DeviceProcessEvents
| where ProcessCommandLine has_any ("nxc", "netexec", "crackmapexec", "cme") and ProcessCommandLine has_any ("smb", "wmi", "ssh", "rdp")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

```kql
// Detección de acceso a shares administrativos
DeviceEvents
| where ActionType == "FileAccess"
| where FolderPath has_any ("ADMIN$", "C$", "IPC$")
| summarize ShareAccess = count() by DeviceId, AccountName, bin(Timestamp, 5m)
| where ShareAccess > 5
| order by ShareAccess desc
```

### Alertas recomendadas

| Regla | Descripción | Severidad |
|-------|-------------|-----------|
| **Lateral Movement Spike** | Múltiples conexiones SMB/WMI en poco tiempo | Alta |
| **NetExec Tools** | Detección de herramientas NetExec/CrackMapExec | Alta |
| **Admin Share Access** | Acceso frecuente a shares administrativos | Media |

---

## 🦅 Detección con CrowdStrike Falcon

### Hunting queries (Event Search)

```sql
-- Detección de movimiento lateral con NetExec
event_platform=Win event_simpleName=NetworkConnectIP4
| search RemotePort IN (445, 135, 139, 5985, 5986)
| bin _time span=5m
| stats dc(RemoteAddressIP4) as unique_targets, count as total_connections by ComputerName, UserName, _time
| where unique_targets > 5 OR total_connections > 20
| sort - unique_targets
```

```sql
-- Detección de herramientas NetExec
event_platform=Win event_simpleName=ProcessRollup2 
| search (FileName=*nxc* OR FileName=*netexec* OR FileName=*crackmapexec* OR CommandLine=*nxc* OR CommandLine=*cme*)
| table _time, ComputerName, UserName, FileName, CommandLine, SHA256HashData
| sort - _time
```

```sql
-- Detección de ejecución remota via WMI/SMB
event_platform=Win event_simpleName=RemoteProcessCreation
| search ParentProcessName IN (*wmiprvse.exe*, *services.exe*, *svchost.exe*)
| table _time, ComputerName, ProcessName, CommandLine, ParentProcessName
| sort - _time
```

### Custom IOAs (Indicators of Attack)

```sql
-- IOA para detectar spray de credenciales
event_platform=Win event_simpleName=UserLogon
| search LogonType=3
| bin _time span=2m
| stats dc(ComputerName) as target_systems by UserName, SourceIP, _time
| where target_systems > 3
```

---

## 🔍 Queries KQL para Microsoft Sentinel

### Detección de Lateral Movement con NetExec

```kql
// Query principal para detectar movimiento lateral
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where Account !endswith "$"
| summarize LogonCount = count(), UniqueComputers = dcount(Computer) by Account, IpAddress, bin(TimeGenerated, 5m)
| where LogonCount > 10 or UniqueComputers > 5
| order by LogonCount desc
```

```kql
// Correlación con herramientas NetExec
DeviceProcessEvents
| where ProcessCommandLine has_any ("nxc", "netexec", "crackmapexec")
| join kind=inner (
    SecurityEvent
    | where EventID == 4624 and LogonType == 3
    | project TimeGenerated, Computer, Account, IpAddress
) on $left.DeviceName == $right.Computer
| project TimeGenerated, DeviceName, ProcessCommandLine, Account, IpAddress
```

### Hunting avanzado

```kql
// Detección de ejecución remota coordinada
SecurityEvent
| where EventID == 4688 // Process creation
| where NewProcessName has_any ("cmd.exe", "powershell.exe", "wmic.exe")
| join kind=inner (
    SecurityEvent
    | where EventID == 4624 and LogonType == 3
    | project TimeGenerated, Computer, Account, IpAddress, LogonId
) on Computer, LogonId
| where TimeGenerated > TimeGenerated1 and TimeGenerated - TimeGenerated1 < 5m
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine, IpAddress
```

```kql
// Detección de acceso a múltiples shares en red
SecurityEvent
| where EventID == 5140 // Network share accessed
| where ShareName in ("ADMIN$", "C$", "IPC$")
| summarize AccessCount = count(), UniqueShares = dcount(ShareName), UniqueComputers = dcount(Computer) by Account, IpAddress, bin(TimeGenerated, 10m)
| where AccessCount > 10 or UniqueComputers > 3
| order by AccessCount desc
```

---

## 🦾 Hardening y mitigación

| Medida                                  | Descripción                                                                                      |
|------------------------------------------|-------------------------------------------------------------------------------------------------|
| **Restringe acceso a svcctl**            | Solo los administradores reales y sistemas de gestión deben poder acceder a IPC$ y svcctl.       |
| **Honeytokens de servicio**              | Crea servicios trampa (falsos) y alerta si se accede a ellos.                                   |
| **Deshabilita shares administrativos**   | Si no son necesarios, desactiva IPC$, ADMIN$, C$ en sistemas de usuario.                        |
| **Segmentación de red**                  | Los usuarios normales jamás deberían poder conectar a IPC$ de otros equipos.                     |
| **Auditoría avanzada**                   | Activa auditoría solo en los eventos y objetos críticos, evita el ruido, máxima visibilidad.     |
| **SMBv1 deshabilitado y SMB signing**    | Elimina SMBv1 y exige signing para evitar ataques relay y legacy.                                |
| **Permisos de delegación revisados**     | Revisa los permisos delegados en el Service Control Manager y reduce el exceso de privilegios.   |
| **Alertas automáticas por Write/Execute**| Automatiza alertas por accesos WriteData o Execute en svcctl fuera de lo habitual.               |

---

## 🚨 Respuesta ante incidentes

1. **Aísla la IP de origen** si detectas WriteData/Execute en svcctl o shares críticos.
2. **Revoca y revisa la cuenta implicada** en el acceso sospechoso.
3. **Busca eventos 7045 (creación de servicios)** y procesos hijos de services.exe tras el acceso.
4. **Investiga movimiento lateral** correlacionando eventos en otras máquinas.
5. **Refuerza auditoría temporalmente** en los sistemas afectados y busca persistencia.

---

## 💡 Soluciones innovadoras

- **Honeytokens dinámicos:** Cambia el nombre/ruta de servicios trampa periódicamente para detectar atacantes.
- **Rate limiting SMB:** Limita la frecuencia de accesos a IPC$ y svcctl desde IPs no administrativas.
- **Auditoría basada en contexto:** Alerta solo si Write/Execute ocurre fuera de horario o por cuentas no habituales.
- **Responde de forma automatizada:** Scripts que bloquean cuentas/IP tras 3+ WriteData/Execute en objetos críticos.

---

## ⚡ CVEs y técnicas MITRE relevantes

- **T1021.002 (SMB/Windows Admin Shares):** Movimiento lateral y ejecución remota
- **CVE-2017-0144 (EternalBlue), CVE-2020-0796 (SMBGhost):** Explotación de SMB
- **PrintNightmare (CVE-2021-34527):** Ejecución remota a través de servicios

---

## 🔧 Parches y actualizaciones

| Parche/Update | Descripción                                                                                  |
|---------------|----------------------------------------------------------------------------------------------|
| **KB5025221** | Windows 11/10 - Mejoras en protección contra movimiento lateral vía SMB/WMI/PSExec.        |
| **KB5022906** | Windows Server 2022 - Fortalecimiento de servicios remotos y autenticación administrativa. |
| **KB5022845** | Windows Server 2019 - Correcciones en manejo de credenciales para servicios remotos.       |
| **KB4580390** | Windows Server 2016 - Parches para protección contra escalada via servicios administrativos.|
| **KB4556836** | Zerologon patch - Crítico para prevenir movimiento lateral post-compromiso inicial.        |
| **Administrative Tools Updates** | Actualizaciones de herramientas administrativas para mejor seguridad.    |

### Configuraciones de registro críticas

```powershell
# Configurar Credential Guard
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "LsaCfgFlags" -Value 1

# Habilitar LSA Protection
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1

# Configurar WDigest para no almacenar credenciales en texto plano
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0

# Restricciones de servicios remotos
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 0
```

### Configuraciones de GPO críticas

```powershell
# Configurar políticas de Privileged Access Workstations
# Computer Configuration\Policies\Administrative Templates\System\Credentials Delegation:
# "Allow delegating default credentials" = Disabled
# "Allow delegating default credentials with NTLM-only server authentication" = Disabled

# Configurar restricciones de servicios administrativos
# Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment:
# "Log on as a service" = Solo cuentas específicas de servicio
# "Act as part of the operating system" = Solo SYSTEM
```

### Scripts de validación y detección

```powershell
# Verificar Credential Guard
$credGuard = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "LsaCfgFlags" -ErrorAction SilentlyContinue
if ($credGuard.LsaCfgFlags -eq 1) {
    Write-Host "✓ Credential Guard habilitado" -ForegroundColor Green
} else {
    Write-Host "✗ HABILITAR Credential Guard" -ForegroundColor Red
}

# Verificar LSA Protection
$lsaPPL = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
if ($lsaPPL.RunAsPPL -eq 1) {
    Write-Host "✓ LSA Protection habilitado" -ForegroundColor Green
} else {
    Write-Host "✗ HABILITAR LSA Protection" -ForegroundColor Red
}

# Detectar herramientas de movimiento lateral
Get-Process | Where-Object {$_.ProcessName -match "(psexec|wmiexec|crackmapexec|nxc|winrs)"} |
ForEach-Object {
    Write-Warning "Herramienta de movimiento lateral detectada: $($_.ProcessName) PID:$($_.Id)"
}

# Monitorear conexiones administrativas sospechosas
$adminConnections = Get-NetTCPConnection | Where-Object {$_.LocalPort -in @(445,135,5985,5986) -and $_.State -eq "Established"}
$adminConnections | Group-Object RemoteAddress | Where-Object Count -gt 3 |
ForEach-Object {
    Write-Warning "Múltiples conexiones administrativas desde: $($_.Name) - $($_.Count) conexiones"
}
```

### Scripts de respuesta a incidentes

```powershell
# Script para resetear credenciales comprometidas
function Reset-CompromisedCredentials {
    param($ComputerName)
    
    # Resetear contraseña de cuenta de máquina
    Reset-ComputerMachinePassword -Credential (Get-Credential) -Server $ComputerName
    
    # Limpiar tickets Kerberos
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {klist purge}
    
    # Reiniciar servicios críticos
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        Restart-Service -Name "Netlogon" -Force
        Restart-Service -Name "LanmanServer" -Force
    }
}
```

### Actualizaciones críticas de seguridad

- **CVE-2020-1472**: Zerologon - facilita movimiento lateral masivo (KB4556836)
- **CVE-2021-36934**: HiveNightmare - acceso a credenciales locales (KB5005101)
- **CVE-2022-26925**: LSA spoofing que facilita movimiento lateral (KB5014754)
- **CVE-2019-1384**: Escalada de privilegios que puede usarse en movimiento lateral (KB4524244)

---

## 📚 Referencias

- [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec)
- [nxc - SMB offensive tool](https://github.com/OfensiveSecurity/nxc)
- [Impacket](https://github.com/fortra/impacket)
- [Hardening Svcctl - Microsoft Docs](https://learn.microsoft.com/es-es/windows/security/threat-protection/windows-authentication/service-control-manager-hardening)
