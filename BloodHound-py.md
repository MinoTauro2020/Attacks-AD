# 🩸 Reconocimiento y mapeo de Active Directory con BloodHound.py

---

## 📝 ¿Qué es BloodHound.py y por qué es tan crítico?

| Concepto      | Descripción                                                                                                 |
|---------------|------------------------------------------------------------------------------------------------------------|
| **Definición**| Ingestor de datos en Python para BloodHound que enumera y mapea Active Directory remotamente sin necesidad de agentes. Identifica rutas de ataque, relaciones de confianza y privilegios elevados. |
| **Uso**       | Herramienta de reconocimiento que recopila información crítica sobre usuarios, grupos, equipos, GPOs y relaciones de confianza para identificar vectores de escalada de privilegios y movimiento lateral. |

---

## 🛠️ ¿Cómo funciona el ataque? (paso a paso real)

| Fase             | Acción                                                                                                          |
|------------------|-----------------------------------------------------------------------------------------------------------------|
| **Autenticación**| El atacante se autentica contra el dominio usando credenciales válidas (usuario/contraseña o hash).            |
| **Enumeración**  | Consulta LDAP/LDAPS para enumerar usuarios, grupos, equipos, GPOs y relaciones organizacionales.              |
| **Mapeo**        | Identifica miembros de grupos privilegiados, delegaciones Kerberos, ACLs y permisos de objetos críticos.      |
| **Análisis**     | Procesa los datos recopilados para identificar rutas de ataque y vectores de escalada de privilegios.          |
| **Explotación**  | Utiliza la información para planificar ataques dirigidos (Kerberoasting, ASREPRoast, delegación, etc.).       |

---

## 💻 Ejemplo ofensivo (comandos reales)

```bash
# Recopilación básica con credenciales
bloodhound-python -d essos.local -u usuario -p 'contraseña' -gc controlador.essos.local -c all

# Usando hash NTLM en lugar de contraseña
bloodhound-python -d essos.local -u usuario --hashes aad3b435b51404eeaad3b435b51404ee:5e8a0123456789abcdef0123456789ab -gc controlador.essos.local -c all

# Enumeración específica (solo usuarios y grupos)
bloodhound-python -d essos.local -u usuario -p 'contraseña' -gc controlador.essos.local -c Users,Groups

# Con autenticación Kerberos (ccache)
export KRB5CCNAME=/tmp/usuario.ccache
bloodhound-python -d essos.local -k -gc controlador.essos.local -c all

# Salida a archivo específico
bloodhound-python -d essos.local -u usuario -p 'contraseña' -gc controlador.essos.local -c all --zip
```

---

## 📊 Detección en Splunk

| Evento clave | Descripción                                                                                                   |
|--------------|--------------------------------------------------------------------------------------------------------------|
| **4776**     | Autenticación NTLM del atacante contra el controlador de dominio.                                           |
| **4624**     | Inicio de sesión exitoso (tipo 3/red) con las credenciales utilizadas.                                      |
| **4768/4769**| Solicitudes de tickets Kerberos TGT/TGS para autenticación.                                                 |
| **5156**     | Conexiones LDAP/LDAPS hacia el controlador de dominio (puerto 389/636).                                     |
| **4662**     | Operaciones de objeto realizadas - acceso a objetos críticos del directorio.                                |
| **4661**     | Manejo de objeto solicitado - acceso a atributos específicos de AD.                                         |

### Query Splunk esencial

```splunk
index=dc_logs (EventCode=4662 OR EventCode=4661)
| search (Object_Type="*user*" OR Object_Type="*group*" OR Object_Type="*computer*" OR Object_Type="*organizationalUnit*")
| search Properties="*member*" OR Properties="*memberOf*" OR Properties="*servicePrincipalName*" OR Properties="*msDS-AllowedToDelegateTo*"
| stats count by _time, Account_Name, Source_Address, Object_Name, Properties
| where count > 50
```

### Query para detectar enumeración masiva

```splunk
index=dc_logs EventCode=4662
| search Object_Type="*user*" OR Object_Type="*group*" OR Object_Type="*computer*"
| stats dc(Object_Name) as objetos_unicos, count by Account_Name, Source_Address, _time
| where objetos_unicos > 100 OR count > 500
| table _time, Account_Name, Source_Address, objetos_unicos, count
```

### Query para correlacionar secuencias sospechosas

```splunk
index=dc_logs (EventCode=4768 OR EventCode=4769 OR EventCode=4662 OR EventCode=5156)
| bin _time span=5m
| stats values(EventCode) as eventos, dc(Object_Name) as objetos by _time, Account_Name, Source_Address
| where objetos > 50
| table _time, Account_Name, Source_Address, eventos, objetos
```

---

## 🛡️ Detección con Windows Defender for Endpoint

### Reglas de detección personalizadas

```kql
// BloodHound-py - Detección de enumeración LDAP masiva
DeviceNetworkEvents
| where RemotePort == 389 or RemotePort == 636
| where ActionType == "ConnectionSuccess"
| summarize ConnectionCount = count() by DeviceId, RemoteIP, bin(Timestamp, 5m)
| where ConnectionCount > 50
| order by ConnectionCount desc
```

```kql
// Detección de herramientas BloodHound
DeviceProcessEvents
| where ProcessCommandLine has_any ("bloodhound-python", "bloodhound.py", "sharphound", "azurehound")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

```kql
// Detección de consultas LDAP anómalas
DeviceEvents
| where ActionType == "LdapQuery"
| where AdditionalFields has_any ("member", "memberof", "objectclass", "distinguishedname")
| summarize QueryCount = count() by DeviceId, AccountName, bin(Timestamp, 5m)
| where QueryCount > 100
| order by QueryCount desc
```

### Alertas recomendadas

| Regla | Descripción | Severidad |
|-------|-------------|-----------|
| **LDAP Enumeration Spike** | Más de 50 consultas LDAP en 5 minutos | Media |
| **BloodHound Tools** | Detección de herramientas de enumeración conocidas | Alta |
| **Mass LDAP Queries** | Consultas LDAP masivas para enumeración de AD | Media |

---

## 🦅 Detección con CrowdStrike Falcon

### Hunting queries (Event Search)

```sql
-- Detección de BloodHound basado en consultas LDAP
event_platform=Win event_simpleName=LdapSearch
| bin _time span=5m
| stats count as query_count, values(SearchFilter) as filters by ComputerName, UserName, _time
| where query_count > 100
| sort - query_count
```

```sql
-- Detección de herramientas BloodHound
event_platform=Win event_simpleName=ProcessRollup2 
| search (FileName=*bloodhound* OR CommandLine=*bloodhound-python* OR CommandLine=*sharphound*)
| table _time, ComputerName, UserName, FileName, CommandLine, SHA256HashData
| sort - _time
```

```sql
-- Detección de conexiones LDAP masivas
event_platform=Win event_simpleName=NetworkConnectIP4
| search RemotePort IN (389, 636, 3268, 3269)
| bin _time span=5m
| stats count as connection_count by ComputerName, RemoteAddressIP4, RemotePort, _time
| where connection_count > 20
| sort - connection_count
```

### Custom IOAs (Indicators of Attack)

```sql
-- IOA para detectar enumeración de AD
event_platform=Win event_simpleName=DirectoryServiceAccess
| search ObjectDN=*
| bin _time span=2m
| stats dc(ObjectDN) as unique_objects by ComputerName, UserName, _time
| where unique_objects > 500
```

---

## 🔍 Queries KQL para Microsoft Sentinel

### Detección de BloodHound

```kql
// Query principal para detectar enumeración con BloodHound
SecurityEvent
| where EventID == 4662 // Directory service access
| where AccessMask != "0x0"
| summarize ObjectCount = dcount(ObjectName), AccessCount = count() by Account, Computer, bin(TimeGenerated, 5m)
| where ObjectCount > 100 or AccessCount > 500
| order by ObjectCount desc
```

```kql
// Correlación con herramientas conocidas
DeviceProcessEvents
| where ProcessCommandLine contains "bloodhound" or ProcessCommandLine contains "sharphound"
| join kind=inner (
    SecurityEvent
    | where EventID == 4662
    | project TimeGenerated, Computer, Account, ObjectName
) on $left.DeviceName == $right.Computer, $left.AccountName == $right.Account
| project TimeGenerated, DeviceName, ProcessCommandLine, ObjectName
```

### Hunting avanzado

```kql
// Detección de consultas LDAP específicas de BloodHound
Event
| where Source == "Microsoft-Windows-LDAP-Client" and EventID == 30
| where ParameterXml has_any ("member", "memberof", "distinguishedname", "objectsid")
| summarize QueryCount = count(), UniqueQueries = dcount(ParameterXml) by Computer, UserName, bin(TimeGenerated, 5m)
| where QueryCount > 50 or UniqueQueries > 20
| order by QueryCount desc
```

```kql
// Detección de acceso masivo a objetos de AD
SecurityEvent
| where EventID == 4662
| where ObjectServer == "DS"
| where Properties has_any ("{bf967aba-0de6-11d0-a285-00aa003049e2}", "{bf967a86-0de6-11d0-a285-00aa003049e2}")
| summarize by TimeGenerated, Account, Computer, ObjectName, Properties
| summarize ObjectCount = dcount(ObjectName) by Account, Computer, bin(TimeGenerated, 10m)
| where ObjectCount > 1000
| order by ObjectCount desc
```

---

## 🦾 Hardening y mitigación

| Medida                                  | Descripción                                                                                      |
|------------------------------------------|-------------------------------------------------------------------------------------------------|
| **Auditoría avanzada de AD**             | Habilita auditoría detallada de acceso a objetos del directorio y operaciones LDAP.            |
| **Restricción de consultas LDAP**        | Limita las consultas LDAP masivas y el acceso a atributos sensibles para usuarios no privilegiados. |
| **Honeytokens en AD**                    | Crea usuarios/grupos señuelo y alerta si son enumerados o accedidos.                           |
| **Segmentación de red**                  | Los usuarios normales no deberían poder conectar directamente a puertos LDAP del DC.           |
| **Limitación de permisos de lectura**    | Restringe permisos de lectura en objetos críticos solo a cuentas que realmente los necesiten.  |
| **Detección de comportamiento anómalo**  | Implementa detección de consultas LDAP masivas y accesos atípicos a objetos del directorio.    |
| **LDAP signing obligatorio**             | Exige firma LDAP para prevenir ataques man-in-the-middle.                                      |
| **Rate limiting LDAP**                   | Implementa límites de velocidad para consultas LDAP por usuario/IP.                            |

---

## 🚨 Respuesta ante incidentes

1. **Aísla la IP de origen** que realiza consultas LDAP masivas o accesos sospechosos.
2. **Investiga la cuenta comprometida** y revisa todos los objetos accedidos durante la enumeración.
3. **Busca actividad posterior** como Kerberoasting, ASREPRoast o intentos de escalada de privilegios.
4. **Revisa logs de autenticación** para identificar el vector de compromiso inicial.
5. **Cambia credenciales** de cuentas potencialmente expuestas y revisa permisos de delegación.
6. **Implementa monitoreo adicional** en cuentas de servicio y grupos privilegiados identificados.

---

## 💡 Soluciones innovadoras

- **Honeytokens dinámicos:** Crea usuarios señuelo con nombres atractivos que cambien periódicamente.
- **Deception en AD:** Implementa objetos falsos con permisos elevados para detectar reconocimiento.
- **ML para detección:** Utiliza machine learning para identificar patrones anómalos de consultas LDAP.
- **Respuesta automatizada:** Scripts que bloquean cuentas tras enumeración masiva de objetos críticos.
- **Ofuscación de información:** Limita la información visible en atributos no esenciales del directorio.

---

## ⚡ CVEs y técnicas MITRE relevantes

- **T1087.002 (Domain Account Discovery):** Enumeración de cuentas de dominio
- **T1482 (Domain Trust Discovery):** Descubrimiento de relaciones de confianza de dominio
- **T1069.002 (Domain Groups Discovery):** Enumeración de grupos de dominio
- **T1018 (Remote System Discovery):** Descubrimiento de sistemas remotos
- **T1083 (File and Directory Discovery):** Descubrimiento de archivos y directorios
- **T1033 (System Owner/User Discovery):** Descubrimiento de propietarios/usuarios del sistema

---

## 🔧 Parches y actualizaciones

| Parche/Update | Descripción                                                                                  |
|---------------|----------------------------------------------------------------------------------------------|
| **KB5025238** | Windows 11/10 - Mejoras en protección de consultas LDAP y limitación de enumeración.       |
| **KB5022906** | Windows Server 2022 - Fortalecimiento de controles de acceso LDAP y auditoría mejorada.    |
| **KB5022845** | Windows Server 2019 - Correcciones en permisos por defecto y limitación de acceso anónimo. |
| **KB4580390** | Windows Server 2016 - Parches para restringir enumeración vía LDAP y protocolos RPC.       |
| **KB5005413** | Todas las versiones - Mejoras en Channel Binding LDAP para prevenir enumeración.           |
| **LDAP Hardening Updates** | Actualizaciones específicas para limitar consultas de enumeración masiva.        |

### Configuraciones de registro críticas

```powershell
# Limitar consultas LDAP anónimas
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "DsHeuristics" -Value "001000001"

# Configurar auditoría detallada de acceso al directorio
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable

# Limitar tamaño de respuestas LDAP (anti-enumeración)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "MaxPageSize" -Value 100
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "MaxQueryDuration" -Value 300
```

### Configuraciones de GPO críticas

```powershell
# Configurar permisos restrictivos en AD
# Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options:
# "Network access: Allow anonymous SID/Name translation" = Disabled
# "Network access: Do not allow anonymous enumeration of SAM accounts" = Enabled

# Configurar políticas de acceso al directorio
# Remove "Everyone" from "Pre-Windows 2000 Compatible Access" group
Get-ADGroup "Pre-Windows 2000 Compatible Access" | Set-ADGroup -Clear member
```

### Scripts de validación y detección

```powershell
# Verificar configuraciones anti-enumeración
$ldapIntegrity = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue
if ($ldapIntegrity.LDAPServerIntegrity -eq 2) {
    Write-Host "✓ LDAP Server Integrity configurado" -ForegroundColor Green
} else {
    Write-Host "✗ CONFIGURAR LDAP Server Integrity" -ForegroundColor Red
}

# Detectar consultas LDAP masivas (tipo BloodHound)
$ldapEvents = Get-WinEvent -FilterHashtable @{LogName='Directory Service'; ID=1644,1645} -MaxEvents 100 -ErrorAction SilentlyContinue
$ldapEvents | Group-Object Properties[1] | Where-Object Count -gt 50 | 
ForEach-Object {
    Write-Warning "Enumeración masiva detectada desde: $($_.Name) - $($_.Count) consultas"
}

# Monitorear conexiones LDAP sospechosas
Get-NetTCPConnection | Where-Object {$_.LocalPort -eq 389 -or $_.LocalPort -eq 636} |
Group-Object RemoteAddress | Where-Object Count -gt 10 |
Select-Object Name, Count | Sort-Object Count -Descending
```

### Configuraciones defensivas específicas

```powershell
# Crear GPO para limitar herramientas de enumeración
# Computer Configuration\Policies\Administrative Templates\System:
# "Prevent access to the command prompt" = Enabled (for standard users)

# Configurar Windows Defender para detectar BloodHound
Add-MpPreference -AttackSurfaceReductionRules_Ids "e6db77e5-3df2-4cf1-b95a-636979351e5b" -AttackSurfaceReductionRules_Actions Enabled

# Implementar honeypots para detectar enumeración
New-ADUser -Name "HoneyPot_Admin" -Enabled $false -Description "Cuenta trampa para detectar enumeración"
```

### Actualizaciones críticas relacionadas

- **CVE-2022-26923**: Vulnerabilidad en certificados que facilita enumeración privilegiada (KB5014754)
- **CVE-2021-42278**: Spoofing que puede ser usado junto con enumeración (KB5008102)
- **CVE-2019-1040**: LDAP Channel Binding bypass usado en enumeración (KB4511553)
- **CVE-2020-1472**: Zerologon que facilita acceso para enumeración completa (KB4556836)

---

## 📚 Referencias

- [BloodHound.py - GitHub](https://github.com/dirkjanm/BloodHound.py)
- [BloodHound - GitHub](https://github.com/BloodHoundAD/BloodHound)
- [BloodHound Documentation](https://bloodhound.readthedocs.io/)
- [Active Directory Security - Microsoft Docs](https://learn.microsoft.com/es-es/windows-server/identity/ad-ds/plan/security-best-practices/)
- [MITRE ATT&CK - Discovery Techniques](https://attack.mitre.org/tactics/TA0007/)