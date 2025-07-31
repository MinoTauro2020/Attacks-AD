# 🛑 Kerberoasting en Active Directory

---

## 📝 ¿Qué es Kerberoasting?

| Concepto      | Descripción                                                                                                   |
|---------------|--------------------------------------------------------------------------------------------------------------|
| **Definición**| Técnica que permite a un atacante solicitar tickets de servicio (TGS) Kerberos para cuentas con SPN y crackear los hashes offline. |
| **Requisito** | El atacante debe tener acceso a una cuenta autenticada en el dominio y que existan cuentas de servicio con SPN configurado.        |

---

## 🛠️ ¿Cómo funciona el ataque?

| Fase             | Acción                                                                                         |
|------------------|------------------------------------------------------------------------------------------------|
| **Enumeración**  | El atacante identifica cuentas de servicio con SPN vía LDAP/AD o herramientas (Impacket, PowerView, etc). |
| **Solicitud**    | Solicita tickets de servicio (TGS) al KDC para esas cuentas de servicio.                       |
| **Obtención**    | El KDC responde con el ticket cifrado con el hash de la contraseña de la cuenta de servicio.   |
| **Crackeo**      | El atacante extrae el hash y lo crackea offline (ej: Hashcat, John the Ripper).                |

---

## 💻 Ejemplo práctico

```bash
python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py essos.local/daenerys.targaryen:'Dracarys123'
```

```
ServicePrincipalName         Name        MemberOf  PasswordLastSet             LastLogon                   Delegation  PwdNeverExpires  UAC      
---------------------------- ----------  --------  --------------------------  --------------------------  ----------  ---------------  --------
MSSQLSvc/meereen.essos.local:1433 sql_svc            2025-02-26 09:30:35.437503  2025-05-23 07:05:19.141162            False             0x410200 

$krb5tgs$23$*sql_svc$MSSQLSvc/meereen.essos.local*essos.local*$d21c1eebd2bfa64bd4f5f3a7c67cf885$aa3b1c1b1f2c3a2a0b7a5d0f0e0b6e5e6e4c3d2e1b0a0a0b0d0e0f0a0b0a0b0a0b0a0b0a0b0a0b0a0b0a0b0a0b0a0b0a0b0a0b
```

---

## 📊 Detección en logs y SIEM

| Campo clave                   | Descripción                                           |
|-------------------------------|------------------------------------------------------|
| **EventCode = 4769**          | Solicitud de ticket de servicio (TGS) en Kerberos.   |
| **Service_Name**              | Cuenta de servicio objetivo (con SPN).               |
| **Account_Name**              | Cuenta que solicita el ticket (atacante).            |
| **Client_Address**            | IP origen de la petición.                            |
| **Ticket_Encryption_Type**    | Tipo de cifrado (RC4, AES, etc).                     |

### Query Splunk básica

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| table _time, ComputerName, Account_Name, Service_Name, Client_Address, Ticket_Encryption_Type
```

---

## 🔎 Queries completas para más investigación

### 0 .Prioridad de cuentas

```splunk

index=dc_logs sourcetype=WinEventLog:Security EventCode=4769 Ticket_Encryption_Type="0x17"
| where match(Service_Name, "(?i)(admin|svc|sql|oracle|backup|db|service|root|sap)")
| stats count by Service_Name, Account_Name, Client_Address
| where count > 3
| sort -count
```

### 1. Solicitudes masivas de TGS desde una misma IP

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| stats count by Client_Address, Account_Name
| where count > 5
```

### 2. Solicitudes de TGS a cuentas privilegiadas o con SPN críticos

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| search Service_Name="*admin*" OR Service_Name="*svc*" OR Service_Name="MSSQLSvc*" OR Service_Name="HTTP/*"
| table _time, Service_Name, Account_Name, Client_Address
```

### 3. Solicitudes de TGS con cifrado RC4 (más vulnerable)

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769 Ticket_Encryption_Type=0x17
| table _time, Service_Name, Account_Name, Client_Address
```

### 4. Solicitudes desde redes externas o no confiables

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| search NOT (Client_Address="10.*" OR Client_Address="192.168.*" OR Client_Address="172.16.*" OR Client_Address="127.0.0.1")
| table _time, Service_Name, Account_Name, Client_Address
```

### 5. Correlación con logons recientes desde la misma IP

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| rename Account_Name as kerb_user, Client_Address as kerb_ip, _time as kerb_time
| join kerb_ip [
    search index=dc_logs sourcetype=WinEventLog:Security EventCode=4624
    | rename Account_Name as logon_user, IpAddress as logon_ip, _time as logon_time
    | table logon_user, logon_ip, logon_time
]
| where logon_ip=kerb_ip AND logon_time < kerb_time
| table kerb_time, kerb_user, kerb_ip, logon_user, logon_time
| sort kerb_time, kerb_ip, logon_time
```

### 6. Analizar tickets solicitados nunca usados (sin acceso real a servicios)

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4769
| join Service_Name [
    search index=dc_logs sourcetype=WinEventLog:Security EventCode=5140
    | rename Share_Name as Service_Name, IpAddress as Client_Address, _time as access_time
    | table Service_Name, Client_Address, access_time
]
| where isnull(access_time)
| table _time, Account_Name, Service_Name, Client_Address
```

### 7. Quien pide el TGS

```splunk
index="*" 4769
| where Ticket_Encryption_Type="0x17" OR Ticket_Encryption_Type="23"
| search Service_Name="*admin*" OR Service_Name="*svc*" OR Service_Name="MSSQLSvc*" OR Service_Name="HTTP/*" OR Service_Name="*sql*" OR Service_Name="*backup*"
| stats count by Account_Name, Service_Name, Client_Address
| where count > 3
| sort -count
```

---

## 🦾 Hardening y mitigación

| Medida                                   | Descripción                                                                                  |
|-------------------------------------------|---------------------------------------------------------------------------------------------|
| **Contraseñas robustas en cuentas SPN**   | Usa contraseñas largas y complejas en cuentas de servicio/SPN.                               |
| **Revisar cuentas privilegiadas con SPN** | Minimiza privilegios de cuentas con SPN, y usa cuentas dedicadas y gestionadas.              |
| **Monitorización continua**               | Vigila eventos 4769 y correlaciona con actividad sospechosa o inusual.                       |
| **Evitar RC4 en cuentas de servicio**     | Forzar cifrado AES en cuentas de servicio, deshabilitando RC4 si es posible.                 |
| **Rotación periódica de contraseñas**     | Cambia periódicamente contraseñas de cuentas de servicio con SPN.                             |
| **Segmentación de red**                   | Restringe acceso a servicios Kerberos solo a redes y usuarios necesarios.                     |
| **Auditoría periódica de SPNs**           | Revisa regularmente qué cuentas tienen SPN y si siguen siendo necesarias.                     |

---

## 🔧 Parches y actualizaciones

| Parche/Update | Descripción                                                                                  |
|---------------|----------------------------------------------------------------------------------------------|
| **KB5025238** | Windows 11 22H2 - Mejoras en cifrado AES para tickets TGS y mitigación de Kerberoasting.    |
| **KB5025221** | Windows 10 22H2 - Fortalecimiento de validaciones de SPN y auditoría de solicitudes TGS.    |
| **KB5022906** | Windows Server 2022 - Mejoras en logging de eventos 4769 con metadatos adicionales.         |
| **KB5022845** | Windows Server 2019 - Correcciones en manejo de tickets de servicio y cifrado RC4.          |
| **KB4580390** | Windows Server 2016 - Parches para desactivar cifrado RC4 en cuentas de servicio.          |
| **RSAT Updates** | Herramientas actualizadas para gestión de SPNs y políticas de cifrado Kerberos.      |

### Configuraciones de registro recomendadas

```powershell
# Deshabilitar cifrado RC4 en Kerberos (forzar AES)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "DefaultEncryptionType" -Value 0x18

# Habilitar auditoría detallada de TGS
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

# Configurar política de contraseñas robustas para cuentas de servicio
Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 25 -ComplexityEnabled $true
```

### Configuraciones de GPO recomendadas

```powershell
# Aplicar políticas de cifrado AES en todo el dominio
Set-ADDomainMode -Identity "midominio.local" -DomainMode Windows2016Domain
Set-ADForestMode -Identity "midominio.local" -ForestMode Windows2016Forest
```

### Actualizaciones críticas de seguridad

- **CVE-2022-37958**: Vulnerabilidad en validación de tickets TGS (parcheada en actualizaciones de noviembre 2022)
- **CVE-2021-42287**: sAMAccountName spoofing que facilita Kerberoasting (KB5008102)
- **CVE-2020-17049**: Vulnerabilidad en Kerberos KDC que permite bypass de validaciones (KB4586876)
- **CVE-2019-1384**: Escalada de privilegios via SPNs mal configurados (KB4524244)

---

## 🧑‍💻 ¿Cómo revisar cuentas con SPN en Active Directory?

```powershell
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName
```
O con Impacket desde Kali Linux:
```bash
python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py essos.local/usuario:contraseña
```

---

## 📚 Referencias

- [Kerberoasting - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoasting)
- [Impacket GetUserSPNs](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py)
