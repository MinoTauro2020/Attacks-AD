# 🛡️ Enumeración de Usuarios en Active Directory

---

## 📝 ¿Qué es la enumeración de usuarios?

| Concepto      | Descripción                                                                                    |
|---------------|------------------------------------------------------------------------------------------------|
| **Definición**| Proceso mediante el cual un atacante recopila la lista de usuarios de un dominio a través de consultas LDAP, SMB, RPC o acceso directo a la SAM. |
| **Requisito** | El atacante debe tener acceso autenticado al dominio, incluso con un usuario de bajo privilegio.|

---

## 🛠️ ¿Cómo funciona el ataque?

| Fase             | Acción                                                                                                 |
|------------------|--------------------------------------------------------------------------------------------------------|
| **Autenticación**| El atacante inicia sesión en el dominio (4624, 4776).                                                  |
| **Enumeración**  | Utiliza herramientas (NetExec, CrackMapExec, BloodHound, Impacket, scripts LDAP/RPC) para consultar usuarios. |
| **Obtención**    | El DC responde con objetos tipo `SAM_USER` (usuarios) y el atacante recibe/extrae la lista de cuentas.  |

---

## 💻 Ejemplo práctico

```bash
python3 /usr/share/doc/python3-impacket/examples/GetADUsers.py essos.local/daenerys.targaryen:'Dracarys123' -all
```

```
username              lastlogon              pwdlastset             description
--------------------- --------------------- ---------------------- -------------
jon.snow              2025-05-23 07:05:19   2025-02-26 09:30:35    Lord Commander
arya.stark            2025-05-21 11:15:42   2025-03-12 08:12:12    No One
...
```

---

## 📊 Detección en logs y SIEM

| Campo clave                   | Descripción                                                                                      |
|-------------------------------|-------------------------------------------------------------------------------------------------|
| **EventCode = 4661**          | Acceso a objeto protegido AD; clave: muchos accesos a `SAM_USER` (usuarios) en poco tiempo.     |
| **Object_Type = SAM_USER**    | Indica acceso a un objeto de usuario (local o dominio).                                         |
| **Object_Name = SID**         | SID del usuario accedido (cambia en cada acceso).                                               |
| **Accesses = DELETE/READ**    | Permisos solicitados. Muchos accesos simultáneos, sobre todo DELETE/READ, son sospechosos.      |
| **Account_Name**              | Cuenta que realiza la enumeración (a veces una cuenta de equipo en procesos automáticos).       |
| **Process_Name**              | Proceso que accede (ej: `C:\Windows\System32\lsass.exe`).                                       |
| **Client_Address**            | IP origen de la petición (si disponible).                                                       |

### Ejemplo de evento 4661 relevante

```
A handle to an object was requested.
Subject:
    Account Name:      MEEREEN$
    Account Domain:    ESSOS
    Logon ID:          0x3E7
Object:
    Object Type:       SAM_USER
    Object Name:       S-1-5-21-2000378473-4079260497-750590020-1112
Process Information:
    Process Name:      C:\Windows\System32\lsass.exe
Access Request Information:
    Accesses:          DELETE READ_CONTROL WRITE_DAC ...
```

---

## 🔎 Queries Splunk para hunting

### 1. Detección de enumeración masiva (muchos 4661 sobre distintos SAM_USER en poco tiempo)

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4661 Object_Type=SAM_USER
| bucket _time span=1m
| stats dc(Object_Name) as unique_users, values(Object_Name) as users, count by _time, Account_Name, Process_Name
| where unique_users > 12
| sort -_time
```
> _Alerta si en 1 minuto hay accesos a más de 12 SIDs distintos de usuario (`SAM_USER`) por la misma cuenta/proceso._

### 2. Patrón tras autenticación (4624 → muchos 4661)

```splunk
index=dc_logs sourcetype=WinEventLog:Security (EventCode=4624 OR EventCode=4661)
| transaction Account_Name maxspan=2m
| search EventCode=4624 AND EventCode=4661
| table _time, Account_Name, host, EventCode
```

### 3. Excluir cuentas/procesos legítimos

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4661 Object_Type=SAM_USER
| search NOT (Account_Name="MEEREEN$" OR Account_Name="backup" OR Process_Name="C:\\Windows\\System32\\lsass.exe")
| stats count by _time, Account_Name, Process_Name
```

---

## ⚡️ Alertas recomendadas

| Alerta                                        | Descripción                                                                    |
|-----------------------------------------------|--------------------------------------------------------------------------------|
| **Alerta 1**                                 | Más de 12 accesos 4661 a SIDs distintos de `SAM_USER` por el mismo usuario/proceso en 1 minuto. |
| **Alerta 2**                                 | Patrón de 4624 seguido rápidamente de muchos 4661 por el mismo usuario/IP.      |
| **Alerta 3**                                 | Accesos DELETE/READ sobre muchos `SAM_USER` en poco tiempo por cuentas no habituales.|

---

## 🦾 Hardening y mitigación

| Medida                                   | Descripción                                                                                  |
|-------------------------------------------|---------------------------------------------------------------------------------------------|
| **Auditoría avanzada en objetos clave**   | Configura SACLs para auditar accesos a usuarios críticos o grupos sensibles.                 |
| **Exclusión de cuentas legítimas**        | Excluye del alertado cuentas de equipo o procesos de sistema conocidos.                      |
| **Monitorización continua**               | Vigila patrones de eventos 4661 y correlación con actividad inusual.                         |
| **Segmentación de red**                   | Restringe acceso a DCs solo a redes y usuarios necesarios.                                   |
| **Alertas y dashboards en SIEM**          | Implementa alertas ante patrones de enumeración y revisa dashboards periódicamente.           |

---

## 🧑‍💻 ¿Cómo revisar usuarios en Active Directory?

```powershell
Get-ADUser -Filter * -Properties *
```
O con Impacket desde Kali Linux:
```bash
python3 /usr/share/doc/python3-impacket/examples/GetADUsers.py essos.local/usuario:contraseña -all
```

---

## 🔧 Parches y actualizaciones

| Parche/Update | Descripción                                                                                  |
|---------------|----------------------------------------------------------------------------------------------|
| **KB5025238** | Windows 11/10 - Mejoras en protección contra enumeración de usuarios vía múltiples métodos.|
| **KB5022906** | Windows Server 2022 - Fortalecimiento de controles de acceso para consultas de usuarios.   |
| **KB5022845** | Windows Server 2019 - Correcciones en permisos por defecto y limitación de acceso anónimo. |
| **KB4580390** | Windows Server 2016 - Parches para restringir enumeración vía SMB, RPC y LDAP.             |
| **KB5005413** | Todas las versiones - Mejoras en autenticación para prevenir enumeración no autorizada.    |
| **Anonymous Access Updates** | Actualizaciones para limitar acceso anónimo y enumeración de usuarios.        |

### Configuraciones de registro críticas

```powershell
# Restringir enumeración anónima de usuarios
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1

# Limitar consultas RPC anónimas
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -Value 0

# Configurar auditoría de enumeración
auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
```

### Configuraciones de GPO críticas

```powershell
# Configurar políticas anti-enumeración
# Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options:
# "Network access: Do not allow anonymous enumeration of SAM accounts" = Enabled
# "Network access: Do not allow anonymous enumeration of SAM accounts and shares" = Enabled
# "Network access: Restrict anonymous access to Named Pipes and Shares" = Enabled

# Configurar permisos restrictivos
Remove-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" -Members "Everyone" -Confirm:$false
```

### Scripts de validación post-configuración

```powershell
# Verificar configuraciones anti-enumeración
$restrictAnon = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -ErrorAction SilentlyContinue
if ($restrictAnon.RestrictAnonymous -eq 2) {
    Write-Host "✓ RestrictAnonymous configurado correctamente" -ForegroundColor Green
} else {
    Write-Host "✗ CONFIGURAR RestrictAnonymous = 2" -ForegroundColor Red
}

# Verificar permisos del grupo Pre-Windows 2000 Compatible Access
$preW2kGroup = Get-ADGroupMember "Pre-Windows 2000 Compatible Access" | Where-Object {$_.Name -eq "Everyone"}
if (-not $preW2kGroup) {
    Write-Host "✓ Everyone removido de Pre-Windows 2000 Compatible Access" -ForegroundColor Green
} else {
    Write-Host "✗ REMOVER Everyone de Pre-Windows 2000 Compatible Access" -ForegroundColor Red
}

# Detectar intentos de enumeración
$enumEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4798,4799} -MaxEvents 50 -ErrorAction SilentlyContinue
$enumEvents | Group-Object Properties[1] | Where-Object Count -gt 10 |
ForEach-Object {
    Write-Warning "Enumeración de usuarios detectada desde: $($_.Name) - $($_.Count) intentos"
}
```

### Scripts de detección específicos

```powershell
# Monitorear consultas LDAP de enumeración masiva
$ldapEvents = Get-WinEvent -FilterHashtable @{LogName='Directory Service'; ID=1644} -MaxEvents 100 -ErrorAction SilentlyContinue
$ldapEvents | Where-Object {$_.Message -like "*objectClass=user*"} |
Group-Object Properties[3] | Where-Object Count -gt 20 |
ForEach-Object {
    Write-Warning "Enumeración masiva de usuarios via LDAP: IP $($_.Name) - $($_.Count) consultas"
}

# Detectar herramientas de enumeración comunes
Get-Process | Where-Object {$_.ProcessName -match "(enum4linux|rpcclient|ldapsearch|net\.exe)"} |
ForEach-Object {
    Write-Warning "Herramienta de enumeración detectada: $($_.ProcessName) PID:$($_.Id)"
}
```

### Actualizaciones críticas relacionadas

- **CVE-2022-26923**: Vulnerabilidad que puede facilitar enumeración privilegiada (KB5014754)
- **CVE-2021-42278**: Spoofing que combinado con enumeración puede ser crítico (KB5008102)
- **CVE-2019-1040**: Bypass que facilita enumeración no autorizada (KB4511553)
- **CVE-2020-1472**: Zerologon que permite enumeración completa post-explotación (KB4556836)

---

## 📚 Referencias

- [User Enumeration in AD - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/domain-user-enumeration)
- [Impacket GetADUsers](https://github.com/fortra/impacket/blob/master/examples/GetADUsers.py)
