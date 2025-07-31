# 🛡️ Fuerza Bruta por LDAP en Active Directory

---

## 📝 ¿Qué es la fuerza bruta por LDAP?

| Concepto      | Descripción                                                                                    |
|---------------|------------------------------------------------------------------------------------------------|
| **Definición**| Ataque en el que un adversario intenta adivinar contraseñas de usuarios del dominio mediante múltiples intentos de autenticación LDAP, generalmente usando scripts o herramientas automatizadas. |
| **Requisito** | Acceso en red al controlador de dominio y al puerto LDAP (389/636). Puede ser anónimo o desde cuentas con permisos mínimos.|

---

## 🛠️ ¿Cómo funciona el ataque?

| Fase               | Acción                                                                                                   |
|--------------------|----------------------------------------------------------------------------------------------------------|
| **Descubrimiento** | El atacante identifica usuarios válidos (por enumeración previa, listas filtradas, etc).                 |
| **Automatización** | Utiliza herramientas (Impacket, CrackMapExec, python-ldap, Hydra, scripts caseros) para lanzar intentos masivos de login. |
| **Autenticación**  | El DC recibe múltiples binds LDAP (simple o inseguro) y responde con éxito o error según la contraseña.   |
| **Evasión**        | Algunos atacantes espacian los intentos para evitar bloqueos o detección por umbral.                     |

---

## 💻 Ejemplo práctico


```
o con CrackMapExec:
```bash
cme ldap 192.168.1.5 -u usuarios.txt -p passwords.txt --no-bruteforce-lockout
```

---

## 📊 Detección en logs y SIEM

| Campo clave                   | Descripción                                                                                      |
|-------------------------------|-------------------------------------------------------------------------------------------------|
| **EventCode = 2889**          | Bind LDAP inseguro realizado (sin cifrado ni signing). Relevante para ataques legacy y modernos.|
| **EventCode = 4625**          | Fallo de inicio de sesión (incluye intentos LDAP fallidos).                                     |
| **Source_Network_Address/IP** | IP origen del intento de autenticación.                                                         |
| **Account_Name/User**         | Usuario objetivo del intento de login.                                                          |
| **Failure_Reason**            | Motivo del fallo (cuenta bloqueada, contraseña incorrecta, etc).                               |

### Ejemplo de eventos relevantes

```
EventCode=2889
Client IP address: 192.168.57.151:55932
Identity the client attempted to authenticate as: ESSOS\daenerys.targaryen

EventCode=4625
Source_Network_Address: 192.168.57.151
Account_Name: daenerys.targaryen
Failure_Reason: Account locked out.
```

---

## 🔎 Queries Splunk para hunting

### 1. Detección de fuerza bruta LDAP (muchos 2889 y/o 4625 por IP/usuario en poco tiempo)

```splunk
index=dc_logs (EventCode=2889 OR EventCode=4625)
| eval tipo=case(EventCode==2889,"ldap_inseguro", EventCode==4625,"fallo_login")
| eval src_ip=coalesce(ip, Source_Network_Address)
| eval usuario=coalesce(user, Account_Name)
| bucket _time span=3m
| stats count as total_intentos, values(tipo) as tipos, values(Failure_Reason) as fallos by _time, src_ip, usuario
| where total_intentos > 10
| sort -_time
```
> _Alerta si en 3 minutos hay más de 4 intentos (binds o fallos) para el mismo usuario/IP._

### 2. Correlación de bind LDAP inseguro seguido de fallo de login

```splunk
index=dc_logs (EventCode=2889 OR EventCode=4625)
| eval src_ip=coalesce(ip, Source_Network_Address)
| eval usuario=coalesce(user, Account_Name)
| sort 0 src_ip, usuario, _time
| streamstats current=f window=1 last(EventCode) as evento_anterior last(_time) as tiempo_anterior by src_ip, usuario
| where EventCode=4625 AND evento_anterior=2889 AND (_time - tiempo_anterior)<=120
| table tiempo_anterior evento_anterior _time EventCode src_ip usuario Failure_Reason
```
> _Muestra cuando un bind inseguro (2889) precede a un fallo de login (4625) para la misma IP y usuario en menos de 2 minutos._

---

## ⚡️ Alertas recomendadas

| Alerta                                  | Descripción                                                                                 |
|------------------------------------------|--------------------------------------------------------------------------------------------|
| **Alerta 1**                            | Más de 10 intentos de bind o login fallido LDAP por la misma IP/usuario en 3 minutos.      |
| **Alerta 2**                            | Secuencia 2889 seguido de 4625 para la misma IP/usuario en corto intervalo (fuerza bruta real).|

---

## 🦾 Hardening y mitigación

| Medida                                   | Descripción                                                                                 |
|-------------------------------------------|--------------------------------------------------------------------------------------------|
| **Deshabilitar LDAP inseguro**            | Obliga a usar LDAP firma y cifrado en DCs y clientes.                                      |
| **Bloqueo automático por umbral**         | Si una IP/usuario supera X intentos fallidos en Y minutos, bloquea temporalmente.          |
| **Normalización de logs**                 | Unifica formato de usuario/IP para no perder correlaciones.                                |
| **Segmentación de red**                   | Restringe acceso LDAP solo a sistemas y redes necesarios.                                  |
| **Alertas y dashboards en SIEM**          | Implementa alertas específicas y revisa paneles de intentos LDAP sospechosos.              |
| **Lista negra temporal**                  | IPs que repitan patrón de ataque, a watchlist para seguimiento proactivo.                  |

---

## 🧑‍💻 ¿Cómo probar fuerza bruta LDAP en laboratorio?

```bash
python3 /usr/share/doc/python3-impacket/examples/ldap_login.py essos.local/usuarios.txt contraseñas.txt
```
o con Hydra:
```bash
hydra -L usuarios.txt -P passwords.txt ldap://192.168.1.5
```

---

## 🔧 Parches y actualizaciones

| Parche/Update | Descripción                                                                                  |
|---------------|----------------------------------------------------------------------------------------------|
| **KB5025238** | Windows 11 22H2 - Mejoras en protección contra ataques de fuerza bruta LDAP.               |
| **KB5025221** | Windows 10 22H2 - Fortalecimiento de políticas de autenticación LDAP y auditoría.          |
| **KB5022906** | Windows Server 2022 - Mejoras en logging de conexiones LDAP y detección de anomalías.      |
| **KB5022845** | Windows Server 2019 - Correcciones en manejo de conexiones LDAP concurrentes.              |
| **KB4580390** | Windows Server 2016 - Parches para protección contra ataques LDAP de fuerza bruta.         |
| **LDAP Signing Updates** | Actualizaciones para forzar firma LDAP y prevenir ataques MitM.                |

### Configuraciones de registro recomendadas

```powershell
# Configurar LDAP signing obligatorio
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "RequireSignOrSeal" -Value 1

# Habilitar auditoría detallada de acceso a directorio
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable

# Configurar límites de conexiones LDAP
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "MaxConnections" -Value 50
```

### Configuraciones de GPO críticas

```powershell
# Política de firmas LDAP a nivel de dominio
# En Group Policy: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options
# "Domain controller: LDAP server signing requirements" = Require signing

# Configurar Channel Binding para LDAP
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -Value 2
```

### Actualizaciones críticas de seguridad

- **CVE-2022-26923**: Vulnerabilidad en autenticación LDAP que permite bypass (KB5014754)
- **CVE-2021-34470**: Bypass de políticas de autenticación LDAP (KB5005413)
- **CVE-2020-1472**: Zerologon - impacta también conexiones LDAP (KB4556836)
- **CVE-2019-1040**: Vulnerabilidad LDAP channel binding bypass (KB4511553)

### Herramientas de monitoreo avanzadas

```powershell
# Script para detectar intentos de brute force LDAP
$ldapEvents = Get-WinEvent -FilterHashtable @{LogName='Directory Service'; ID=2889,2887} -MaxEvents 100
$ldapEvents | Group-Object Properties[3] | Where-Object Count -gt 10 | Select-Object Name, Count

# Monitorear conexiones LDAP anómalas
Get-Counter "\NTDS\LDAP Bind Time" -MaxSamples 10 | Where-Object {$_.CounterSamples.CookedValue -gt 1000}
```

---

## 📚 Referencias

- [LDAP Brute Force Detection - SigmaHQ](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_ldap_brute_force.yml)
- [Impacket ldap_login.py](https://github.com/fortra/impacket/blob/master/examples/ldap_login.py)
