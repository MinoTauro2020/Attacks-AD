# 🛡️ Password Spray por Kerberos en Active Directory

---

## 📝 ¿Qué es un password spray por Kerberos?

| Concepto      | Descripción                                                                                    |
|---------------|------------------------------------------------------------------------------------------------|
| **Definición**| Ataque donde un adversario prueba una sola contraseña común contra muchos usuarios de dominio, usando Kerberos como vector. Evita bloqueos por umbral y maximiza el sigilo. |
| **Requisito** | Acceso en red al puerto Kerberos (88) del controlador de dominio. Los usuarios pueden ser enumerados previamente o deducidos.|

---

## 🛠️ ¿Cómo funciona el ataque?

| Fase               | Acción                                                                                                   |
|--------------------|----------------------------------------------------------------------------------------------------------|
| **Enumeración**    | El atacante recopila usuarios válidos del dominio (LDAP, scripts, dumps, OSINT, etc).                    |
| **Automatización** | Herramientas como Rubeus, CrackMapExec, Kerbrute, Impacket, Python o scripts caseros lanzan miles de tickets TGT (AS-REQ). |
| **Validación**     | El DC responde: si el usuario existe y la contraseña es correcta, éxito; si no, error específico (4768/4771). |
| **Evasión**        | El atacante alterna usuarios y contraseñas para evitar bloqueos y detección por volumen.                  |

---

## 💻 Ejemplo práctico

```bash
kerbrute passwordspray -d essos.local --users usuarios.txt --passwords passwords.txt --no-save-cred 192.168.1.5
```
o con CrackMapExec:
```bash
cme kerberos 192.168.1.5 -u usuarios.txt -p passwords.txt --no-bruteforce-lockout
```

---

## 📊 Detección en logs y SIEM

| Campo clave                   | Descripción                                                                                      |
|-------------------------------|-------------------------------------------------------------------------------------------------|
| **EventCode = 4768**          | Solicitud de TGT (AS-REQ). Fallos y éxitos de autenticación Kerberos.                           |
| **EventCode = 4771**          | Fallos de autenticación Kerberos (preautenticación fallida, contraseña incorrecta, usuario no existe...). |
| **Client_Address/IP**         | IP origen del intento de autenticación.                                                         |
| **Account_Name/User**         | Usuario objetivo del intento de login.                                                          |
| **Failure_Code/Result_Code**  | Motivo del fallo (usuario no existe: 0x6, password incorrecta: 0x18, cuenta bloqueada: 0x12...).|

### Ejemplo de eventos relevantes

```
EventCode=4768
Client Address: 192.168.57.151
Account Name: daenerys.targaryen
Result Code: 0x6

EventCode=4771
Client Address: 192.168.57.151
Account Name: drogon
Failure Code: 0x18
```

---

## 🔎 Queries Splunk para hunting

### 1. Detección de password spray (muchos 4768/4771 por IP/usuario en poco tiempo)

```splunk
index=dc_logs (EventCode=4768 OR EventCode=4771)
| eval tipo=case(EventCode==4768,"solicitud_kerberos", EventCode==4771,"fallo_kerberos")
| eval src_ip=coalesce(Client_Address, ip)
| eval usuario=coalesce(Account_Name, user)
| bucket _time span=3m
| stats count as total_intentos, values(tipo) as tipos, values(Failure_Code) as fallos by _time, src_ip, usuario
| where total_intentos > 10
| sort -_time
```
> _Alerta si en 3 minutos hay más de 10 intentos Kerberos para el mismo usuario/IP._

### 2. Cuentas inexistentes o patrones de diccionario

```splunk
index=dc_logs (EventCode=4768 OR EventCode=4771)
| rex field=Message "Result Code:\s+(?<ResultCode>0x[0-9A-Fa-f]+)"
| eval user_no_existe=if(ResultCode=="0x6",1,0)
| where user_no_existe=1 OR match(Account_Name, "\.(txt|csv|docx|log|ini)$") OR match(Account_Name, "^[0-9]+$") OR match(Account_Name, "^[\.\-_]")
| stats count by _time, src_ip, Account_Name
```
> _Ideal para detectar password spray tosco: si ves nombres tipo .txt/.csv o muchas cuentas inexistentes, tienes ataque automatizado claro._

---

## ⚡️ Alertas recomendadas

| Alerta                                  | Descripción                                                                                 |
|------------------------------------------|--------------------------------------------------------------------------------------------|
| **Alerta 1**                            | Más de 10 eventos 4768/4771 por la misma IP/usuario en 3 minutos.                          |
| **Alerta 2**                            | Secuencia de cuentas inexistentes o nombres de diccionario en intentos Kerberos.           |

---

## 🦾 Hardening y mitigación

| Medida                                   | Descripción                                                                                 |
|-------------------------------------------|--------------------------------------------------------------------------------------------|
| **Bloqueo por umbral**                    | Si una IP/usuario supera X intentos fallidos en Y minutos, bloquea temporalmente.          |
| **Deshabilitar cuentas trampa/legacy**    | Elimina cuentas antiguas o crea honeypots para detectar actividad anómala.                 |
| **Obligar contraseñas robustas**          | Minimiza el riesgo de éxito en password spray.                                             |
| **Normalización de logs**                 | Unifica formato de usuario/IP para no perder correlaciones.                                |
| **Segmentación de red**                   | Restringe acceso Kerberos solo a lo necesario.                                             |
| **Alertas y dashboards en SIEM**          | Implementa alertas específicas y paneles de intentos Kerberos sospechosos.                 |
| **Lista negra temporal**                  | IPs que repitan patrón de ataque, a watchlist para seguimiento proactivo.                  |

---

## 🧑‍💻 ¿Cómo probar password spray Kerberos en laboratorio?

```bash
kerbrute passwordspray -d essos.local --users usuarios.txt --passwords passwords.txt 192.168.1.5
```
o con CrackMapExec:
```bash
cme kerberos 192.168.1.5 -u usuarios.txt -p passwords.txt
```

---

## 📚 Referencias

- [Kerberos Password Spray Detection - SigmaHQ](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_kerberos_password_spray.yml)
- [Kerbrute](https://github.com/ropnop/kerbrute)
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
