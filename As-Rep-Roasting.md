# 🛑 AS-REP Roasting en Active Directory

---

## 📝 ¿Qué es AS-REP Roasting?

| Concepto      | Descripción                                                                                                   |
|---------------|--------------------------------------------------------------------------------------------------------------|
| **Definición**| Técnica que permite a un atacante solicitar tickets AS-REP Kerberos de cuentas con preautenticación deshabilitada y crackear los hashes offline. |
| **Requisito** | La cuenta objetivo debe tener deshabilitada la opción **"Do not require Kerberos preauthentication"**.        |

---

## 🛠️ ¿Cómo funciona el ataque?

| Fase             | Acción                                                                                         |
|------------------|------------------------------------------------------------------------------------------------|
| **Enumeración**  | El atacante identifica cuentas vulnerables vía LDAP/AD.                                         |
| **Solicitud**    | Solicita AS-REP (AS-REQ sin preautenticación) al KDC para esas cuentas.                        |
| **Obtención**    | El KDC responde con el ticket cifrado con el hash de la contraseña de la cuenta.               |
| **Crackeo**      | El atacante extrae el hash y lo crackea offline (ej: Hashcat, John the Ripper).                |

---

## 💻 Ejemplo práctico

```bash
python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py essos.local/daenerys.targaryen -request
```

```
Name       MemberOf  PasswordLastSet             LastLogon                   UAC      
---------  --------  --------------------------  --------------------------  --------
missandei            2025-02-26 09:30:35.437503  2025-05-23 07:05:19.141162  0x410200 

$krb5asrep$23$missandei@ESSOS.LOCAL:600c153e69bd4899e402b6d1aad05e4f$1c5e29ec6f2e26b7d3738f19108a0b9b03ffa7ce3480e02f885bafe0de2668d499f23b6b034be320ee03ba64e70f4f3171c5bd59c0afdd1d79e0f64fcc1d138[...]
```

---

## 📊 Detección en logs y SIEM

| Campo clave                   | Descripción                                           |
|-------------------------------|------------------------------------------------------|
| **EventCode = 4768**          | Solicitud de TGT (AS-REQ) en Kerberos.               |
| **Pre_Authentication_Type=0** | Sin preautenticación: señal de AS-REP Roasting.      |
| **Account_Name**              | Cuenta solicitada.                                   |
| **Client_Address**            | IP origen de la petición.                            |
| **Ticket_Encryption_Type**    | Tipo de cifrado (analítico).                         |

### Query Splunk básica

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4768 Pre_Authentication_Type=0
| table _time, ComputerName, Account_Name, Client_Address, Ticket_Encryption_Type
```

---

## 🔎 Queries completas para más investigación

### 1. Solicitudes repetidas a varias cuentas desde una misma IP

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4768 Pre_Authentication_Type=0
| stats count by Client_Address, Account_Name
| where count > 3
```

---

### 2. Solicitudes a cuentas privilegiadas

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4768 Pre_Authentication_Type=0
| search Account_Name="Administrator" OR Account_Name="krbtgt" OR Account_Name="*svc*" OR Account_Name="*admin*"
| table _time, Account_Name, Client_Address
```

---

### 3. Correlación con otros eventos sospechosos del mismo origen

```splunk
index=dc_logs (sourcetype=WinEventLog:Security AND (EventCode=4768 OR EventCode=4625 OR EventCode=4740))
| search Client_Address="IP_SOSPECHOSA"
| sort _time
```

---

### 4. Cambios en cuentas (preautenticación deshabilitada recientemente)

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4738
| search "Do not require Kerberos preauthentication"=TRUE
| table _time, Target_Account_Name, ComputerName, Subject_Account_Name
```

---

### 5. Solicitudes desde redes externas o no confiables

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4768 Pre_Authentication_Type=0
| search NOT (Client_Address="10.*" OR Client_Address="192.168.*" OR Client_Address="172.16.*" OR Client_Address="127.0.0.1")
| table _time, Account_Name, Client_Address
```

### 6. Solicitudes externas mostrando todos los usuarios que han hecho logon antes del 4768

```splunk
index=dc_logs sourcetype=WinEventLog:Security EventCode=4768 Pre_Authentication_Type=0
| search NOT (Client_Address="10.*" OR Client_Address="192.168.*" OR Client_Address="172.16.*" OR Client_Address="127.0.0.1")
| rename Account_Name as asrep_user, Client_Address as asrep_ip, _time as asrep_time
| join asrep_ip [
    search index=dc_logs sourcetype=WinEventLog:Security EventCode=4624
    | rename Account_Name as logon_user, IpAddress as logon_ip, _time as logon_time
    | table logon_user, logon_ip, logon_time
]
| where logon_ip=asrep_ip AND logon_time < asrep_time
| table asrep_time, asrep_user, asrep_ip, logon_user, logon_time
| sort asrep_time, asrep_ip, logon_time
```

### 7. Analizar los resultados en función de la presencia o ausencia de logons previos

```splunk

... | stats count by asrep_time, asrep_ip | where count=0

```
---

## 🛡️ Hardening y mitigación

| Medida                                   | Descripción                                                                                  |
|-------------------------------------------|---------------------------------------------------------------------------------------------|
| **Activar preautenticación**              | Desactiva la opción **"No requerir preautenticación Kerberos"** en todas las cuentas.        |
| **Revisar cuentas sensibles**             | Verifica que cuentas privilegiadas y de servicio tengan preautenticación habilitada.         |
| **Contraseñas robustas**                  | Usa contraseñas largas y complejas, dificultando el crackeo offline.                        |
| **Monitorización**                        | Vigila eventos 4768 con Pre_Authentication_Type=0 y correlaciona IPs sospechosas.           |
| **Auditoría periódica**                   | Busca cuentas vulnerables a AS-REP Roasting periódicamente.                                 |
| **No exponer controladores de dominio**   | Mantén DCs y cuentas AD fuera de alcance de redes públicas/no confiables.                   |

---

## 🛡️ Soluciones y Hardening frente a AS-REP Roasting

El KDC (servicio Kerberos) **no tiene una opción directa para bloquear AS-REQ anónimos**, pero sí puedes aplicar varias medidas para reducir la superficie de ataque y dificultar el AS-REP Roasting.

---

### 1. Restringir consultas LDAP anónimas

Esto evita que atacantes sin credenciales puedan **enumerar usuarios del dominio vía LDAP**.

En el controlador de dominio:

1. Abre la consola de políticas de seguridad local (`secpol.msc`) y ve a:

   ```
   Directiva de seguridad local > Directivas locales > Opciones de seguridad >
   Acceso de red: no permitir enumeración anónima de cuentas y recursos SAM
   ```

2. Activa las siguientes opciones:
   - **Acceso de red: no permitir la enumeración anónima de cuentas SAM**
   - **Acceso de red: no permitir la enumeración anónima de cuentas y recursos SAM**

Esto **no bloquea el AS-REQ anónimo en Kerberos**, pero sí hace más difícil que un atacante sepa qué cuentas existen.

---

### 2. Evitar cuentas con "No requerir preautenticación"

**¡La contramedida principal!**  
Asegúrate de que **ninguna cuenta** tenga la opción **“No requerir preautenticación Kerberos”**.

Así, aunque un atacante pueda adivinar el nombre de usuario, **nunca recibirá el hash Kerberos (AS-REP) sin autenticarse**.

---

### 3. Forzar requerir autenticación para servicios LDAP y Kerberos

#### LDAP:

Edita el registro para impedir el acceso anónimo:

- **Clave:**
  ```
  HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
  ```
- **Valor (REG_DWORD):**
  ```
  "LDAPServerIntegrity"=2
  ```
Esto fuerza la integridad y autenticación para LDAP.

#### Kerberos:

No existe una GPO específica para impedir AS-REQ anónimos, porque el protocolo asume siempre que el usuario existe o no, y solo entrega el ticket si la cuenta está vulnerable.

---

### 4. Restringir acceso de red al KDC y a los DCs

- Solo permite acceso desde redes internas de confianza.
- **No expongas controladores de dominio a Internet** o a redes no confiables.

---

### 5. Resumen rápido

| Acción                                                    | ¿Bloquea AS-REQ anónimo? | ¿Dificulta ASREPRoasting? | Notas                                         |
|-----------------------------------------------------------|:------------------------:|:------------------------:|-----------------------------------------------|
| Restringir LDAP anónimo                                   | ✅                        | ✅                        | No pueden enumerar usuarios fácilmente         |
| Quitar "No requerir preautenticación" a todas las cuentas | ❌                        | ✅                        | Defensa real ante AS-REP Roasting              |
| Restringir acceso red a DCs/KDC                           | ✅                        | ✅                        | Evita ataques remotos                          |
| Forzar autenticación LDAP                                 | ✅                        | ❌                        | Solo evita enumeración, no AS-REP Roasting     |

---

## 🧰 ¿Cómo revisar o identificar la preautenticación de una cuenta?

```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```
O revisa en la consola de Active Directory:  
Propiedades de usuario → Cuenta → Opciones de cuenta →  
**"No requerir preautenticación Kerberos"** (debe estar desmarcada).

---

## Otros datos

➡️ Modo sin credenciales (anónimo):  
• Puedes usar la herramienta sin usuario ni contraseña (por ejemplo, solo con una lista de usuarios).

• ¿Por qué? Porque la consulta del ticket AS-REP no requiere autenticación si la cuenta está mal configurada.

• La herramienta envía, para cada usuario de la lista, una petición AS-REQ al controlador de dominio preguntando:  
“¿Me das un ticket para este usuario?”.

• Si el usuario no requiere preautenticación, el DC responde con el ticket AS-REP.

• Si la cuenta sí requiere preautenticación, el controlador rechaza la petición (no responde con el ticket).

➡️ Modo autenticado (con usuario/contraseña):  
• Puedes también lanzar la herramienta con un usuario y una contraseña del dominio.

• Esto sirve en entornos donde el controlador de dominio no permite consultas anónimas (más restrictivo) o donde necesitas enumerar usuarios reales.

• La herramienta se conecta autenticándose con el usuario y puede pedir tickets para otros usuarios del dominio.

---

## 📚 Referencias

- [AS-REP Roasting - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/as-rep-roasting)
- [Impacket GetNPUsers](https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py)
