# 🛑 AS-REP Roasting en Active Directory

---

## 📝 ¿Qué es AS-REP Roasting?

| Concepto          | Descripción                                                                                          |
|-------------------|------------------------------------------------------------------------------------------------------|
| **Definición**    | Técnica que permite a un atacante solicitar tickets AS-REP Kerberos de cuentas con preautenticación deshabilitada y crackear los hashes offline. |
| **Requisito**     | La cuenta objetivo debe tener deshabilitada la opción **"Do not require Kerberos preauthentication"**. |

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

$krb5asrep$23$missandei@ESSOS.LOCAL:600c153e69bd4899e402b6d1aad05e4f$1c5e29ec6f2e26b7d3738f19108a0b9b03ffa7ce3480e02f885bafe0de2668d499f23b6b034be320ee03ba64e70f4f3171c5bd59c0afdd1d79e0f64fcc1d13880691ea432a88a2c4f780d5765c000e802d10f1eac3590db4a0306187596f4d4166446e014eda622cb6b7565e305bddb2fefcf4248dc3819d0561d088f1d4ac1f19335f2fe54b5088b45764f6bd6aeec4970bcf7c83f9f985fa257b27e9c77800d25980f23b3f76454e93cf2ae31f7841fa40834b6fb42a11f7a6751aeed4dc5cd5981c5ca05120b419974cfdf400617d2b8cb8e8cea4f9232276f37cd48c845ad83aa12251d73bf05446
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

## 🔍 ¿Qué buscar además en la detección?

| Detección avanzada                                     | Query Splunk sugerida                                                                                                                                    |
|--------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| **1. Solicitudes repetidas desde la misma IP**         | ```splunk<br>index=dc_logs sourcetype=WinEventLog:Security EventCode=4768 Pre_Authentication_Type=0<br>| stats count by Client_Address, Account_Name<br>| where count > 3<br>``` |
| **2. Solicitudes a cuentas privilegiadas**             | ```splunk<br>index=dc_logs sourcetype=WinEventLog:Security EventCode=4768 Pre_Authentication_Type=0 (Account_Name="Administrator" OR Account_Name="krbtgt" OR Account_Name="*svc*" OR Account_Name="*admin*")<br>| table _time, Account_Name, Client_Address<br>``` |
| **3. Correlación con otros eventos sospechosos**       | ```splunk<br>index=dc_logs (sourcetype=WinEventLog:Security AND (EventCode=4768 OR EventCode=4625 OR EventCode=4740)) (Client_Address="IP_SOSPECHOSA")<br>| sort _time<br>``` |
| **4. Cambios de preautenticación en cuentas**          | ```splunk<br>index=dc_logs sourcetype=WinEventLog:Security EventCode=4738<br>| search "Do not require Kerberos preauthentication"=TRUE<br>| table _time, Target_Account_Name, ComputerName, Subject_Account_Name<br>``` |
| **5. Solicitudes desde redes externas/no confiables**  | ```splunk<br>index=dc_logs sourcetype=WinEventLog:Security EventCode=4768 Pre_Authentication_Type=0<br>| search NOT Client_Address="10.*" NOT Client_Address="192.168.*" NOT Client_Address="172.16.*" NOT Client_Address="127.0.0.1"<br>| table _time, Account_Name, Client_Address<br>``` |

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

## 🧰 ¿Cómo revisar la preautenticación de una cuenta?

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
