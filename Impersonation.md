# Tabla de Técnicas de Suplantación/Impersonation en Active Directory

| Nº | Técnica                                       | Descripción breve                                                                              | Herramientas principales                          | SO                |
|----|-----------------------------------------------|-----------------------------------------------------------------------------------------------|---------------------------------------------------|-------------------|
| 1  | Pass-the-Hash (PtH)                          | Usar hash NTLM para autenticarse sin conocer la contraseña.                                   | Mimikatz, CrackMapExec                            | Windows, Linux    |
| 2  | Overpass-the-Hash (OpTH)                     | Convertir hash NTLM en TGT Kerberos.                                                          | Rubeus, Mimikatz                                  | Windows           |
| 3  | Pass-the-Ticket (PtT)                        | Inyectar ticket Kerberos (.kirbi) en sesión para acceder a recursos.                          | Mimikatz, Rubeus                                  | Windows           |
| 4  | Pass-the-Key (PTK)                           | Usar claves AES Kerberos para generar tickets.                                                | Mimikatz                                          | Windows           |
| 5  | Silver Ticket Attack                         | Crear TGS falso para un servicio usando hash NT de la cuenta de servicio.                     | Mimikatz, Rubeus                                  | Windows           |
| 6  | Golden Ticket Attack                         | Crear TGT falso usando hash de KRBTGT del dominio.                                            | Mimikatz, Impacket (ticketer.py)                  | Windows, Linux    |
| 7  | S4U (Service-for-User) Delegation Abuse      | Abusar de delegación S4U2Self/S4U2Proxy para obtener tickets en nombre de otros usuarios.     | Rubeus                                            | Windows           |
| 8  | Shadow Credentials                           | Añadir credencial de clave a objeto AD para obtener TGT con certificados.                     | Whisker, Certify                                  | Windows           |
| 9  | Kerberos Unconstrained Delegation            | Extraer TGT de usuarios que se conectan a sistemas con delegación sin restricciones.          | Mimikatz, Rubeus                                  | Windows           |
| 10 | Kerberos Constrained Delegation (KCD) Abuse  | Solicitar TGS en nombre de cualquier usuario hacia servicios específicos si controlas cuenta. | Rubeus                                            | Windows           |
| 11 | Resource-Based Constrained Delegation (RBCD) | Modificar RBCD para que máquina controlada actúe por otros usuarios en recursos específicos.  | Rubeus, PowerView, Impacket                       | Windows, Linux    |
| 12 | NTLM/SMB Relay                               | Relayear autenticaciones NTLM para acceso con privilegios del usuario autenticado.            | ntlmrelayx.py, Responder                          | Linux, Windows    |
| 13 | MSSQL Impersonation (EXECUTE AS)             | Usar `EXECUTE AS` en SQL Server para impersonar a otro usuario.                              | SSMS, mssqlclient.py                              | Windows, Linux    |
| 14 | Token Impersonation & Token Stealing         | Robar/duplicar tokens de acceso de otros usuarios en Windows.                                 | Mimikatz, Incognito                               | Windows           |
| 15 | SID History Injection                        | Inyectar SIDs históricos a un usuario para heredar permisos de otros.                         | Mimikatz                                          | Windows           |
| 16 | DCShadow Attack                              | Crear DC falso para empujar cambios en objetos AD (ejemplo: contraseñas).                     | Mimikatz                                          | Windows           |
| 17 | Certificate-Based Impersonation (ADCS Abuse) | Abusar de una CA vulnerable para emitir certificados que permiten obtener TGTs.               | Certify, Rubeus, ForgeCert                        | Windows           |
| 18 | Overpass-the-Certificate (Pass-the-Cert)     | Usar un certificado válido para autenticarse en Kerberos.                                     | Rubeus                                            | Windows           |
| 19 | Kerberoasting                                | Solicitar TGS de cuentas de servicio y crackear su hash offline.                              | Rubeus, GetUserSPNs.py (Impacket)                 | Windows, Linux    |
| 20 | AS-REP Roasting                              | Solicitar ticket AS-REP de cuentas sin preauth y crackear el hash offline.                    | Rubeus, GetNPUsers.py (Impacket)                  | Windows, Linux    |

---
