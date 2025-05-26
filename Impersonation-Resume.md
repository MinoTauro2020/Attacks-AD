# Tabla de Técnicas de Suplantación/Impersonation en Active Directory 

| Nº | Técnica                                       | Descripción breve                                                                              | Herramientas principales                  |
|----|-----------------------------------------------|-----------------------------------------------------------------------------------------------|-------------------------------------------|
| 1  | AS-REP Roasting                              | Solicitar ticket AS-REP de cuentas sin preauth y crackear el hash offline.                    | Rubeus, GetNPUsers.py (Impacket)          |
| 2  | Certificate-Based Impersonation (ADCS Abuse) | Abusar de una CA vulnerable para emitir certificados que permiten obtener TGTs.               | Certify, Rubeus, ForgeCert                |
| 3  | DCShadow Attack                              | Crear DC falso para empujar cambios en objetos AD (ejemplo: contraseñas).                     | Mimikatz                                  |
| 4  | Golden Ticket Attack                         | Crear TGT falso usando hash de KRBTGT del dominio.                                            | Mimikatz, Impacket (ticketer.py)          |
| 5  | Kerberoasting                                | Solicitar TGS de cuentas de servicio y crackear su hash offline.                              | Rubeus, GetUserSPNs.py (Impacket)         |
| 6  | Kerberos Constrained Delegation (KCD) Abuse  | Solicitar TGS en nombre de cualquier usuario hacia servicios específicos si controlas cuenta. | Rubeus                                    |
| 7  | Kerberos Unconstrained Delegation            | Extraer TGT de usuarios que se conectan a sistemas con delegación sin restricciones.          | Mimikatz, Rubeus                          |
| 8  | Lateral Movement via SMB/Token/Ticket        | Movimiento lateral usando SMB, tokens o tickets (varias técnicas).                            | Mimikatz, Rubeus, CrackMapExec, Impacket  |
| 9  | MSSQL Impersonation (EXECUTE AS)             | Usar `EXECUTE AS` en SQL Server para impersonar a otro usuario.                               | SSMS, mssqlclient.py                      |
| 10 | NTLM/SMB Relay                               | Relayear autenticaciones NTLM para acceso con privilegios del usuario autenticado.            | ntlmrelayx.py, Responder                  |
| 11 | Overpass-the-Certificate (Pass-the-Cert)     | Usar un certificado válido para autenticarse en Kerberos.                                     | Rubeus                                    |
| 12 | Overpass-the-Hash (OpTH)                     | Convertir hash NTLM en TGT Kerberos.                                                          | Rubeus, Mimikatz                          |
| 13 | Pass-the-Hash (PtH)                          | Usar hash NTLM para autenticarse sin conocer la contraseña.                                   | Mimikatz, CrackMapExec                    |
| 14 | Pass-the-Key (PTK)                           | Usar claves AES Kerberos para generar tickets.                                                | Mimikatz                                  |
| 15 | Pass-the-Ticket (PtT)                        | Inyectar ticket Kerberos (.kirbi) en sesión para acceder a recursos.                          | Mimikatz, Rubeus                          |
| 16 | Resource-Based Constrained Delegation (RBCD) | Modificar RBCD para que máquina controlada actúe por otros usuarios en recursos específicos.  | Rubeus, PowerView, Impacket               |
| 17 | S4U (Service-for-User) Delegation Abuse      | Abusar de delegación S4U2Self/S4U2Proxy para obtener tickets en nombre de otros usuarios.     | Rubeus                                    |
| 18 | Shadow Credentials                           | Añadir credencial de clave a objeto AD para obtener TGT con certificados.                     | Whisker, Certify                          |
| 19 | SID History Injection                        | Inyectar SIDs históricos a un usuario para heredar permisos de otros.                         | Mimikatz                                  |
| 20 | Silver Ticket Attack                         | Crear TGS falso para un servicio usando hash NT de la cuenta de servicio.                     | Mimikatz, Rubeus                          |
| 21 | Token Impersonation & Token Stealing         | Robar/duplicar tokens de acceso de otros usuarios en Windows.                                 | Mimikatz, Incognito                       |

---
