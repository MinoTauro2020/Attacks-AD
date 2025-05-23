# Técnicas de Suplantación/Impersonation en Active Directory – Explicación Detallada

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

| Aspecto         | Detalle                                                                                         |
|-----------------|-----------------------------------------------------------------------------------------------|
| **Descripción** | Solicitar tickets Kerberos a cuentas sin preautenticación y crackear offline su hash.          |
| **Herramientas**| Rubeus, GetNPUsers.py                                                                         |
| **Condiciones** | Cuenta con preauth deshabilitado                                                              |

| Falsos positivos frecuentes         | Cómo verificar                                                        | Qué investigar si es positivo                  |
|-------------------------------------|-----------------------------------------------------------------------|------------------------------------------------|
| Auditorías y escaneos legítimos.    | Revisar logs de solicitud AS-REP, origen y frecuencia, intento de crackeo. | Cuenta afectada, uso del hash, acceso posterior. |

[Volver al índice](#índice-de-técnicas)

---

## 2. Certificate-Based Impersonation (ADCS Abuse)

| Aspecto         | Detalle                                                                                                  |
|-----------------|---------------------------------------------------------------------------------------------------------|
| **Descripción** | Abusar de CA/plantillas vulnerables para obtener certificados que permitan suplantar usuarios.           |
| **Herramientas**| Certify, Rubeus, ForgeCert, Certipy                                                                      |
| **Condiciones** | CA mal configurada, permisos sobre plantillas                                                           |

| Falsos positivos frecuentes                | Cómo verificar                                 | Qué investigar si es positivo                              |
|--------------------------------------------|------------------------------------------------|------------------------------------------------------------|
| Renovaciones automáticas y solicitudes legítimas. | Revisar plantilla usada, UPN, uso del certificado. | Privilegios del certificado, uso para TGT/TGS, acceso posterior. |

[Volver al índice](#índice-de-técnicas)

---

## 3. DCShadow Attack

| Aspecto         | Detalle                                                                                      |
|-----------------|---------------------------------------------------------------------------------------------|
| **Descripción** | Crear un DC falso que replica cambios maliciosos (contraseñas, atributos) en AD.            |
| **Herramientas**| Mimikatz                                                                                    |
| **Condiciones** | Privilegios de Domain Admin, acceso a red interna                                           |

| Falsos positivos frecuentes         | Cómo verificar                                              | Qué investigar si es positivo            |
|-------------------------------------|-------------------------------------------------------------|------------------------------------------|
| Replicación/mantenimiento legítimo. | Buscar eventos 4662, DC emisor, cambios en atributos críticos. | Objeto/cuenta cambiada, acceso posterior, persistencia. |

[Volver al índice](#índice-de-técnicas)

---

## 4. Golden Ticket Attack

| Aspecto         | Detalle                                                                                                 |
|-----------------|--------------------------------------------------------------------------------------------------------|
| **Descripción** | Creación de un TGT falso usando el hash de KRBTGT; acceso ilimitado como cualquier usuario.            |
| **Herramientas**| Mimikatz, ticketer.py                                                                                  |
| **Condiciones** | Hash KRBTGT (privilegios de Domain Admin)                                                              |

| Falsos positivos frecuentes                  | Cómo verificar                                    | Qué investigar si es positivo                       |
|----------------------------------------------|---------------------------------------------------|-----------------------------------------------------|
| Cambios administrativos legítimos, tickets corruptos. | Tickets con lifetime/SID inusual, eventos 4769 y 4624. | Uso del ticket, máquina origen, recursos accedidos. |

[Volver al índice](#índice-de-técnicas)

---

## 5. Kerberoasting

| Aspecto         | Detalle                                                                                                 |
|-----------------|--------------------------------------------------------------------------------------------------------|
| **Descripción** | Solicitar TGS de cuentas de servicio (SPN) y crackear offline su hash.                                 |
| **Herramientas**| Rubeus, GetUserSPNs.py                                                                                 |
| **Condiciones** | Cuentas con SPN y contraseña débil                                                                     |

| Falsos positivos frecuentes               | Cómo verificar                       | Qué investigar si es positivo                |
|-------------------------------------------|--------------------------------------|----------------------------------------------|
| Consultas administrativas de SPNs, escaneos. | Solicitudes TGS masivas, intento de crackeo. | Cuenta de servicio comprometida, privilegios y accesos. |

[Volver al índice](#índice-de-técnicas)

---

## 6. Kerberos Constrained Delegation (KCD) Abuse

| Aspecto         | Detalle                                                                                                 |
|-----------------|--------------------------------------------------------------------------------------------------------|
| **Descripción** | Cuenta con KCD puede pedir tickets en nombre de cualquiera a servicios concretos.                      |
| **Herramientas**| Rubeus                                                                                                 |
| **Condiciones** | Control sobre cuenta/máquina con KCD                                                                   |

| Falsos positivos frecuentes            | Cómo verificar                                       | Qué investigar si es positivo                      |
|----------------------------------------|------------------------------------------------------|----------------------------------------------------|
| Delegación legítima, cambios en servicios. | Cambios recientes en msDS-AllowedToDelegateTo, uso de S4U2Proxy. | Usuarios suplantados, servicios accedidos, movimiento lateral. |

[Volver al índice](#índice-de-técnicas)

---

## 7. Kerberos Unconstrained Delegation

| Aspecto         | Detalle                                                                                                 |
|-----------------|--------------------------------------------------------------------------------------------------------|
| **Descripción** | Extraer TGTs de usuarios que se conecten a un host con delegación sin restricciones.                   |
| **Herramientas**| Mimikatz, Rubeus                                                                                       |
| **Condiciones** | Control sobre host vulnerable, usuarios objetivo que inicien sesión                                    |

| Falsos positivos frecuentes                | Cómo verificar                                 | Qué investigar si es positivo                |
|--------------------------------------------|------------------------------------------------|----------------------------------------------|
| Migraciones, administración legítima.      | Creación/exportación de tickets en sistemas inesperados. | Cuentas comprometidas, uso de tickets, persistencia. |

[Volver al índice](#índice-de-técnicas)

---

## 8. Lateral Movement via SMB/Token/Ticket

| Aspecto         | Detalle                                                                                                 |
|-----------------|--------------------------------------------------------------------------------------------------------|
| **Descripción** | Movimiento lateral usando hashes, tickets o tokens robados.                                             |
| **Herramientas**| Mimikatz, CrackMapExec, Rubeus, Impacket                                                               |
| **Condiciones** | Hashes, tickets, permisos admin, SMB/WinRM habilitado                                                  |

| Falsos positivos frecuentes | Cómo verificar                                | Qué investigar si es positivo                |
|-----------------------------|-----------------------------------------------|----------------------------------------------|
| Herramientas de administración, IT interno. | Origen/destino de autenticación, accesos inusuales. | Credenciales usadas, recursos accedidos, propagación. |

[Volver al índice](#índice-de-técnicas)

---

## 9. MSSQL Impersonation (EXECUTE AS)

| Aspecto         | Detalle                                                                                                 |
|-----------------|--------------------------------------------------------------------------------------------------------|
| **Descripción** | Uso de EXECUTE AS en SQL Server para asumir identidad de otro usuario.                                 |
| **Herramientas**| SSMS, mssqlclient.py                                                                                   |
| **Condiciones** | Permiso EXECUTE AS o CONTROL en SQL Server                                                            |

| Falsos positivos frecuentes          | Cómo verificar                              | Qué investigar si es positivo                |
|--------------------------------------|---------------------------------------------|----------------------------------------------|
| Administración/desarrollo legítimo.  | Logs SQL, comandos EXECUTE AS, eventos 4624/4634. | Privilegios ganados, accesos y cambios en datos. |

[Volver al índice](#índice-de-técnicas)

---

## 10. NTLM/SMB Relay

| Aspecto         | Detalle                                                                                                 |
|-----------------|--------------------------------------------------------------------------------------------------------|
| **Descripción** | Relay de autenticaciones NTLM para acceder con privilegios del usuario autenticado.                    |
| **Herramientas**| ntlmrelayx.py, Responder                                                                               |
| **Condiciones** | Captura de autenticaciones NTLM, SMB signing deshabilitado                                             |

| Falsos positivos frecuentes           | Cómo verificar                          | Qué investigar si es positivo                |
|---------------------------------------|------------------------------------------|----------------------------------------------|
| Pentesting interno, tráfico de descubrimiento. | Logs SMB, intentos de relay, accesos tras relay. | Sistemas accedidos, acciones ejecutadas.     |

[Volver al índice](#índice-de-técnicas)

---

## 11. Overpass-the-Certificate (Pass-the-Cert)

| Aspecto         | Detalle                                                                                                 |
|-----------------|--------------------------------------------------------------------------------------------------------|
| **Descripción** | Usar un certificado válido para solicitar TGT Kerberos y suplantar usuario.                            |
| **Herramientas**| Rubeus                                                                                                 |
| **Condiciones** | Certificado exportable válido, plantilla vulnerable                                                    |

| Falsos positivos frecuentes            | Cómo verificar                                  | Qué investigar si es positivo                |
|----------------------------------------|-------------------------------------------------|----------------------------------------------|
| Renovación/migración legítima de certificados. | Emisión/uso de certificados, solicitud de TGT con certificado. | Cuentas suplantadas, acceso privilegiado.    |

[Volver al índice](#índice-de-técnicas)

---

## 12. Overpass-the-Hash (OpTH)

| Aspecto         | Detalle                                                                                                 |
|-----------------|--------------------------------------------------------------------------------------------------------|
| **Descripción** | Usar hash NTLM para solicitar un TGT Kerberos y autenticarse vía Kerberos.                             |
| **Herramientas**| Rubeus, Mimikatz                                                                                       |
| **Condiciones** | Hash NTLM válido, acceso Kerberos en red                                                               |

| Falsos positivos frecuentes       | Cómo verificar                                 | Qué investigar si es positivo                |
|-----------------------------------|------------------------------------------------|----------------------------------------------|
| Herramientas de auditoría, scripts internos. | Solicitudes TGT inusuales, logon anómalo.     | Recursos accedidos, propagación del ataque.  |

[Volver al índice](#índice-de-técnicas)

---

## 13. Pass-the-Hash (PtH)

| Aspecto         | Detalle                                                                                                 |
|-----------------|--------------------------------------------------------------------------------------------------------|
| **Descripción** | Usar el hash NTLM de un usuario para autenticarse sin contraseña.                                      |
| **Herramientas**| Mimikatz, CrackMapExec                                                                                 |
| **Condiciones** | Hash NTLM válido, SMB/WinRM habilitado                                                                 |

| Falsos positivos frecuentes         | Cómo verificar                              | Qué investigar si es positivo                |
|-------------------------------------|---------------------------------------------|----------------------------------------------|
| Administración/pentesting.          | Logs de autenticación con hash, origen inesperado. | Recursos accedidos, persistencia, movimiento lateral. |

[Volver al índice](#índice-de-técnicas)

---

## 14. Pass-the-Key (PTK)

| Aspecto         | Detalle                                                                                                 |
|-----------------|--------------------------------------------------------------------------------------------------------|
| **Descripción** | Usar claves AES Kerberos extraídas de memoria para generar tickets.                                    |
| **Herramientas**| Mimikatz                                                                                               |
| **Condiciones** | Claves AES en memoria, privilegios elevados                                                            |

| Falsos positivos frecuentes         | Cómo verificar                           | Qué investigar si es positivo                |
|-------------------------------------|------------------------------------------|----------------------------------------------|
| Backups, migraciones legítimas.     | Creación de tickets con claves inusuales. | Uso de tickets, escalada de privilegios.     |

[Volver al índice](#índice-de-técnicas)

---

## 15. Pass-the-Ticket (PtT)

| Aspecto         | Detalle                                                                                                 |
|-----------------|--------------------------------------------------------------------------------------------------------|
| **Descripción** | Inyectar un ticket Kerberos (.kirbi) robado/generado para acceder a recursos.                          |
| **Herramientas**| Mimikatz, Rubeus                                                                                       |
| **Condiciones** | Ticket Kerberos válido (.kirbi)                                                                        |

| Falsos positivos frecuentes      | Cómo verificar                              | Qué investigar si es positivo                |
|----------------------------------|---------------------------------------------|----------------------------------------------|
| Pruebas administrativas.         | Uso de tickets en equipos no habituales.    | Recursos accedidos, propagación del ticket.  |

[Volver al índice](#índice-de-técnicas)

---

## 16. Resource-Based Constrained Delegation (RBCD)

| Aspecto         | Detalle                                                                                                 |
|-----------------|--------------------------------------------------------------------------------------------------------|
| **Descripción** | Modificar RBCD para que una máquina controlada actúe por otros usuarios.                               |
| **Herramientas**| Rubeus, PowerView, Impacket                                                                            |
| **Condiciones** | Permiso de escritura sobre RBCD de la máquina objetivo                                                 |

| Falsos positivos frecuentes       | Cómo verificar                              | Qué investigar si es positivo                |
|-----------------------------------|---------------------------------------------|----------------------------------------------|
| Cambios legítimos en delegación.  | Cambios recientes en RBCD, quién y para qué máquina. | Suplantación de cuentas, acceso a recursos críticos. |

[Volver al índice](#índice-de-técnicas)

---

## 17. S4U (Service-for-User) Delegation Abuse

| Aspecto         | Detalle                                                                                                 |
|-----------------|--------------------------------------------------------------------------------------------------------|
| **Descripción** | Abusar S4U2Self/S4U2Proxy para obtener tickets de servicio como otro usuario.                          |
| **Herramientas**| Rubeus                                                                                                 |
| **Condiciones** | Control sobre cuenta con derechos de delegación                                                        |

| Falsos positivos frecuentes         | Cómo verificar                      | Qué investigar si es positivo                |
|-------------------------------------|-------------------------------------|----------------------------------------------|
| Procesos legítimos de delegación.   | Logs de uso de S4U, cuentas suplantadas. | Recursos accedidos, movimiento lateral.      |

[Volver al índice](#índice-de-técnicas)

---

## 18. Shadow Credentials

| Aspecto         | Detalle                                                                                                 |
|-----------------|--------------------------------------------------------------------------------------------------------|
| **Descripción** | Añadir credencial de clave a objeto AD para obtener TGT usando certificados.                           |
| **Herramientas**| Whisker, Certify                                                                                       |
| **Condiciones** | Permiso de escritura sobre el objeto AD                                                                |

| Falsos positivos frecuentes         | Cómo verificar                          | Qué investigar si es positivo                |
|-------------------------------------|------------------------------------------|----------------------------------------------|
| Cambios administrativos, scripts de gestión. | Cambios en atributos, uso de certificado. | Acceso privilegiado, recursos accedidos.     |

[Volver al índice](#índice-de-técnicas)

---

## 19. SID History Injection

| Aspecto         | Detalle                                                                                                 |
|-----------------|--------------------------------------------------------------------------------------------------------|
| **Descripción** | Inyectar SIDs históricos en un usuario para heredar permisos de otros.                                 |
| **Herramientas**| Mimikatz                                                                                               |
| **Condiciones** | Privilegios Domain Admin                                                                               |

| Falsos positivos frecuentes         | Cómo verificar                    | Qué investigar si es positivo                |
|-------------------------------------|-----------------------------------|----------------------------------------------|
| Migraciones de dominio.             | Cambios recientes en SIDHistory.  | Permisos heredados, accesos realizados.      |

[Volver al índice](#índice-de-técnicas)

---

## 20. Silver Ticket Attack

| Aspecto         | Detalle                                                                                                 |
|-----------------|--------------------------------------------------------------------------------------------------------|
| **Descripción** | Crear TGS falso para un servicio usando el hash NT de la cuenta de servicio.                           |
| **Herramientas**| Mimikatz, Rubeus                                                                                       |
| **Condiciones** | Hash NT de la cuenta de servicio, datos del SPN                                                        |

| Falsos positivos frecuentes         | Cómo verificar                          | Qué investigar si es positivo                |
|-------------------------------------|------------------------------------------|----------------------------------------------|
| Tickets corruptos, pruebas.         | Tickets fuera del KDC, uso en recursos críticos. | Servicio accedido, persistencia o escalada.  |

[Volver al índice](#índice-de-técnicas)

---

## 21. Token Impersonation & Token Stealing

| Aspecto         | Detalle                                                                                                 |
|-----------------|--------------------------------------------------------------------------------------------------------|
| **Descripción** | Robar/duplicar tokens de otros usuarios para ejecutar procesos bajo su identidad.                      |
| **Herramientas**| Mimikatz, Incognito                                                                                    |
| **Condiciones** | Privilegios elevados, acceso local                                                                     |

| Falsos positivos frecuentes         | Cómo verificar                      | Qué investigar si es positivo                |
|-------------------------------------|-------------------------------------|----------------------------------------------|
| Herramientas administrativas.       | Procesos bajo cuentas inesperadas.  | Acciones realizadas, acceso/exfiltración de datos. |

[Volver al índice](#índice-de-técnicas)

---
