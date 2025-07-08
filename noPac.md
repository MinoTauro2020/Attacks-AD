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
| **Manipulación**    | Cambia el nombre/SAMAccountName de la máquina para imitar un DC.                                       |
| **Ticket Kerberos** | Solicita TGT/TGS como esa máquina, engañando al KDC y obteniendo privilegios de administrador de dominio. |
| **Explotación**     | Usa el ticket para ejecutar comandos como SYSTEM, abrir shells remotas y extraer hashes desde el DC.    |
| **Limpieza**        | Borra la cuenta de máquina para eliminar huellas.                                                      |

---

## 💻 Ejemplo práctico

```bash
# Crear cuenta de máquina y cambiar atributos
python3 nopac.py --action addcomputer --computer-name FAKE-DC$ --computer-pass 'Password123!'
python3 nopac.py --action modcomputer --computer-name FAKE-DC$ --newname DC01$

# Solicitar TGT como DC comprometido
getST.py -dc-ip 192.168.1.10 ESSOS.LOCAL/DC01\$ -impersonate administrator

# Usar el ticket para obtener shell como SYSTEM
psexec.py -k -no-pass ESSOS.LOCAL/administrator@dc01.essos.local
```

---

## 📊 Detección en logs y SIEM

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

### Query Splunk básica

```splunk
index=dc_logs (EventCode=4741 OR EventCode=4742 OR EventCode=4743 OR EventCode=4768 OR EventCode=4769 OR EventCode=4624 OR EventCode=7045 OR EventCode=5140 OR EventCode=4662)
| sort _time
| table _time, EventCode, TargetAccountName, SubjectAccountName, host, Client_Address
```

---

## 🔎 Queries avanzadas de investigación

### 1. Secuencia completa de ataque noPac

```splunk
index=dc_logs (EventCode=4741 OR EventCode=4742 OR EventCode=4743 OR EventCode=4768 OR EventCode=4769 OR EventCode=4624 OR EventCode=7045 OR EventCode=5140 OR EventCode=4662)
| sort _time
| transaction TargetAccountName maxspan=30m startswith=(EventCode=4741)
| table _time, EventCode, TargetAccountName, SubjectAccountName, host, Client_Address
```

### 2. Cuentas de máquina nuevas que solicitan tickets Kerberos

```splunk
index=dc_logs (EventCode=4741 OR EventCode=4768 OR EventCode=4769)
| stats min(_time) as created, max(_time) as ticket_time by TargetAccountName
| where ticket_time - created < 1800
```

### 3. Creación y borrado rápido de cuentas de máquina

```splunk
index=dc_logs (EventCode=4741 OR EventCode=4743)
| stats min(_time) as created, max(_time) as deleted by TargetAccountName
| eval diff=deleted-created
| where diff < 1800
```

### 4. Servicios remotos y cambios en cuentas de máquina

```splunk
index=dc_logs (EventCode=7045 OR EventCode=4742)
| table _time, EventCode, TargetAccountName, SubjectAccountName, host
```

---

## 🦾 Hardening, mitigación y soluciones innovadoras

| Medida                                  | Descripción                                                                                      |
|------------------------------------------|-------------------------------------------------------------------------------------------------|
| **MachineAccountQuota = 0**              | Solo los administradores pueden crear cuentas de máquina.                                        |
| **Parchear DCs**                         | Aplica todas las actualizaciones acumulativas desde nov/dic 2021 (CVE-2021-42278 y 42287).       |
| **Alerta por secuencia completa**        | No solo un evento: correlaciona creación, modificación y uso de cuentas de máquina.              |
| **Honeytokens de máquina**               | Crea cuentas de máquina trampa y alerta si se usan.                                              |
| **Auditoría avanzada y logs grandes**    | Habilita directivas de auditoría avanzada y sube el tamaño del log de seguridad.                 |
| **Permisos de delegación restringidos**  | No uses “Permitir delegación a cualquier servicio”. Segmenta y revisa delegaciones periódicamente.|
| **Monitoriza cambios en msDS-AllowedToActOnBehalfOfOtherIdentity** | Detección avanzada de persistencia oculta.                                     |

---

## 🧑‍💻 Comprobación y configuración rápida

### Cambiar MachineAccountQuota a 0

```powershell
Set-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=essos,DC=local" -Replace @{ms-DS-MachineAccountQuota=0}
```

### Ver cuentas de máquina creadas recientemente

```powershell
Get-ADComputer -Filter * | Where-Object { $_.WhenCreated -gt (Get-Date).AddDays(-7) }
```

---

## 🚨 Respuesta ante incidentes

1. **Aísla el DC sospechoso**.
2. **Resetea o elimina cuentas de máquina anómalas**.
3. **Purge tickets Kerberos activos** (`klist purge`).
4. **Revisa creación de servicios y binarios extraños**.
5. **Informa, documenta y revisa delegaciones y permisos**.
6. **Haz análisis forense de los artefactos y secuencia de eventos**.

---

## 📚 Referencias

- [noPac - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/privilege-escalation/nopac)
- [Microsoft Security Update Guide](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278)
- [Impacket](https://github.com/fortra/impacket)
