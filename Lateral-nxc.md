# 🛑 Movimiento lateral y ejecución remota en Windows vía svcctl (SMB)

---

## 📝 ¿Qué es svcctl y por qué es tan crítico?

| Concepto      | Descripción                                                                                                 |
|---------------|------------------------------------------------------------------------------------------------------------|
| **Definición**| Canalización nombrada (named pipe) utilizada por el Service Control Manager para gestionar servicios de Windows de forma remota. Permite crear, modificar, arrancar o eliminar servicios vía SMB. |
| **Uso**       | Herramientas ofensivas como CrackMapExec, nxc, Impacket, PsExec y similares abusan de svcctl para ejecutar comandos y moverse lateralmente en la red. |

---

## 🛠️ ¿Cómo funciona el ataque? (paso a paso real)

| Fase             | Acción                                                                                                          |
|------------------|-----------------------------------------------------------------------------------------------------------------|
| **Reconocimiento**| El atacante valida credenciales y busca shares administrativos accesibles (C$, ADMIN$, IPC$).                  |
| **Acceso**       | Conecta a \\host\IPC$ y accede a la canalización svcctl.                                                        |
| **Ejecución**    | Crea un servicio remoto (temporal o persistente) que ejecuta el comando/malware deseado en la máquina objetivo. |
| **Movimiento**   | Repite la operación en otras máquinas usando credenciales robadas o delegación de privilegios.                   |
| **Limpieza**     | Borra el servicio creado para intentar borrar huellas.                                                          |

---

## 💻 Ejemplo ofensivo (comandos reales)

```bash
# Enumerar shares y permisos con nxc
nxc smb 192.168.1.10 -u usuario -p 'contraseña' 

# Ejecución remota usando svcctl
nxc smb 192.168.1.10 -u usuario -p 'contraseña' -x 'whoami'

# Movimiento lateral con CrackMapExec
crackmapexec smb 192.168.1.10 -u usuario -p 'contraseña' -x 'net user'

# Ejecución remota con Impacket/psexec
psexec.py dominio/usuario:'contraseña'@192.168.1.10
```

---

## 📊 Detección en Splunk

| Evento clave | Descripción                                                                                                   |
|--------------|--------------------------------------------------------------------------------------------------------------|
| **4776**     | Autenticación NTLM solicitada por el atacante.                                                               |
| **4624**     | Inicio de sesión exitoso (tipo 3/red) con las credenciales usadas.                                           |
| **5140**     | Acceso a recursos compartidos administrativos (C$, ADMIN$, IPC$).                                            |
| **5145**     | Acceso a objetos críticos: canalización svcctl, especialmente con WriteData o Execute.                       |
| **4672/4674**| Privilegios especiales asignados o uso de privilegios elevados (si la cuenta es admin).                      |
| **7045**     | Creación de servicios remotos (persistencia/ejecución remota).                                               |
| **4634**     | Cierre de sesión.                                                                                            |

### Query Splunk esencial

```splunk
index=dc_logs (EventCode=5140 OR EventCode=5145)
| search (Share_Name="*IPC$" OR Share_Name="*C$" OR Share_Name="*ADMIN$" OR Relative_Target_Name="svcctl")
| search Accesses="*WriteData*" OR Accesses="*Execute*"
| stats count by _time, Account_Name, Source_Address, ComputerName, Relative_Target_Name, Accesses
```

### Query para correlacionar secuencias sospechosas

```splunk
index=dc_logs (EventCode=4776 OR EventCode=4624 OR EventCode=5140 OR EventCode=5145)
| stats list(EventCode) as Secuencia, min(_time) as Primer_Evento, max(_time) as Ultimo_Evento by Account_Name, Source_Address, ComputerName
| search Secuencia="*5140*" Secuencia="*5145*"
| table Primer_Evento, Ultimo_Evento, Account_Name, Source_Address, ComputerName, Secuencia
```

---

## 🦾 Hardening y mitigación

| Medida                                  | Descripción                                                                                      |
|------------------------------------------|-------------------------------------------------------------------------------------------------|
| **Restringe acceso a svcctl**            | Solo los administradores reales y sistemas de gestión deben poder acceder a IPC$ y svcctl.       |
| **Honeytokens de servicio**              | Crea servicios trampa (falsos) y alerta si se accede a ellos.                                   |
| **Deshabilita shares administrativos**   | Si no son necesarios, desactiva IPC$, ADMIN$, C$ en sistemas de usuario.                        |
| **Segmentación de red**                  | Los usuarios normales jamás deberían poder conectar a IPC$ de otros equipos.                     |
| **Auditoría avanzada**                   | Activa auditoría solo en los eventos y objetos críticos, evita el ruido, máxima visibilidad.     |
| **SMBv1 deshabilitado y SMB signing**    | Elimina SMBv1 y exige signing para evitar ataques relay y legacy.                                |
| **Permisos de delegación revisados**     | Revisa los permisos delegados en el Service Control Manager y reduce el exceso de privilegios.   |
| **Alertas automáticas por Write/Execute**| Automatiza alertas por accesos WriteData o Execute en svcctl fuera de lo habitual.               |

---

## 🚨 Respuesta ante incidentes

1. **Aísla la IP de origen** si detectas WriteData/Execute en svcctl o shares críticos.
2. **Revoca y revisa la cuenta implicada** en el acceso sospechoso.
3. **Busca eventos 7045 (creación de servicios)** y procesos hijos de services.exe tras el acceso.
4. **Investiga movimiento lateral** correlacionando eventos en otras máquinas.
5. **Refuerza auditoría temporalmente** en los sistemas afectados y busca persistencia.

---

## 💡 Soluciones innovadoras

- **Honeytokens dinámicos:** Cambia el nombre/ruta de servicios trampa periódicamente para detectar atacantes.
- **Rate limiting SMB:** Limita la frecuencia de accesos a IPC$ y svcctl desde IPs no administrativas.
- **Auditoría basada en contexto:** Alerta solo si Write/Execute ocurre fuera de horario o por cuentas no habituales.
- **Responde de forma automatizada:** Scripts que bloquean cuentas/IP tras 3+ WriteData/Execute en objetos críticos.

---

## ⚡ CVEs y técnicas MITRE relevantes

- **T1021.002 (SMB/Windows Admin Shares):** Movimiento lateral y ejecución remota
- **CVE-2017-0144 (EternalBlue), CVE-2020-0796 (SMBGhost):** Explotación de SMB
- **PrintNightmare (CVE-2021-34527):** Ejecución remota a través de servicios

---

## 📚 Referencias

- [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec)
- [nxc - SMB offensive tool](https://github.com/OfensiveSecurity/nxc)
- [Impacket](https://github.com/fortra/impacket)
- [Hardening Svcctl - Microsoft Docs](https://learn.microsoft.com/es-es/windows/security/threat-protection/windows-authentication/service-control-manager-hardening)
