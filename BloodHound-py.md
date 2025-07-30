# 🩸 Reconocimiento y mapeo de Active Directory con BloodHound.py

---

## 📝 ¿Qué es BloodHound.py y por qué es tan crítico?

| Concepto      | Descripción                                                                                                 |
|---------------|------------------------------------------------------------------------------------------------------------|
| **Definición**| Ingestor de datos en Python para BloodHound que enumera y mapea Active Directory remotamente sin necesidad de agentes. Identifica rutas de ataque, relaciones de confianza y privilegios elevados. |
| **Uso**       | Herramienta de reconocimiento que recopila información crítica sobre usuarios, grupos, equipos, GPOs y relaciones de confianza para identificar vectores de escalada de privilegios y movimiento lateral. |

---

## 🛠️ ¿Cómo funciona el ataque? (paso a paso real)

| Fase             | Acción                                                                                                          |
|------------------|-----------------------------------------------------------------------------------------------------------------|
| **Autenticación**| El atacante se autentica contra el dominio usando credenciales válidas (usuario/contraseña o hash).            |
| **Enumeración**  | Consulta LDAP/LDAPS para enumerar usuarios, grupos, equipos, GPOs y relaciones organizacionales.              |
| **Mapeo**        | Identifica miembros de grupos privilegiados, delegaciones Kerberos, ACLs y permisos de objetos críticos.      |
| **Análisis**     | Procesa los datos recopilados para identificar rutas de ataque y vectores de escalada de privilegios.          |
| **Explotación**  | Utiliza la información para planificar ataques dirigidos (Kerberoasting, ASREPRoast, delegación, etc.).       |

---

## 💻 Ejemplo ofensivo (comandos reales)

```bash
# Recopilación básica con credenciales
bloodhound-python -d ejemplo.local -u usuario -p 'contraseña' -gc controlador.ejemplo.local -c all

# Usando hash NTLM en lugar de contraseña
bloodhound-python -d ejemplo.local -u usuario --hashes aad3b435b51404eeaad3b435b51404ee:5e8a0123456789abcdef0123456789ab -gc controlador.ejemplo.local -c all

# Enumeración específica (solo usuarios y grupos)
bloodhound-python -d ejemplo.local -u usuario -p 'contraseña' -gc controlador.ejemplo.local -c Users,Groups

# Con autenticación Kerberos (ccache)
export KRB5CCNAME=/tmp/usuario.ccache
bloodhound-python -d ejemplo.local -k -gc controlador.ejemplo.local -c all

# Salida a archivo específico
bloodhound-python -d ejemplo.local -u usuario -p 'contraseña' -gc controlador.ejemplo.local -c all --zip
```

---

## 📊 Detección en Splunk

| Evento clave | Descripción                                                                                                   |
|--------------|--------------------------------------------------------------------------------------------------------------|
| **4776**     | Autenticación NTLM del atacante contra el controlador de dominio.                                           |
| **4624**     | Inicio de sesión exitoso (tipo 3/red) con las credenciales utilizadas.                                      |
| **4768/4769**| Solicitudes de tickets Kerberos TGT/TGS para autenticación.                                                 |
| **5156**     | Conexiones LDAP/LDAPS hacia el controlador de dominio (puerto 389/636).                                     |
| **4662**     | Operaciones de objeto realizadas - acceso a objetos críticos del directorio.                                |
| **4661**     | Manejo de objeto solicitado - acceso a atributos específicos de AD.                                         |

### Query Splunk esencial

```splunk
index=dc_logs (EventCode=4662 OR EventCode=4661)
| search (Object_Type="*user*" OR Object_Type="*group*" OR Object_Type="*computer*" OR Object_Type="*organizationalUnit*")
| search Properties="*member*" OR Properties="*memberOf*" OR Properties="*servicePrincipalName*" OR Properties="*msDS-AllowedToDelegateTo*"
| stats count by _time, Account_Name, Source_Address, Object_Name, Properties
| where count > 50
```

### Query para detectar enumeración masiva

```splunk
index=dc_logs EventCode=4662
| search Object_Type="*user*" OR Object_Type="*group*" OR Object_Type="*computer*"
| stats dc(Object_Name) as objetos_unicos, count by Account_Name, Source_Address, _time
| where objetos_unicos > 100 OR count > 500
| table _time, Account_Name, Source_Address, objetos_unicos, count
```

### Query para correlacionar secuencias sospechosas

```splunk
index=dc_logs (EventCode=4768 OR EventCode=4769 OR EventCode=4662 OR EventCode=5156)
| bin _time span=5m
| stats values(EventCode) as eventos, dc(Object_Name) as objetos by _time, Account_Name, Source_Address
| where objetos > 50
| table _time, Account_Name, Source_Address, eventos, objetos
```

---

## 🦾 Hardening y mitigación

| Medida                                  | Descripción                                                                                      |
|------------------------------------------|-------------------------------------------------------------------------------------------------|
| **Auditoría avanzada de AD**             | Habilita auditoría detallada de acceso a objetos del directorio y operaciones LDAP.            |
| **Restricción de consultas LDAP**        | Limita las consultas LDAP masivas y el acceso a atributos sensibles para usuarios no privilegiados. |
| **Honeytokens en AD**                    | Crea usuarios/grupos señuelo y alerta si son enumerados o accedidos.                           |
| **Segmentación de red**                  | Los usuarios normales no deberían poder conectar directamente a puertos LDAP del DC.           |
| **Limitación de permisos de lectura**    | Restringe permisos de lectura en objetos críticos solo a cuentas que realmente los necesiten.  |
| **Detección de comportamiento anómalo**  | Implementa detección de consultas LDAP masivas y accesos atípicos a objetos del directorio.    |
| **LDAP signing obligatorio**             | Exige firma LDAP para prevenir ataques man-in-the-middle.                                      |
| **Rate limiting LDAP**                   | Implementa límites de velocidad para consultas LDAP por usuario/IP.                            |

---

## 🚨 Respuesta ante incidentes

1. **Aísla la IP de origen** que realiza consultas LDAP masivas o accesos sospechosos.
2. **Investiga la cuenta comprometida** y revisa todos los objetos accedidos durante la enumeración.
3. **Busca actividad posterior** como Kerberoasting, ASREPRoast o intentos de escalada de privilegios.
4. **Revisa logs de autenticación** para identificar el vector de compromiso inicial.
5. **Cambia credenciales** de cuentas potencialmente expuestas y revisa permisos de delegación.
6. **Implementa monitoreo adicional** en cuentas de servicio y grupos privilegiados identificados.

---

## 💡 Soluciones innovadoras

- **Honeytokens dinámicos:** Crea usuarios señuelo con nombres atractivos que cambien periódicamente.
- **Deception en AD:** Implementa objetos falsos con permisos elevados para detectar reconocimiento.
- **ML para detección:** Utiliza machine learning para identificar patrones anómalos de consultas LDAP.
- **Respuesta automatizada:** Scripts que bloquean cuentas tras enumeración masiva de objetos críticos.
- **Ofuscación de información:** Limita la información visible en atributos no esenciales del directorio.

---

## ⚡ CVEs y técnicas MITRE relevantes

- **T1087.002 (Domain Account Discovery):** Enumeración de cuentas de dominio
- **T1482 (Domain Trust Discovery):** Descubrimiento de relaciones de confianza de dominio
- **T1069.002 (Domain Groups Discovery):** Enumeración de grupos de dominio
- **T1018 (Remote System Discovery):** Descubrimiento de sistemas remotos
- **T1083 (File and Directory Discovery):** Descubrimiento de archivos y directorios
- **T1033 (System Owner/User Discovery):** Descubrimiento de propietarios/usuarios del sistema

---

## 📚 Referencias

- [BloodHound.py - GitHub](https://github.com/dirkjanm/BloodHound.py)
- [BloodHound - GitHub](https://github.com/BloodHoundAD/BloodHound)
- [BloodHound Documentation](https://bloodhound.readthedocs.io/)
- [Active Directory Security - Microsoft Docs](https://learn.microsoft.com/es-es/windows-server/identity/ad-ds/plan/security-best-practices/)
- [MITRE ATT&CK - Discovery Techniques](https://attack.mitre.org/tactics/TA0007/)