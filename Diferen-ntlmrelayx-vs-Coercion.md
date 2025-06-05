# Diferencias entre ataques de Relay NTLM (ntlmrelayx SMB/LDAP/HTTP) y ataques de Coerción (Coerce, PetitPotam, PrinterBug)

---

## 1. Resumen ejecutivo

- **Ataques de Relay NTLM**: El atacante intercepta y reenvía (relay) la autenticación NTLM de una víctima a un servicio interno para autenticarse como esa víctima.
- **Ataques de Coerción**: El atacante fuerza activamente a una máquina víctima a autenticarse en un recurso controlado por el atacante, capturando así el hash NTLM (sin MiTM).

---

## 2. Descripción técnica

### Ataques de Relay NTLM (ntlmrelayx, SMB/LDAP/HTTP)

| Característica            | Detalle                                                                                      |
|---------------------------|---------------------------------------------------------------------------------------------|
| ¿Quién inicia?            | La víctima (normalmente inducida mediante LLMNR/NBT-NS/WPAD o MiTM)                         |
| Vector clásico            | SMB, LDAP, HTTP                                                                             |
| ¿Qué explota?             | Falta de signing, autenticación débil, protocolos legacy                                    |
| Necesita MiTM             | Sí (o envenenamiento de nombre)                                                             |
| Hashes comprometidos      | Los de la víctima que inicia la conexión                                                    |
| Herramientas típicas      | ntlmrelayx.py, Responder, mitm6                                                             |
| Impacto                   | Acceso/ejecución como la víctima en servicios internos                                      |
| Defensa clave             | SMB/LDAP Signing, desactivar LLMNR/NBT-NS, segmentar red, canal seguro, parcheo             |

---

### Ataques de Coerción (Coercer, PetitPotam, PrinterBug, etc.)

| Característica            | Detalle                                                                                      |
|---------------------------|---------------------------------------------------------------------------------------------|
| ¿Quién inicia?            | El atacante                                                                                 |
| Vector clásico            | EFSRPC (PetitPotam), Print Spooler (PrinterBug), DFS, FSRVP, EventLog, etc.                |
| ¿Qué explota?             | Funciones RPC remotas mal diseñadas, falta de controles de acceso                           |
| Necesita MiTM             | No                                                                                          |
| Hashes comprometidos      | Los de la máquina víctima (ejemplo: DC, File Server) o cuentas privilegiadas                |
| Herramientas típicas      | Coercer, PetitPotam, DFSCoerce, ShadowCoerce                                               |
| Impacto                   | Exposición de hashes privilegiados, movimiento lateral, escalada de privilegios             |
| Defensa clave             | Parcheo, deshabilitar servicios vulnerables, claves de registro, SMB/LDAP signing, segmentar|

---

## 3. Tabla comparativa

| Característica         | Relay NTLM (ntlmrelayx, SMB/LDAP/HTTP) | Coerción (Coercer, PetitPotam, etc.)      |
|-----------------------|-----------------------------------------|-------------------------------------------|
| ¿Quién inicia?        | Víctima (inducida/MiTM)                 | Atacante                                  |
| Vector                | SMB, LDAP, HTTP                         | RPC: EFSRPC, Print Spooler, DFS, etc.     |
| Necesita MiTM         | Sí                                      | No                                        |
| Hashes comprometidos  | De usuarios                             | De equipos/cuentas privilegiadas          |
| Ejemplo de impacto    | Toma de control de recursos internos    | Movimiento lateral, control de DC         |
| Defensa               | Signing, segmentación, hardening        | Parcheo, registro, desactivar servicios   |

---

## 4. Detalle para cada equipo

### Red Team
- **Relay**: Útil cuando puedes MiTM o inducir autenticaciones (phishing, LLMNR, WPAD).
- **Coerción**: Permite extraer hashes de DCs/servidores privilegiados, incluso si ningún usuario comete errores.

### Blue Team
- **Relay**: Monitoriza tráfico LLMNR/NBT-NS, busca autenticaciones NTLM inesperadas.
- **Coerción**: Aplica parches, deshabilita servicios vulnerables, usa claves de registro y SMB/LDAP signing.

### Threat Hunter
- **Relay**: Busca actividad Responder/ntlmrelayx, conexiones a recursos no existentes, logs NTLM fallidos.
- **Coerción**: Busca llamadas RPC anómalas, binds a pipes como `\PIPE\efsrpc`, intentos de autenticación NTLM entre servidores.

### Purple Team
- Simula ambos vectores. Valida que mitigaciones (signing, parches, hardening) bloqueen efectivamente ambos caminos.

### Threat Intelligence
- **Relay**: Común en ataques oportunistas, ransomware de propagación rápida.
- **Coerción**: Preferido por APTs y operadores avanzados para movimiento lateral y persistencia, difícil de detectar si no se monitorea.

---

## 5. Resumen gráfico

```
Relay NTLM
Víctima → (autenticación NTLM) → Atacante (relay) → Servicio interno (SMB/LDAP/HTTP)

Coerción
Atacante → (función RPC vulnerable) → Víctima → (autenticación NTLM forzada) → Atacante
```
# ¿Por qué el relay NTLM permite escalar privilegios?

---

## 1. ¿Qué es la escalada de privilegios vía relay NTLM?

El **relay NTLM** permite a un atacante tomar la autenticación legítima de un usuario (o equipo) y reutilizarla en tiempo real contra un servicio interno, **usurpando su identidad**.  
Si la víctima tiene privilegios elevados (ej: es administrador local, Domain Admin, SYSTEM, o un servicio crítico), el atacante **obtiene esos mismos privilegios** en el recurso de destino, aunque él mismo tenga credenciales bajas o ninguna.

---

## 2. ¿Cómo ocurre la escalada de privilegios?

### Escenario típico:
1. **El atacante intercepta o fuerza una autenticación NTLM** de una cuenta privilegiada (ejemplo: un Domain Admin o un servidor crítico).
2. **Reenvía (relay) ese token de autenticación** a un servicio vulnerable (SMB, LDAP, HTTP, etc.) sin SMB/LDAP signing ni mitigaciones.
3. **El servicio de destino** acepta la autenticación NTLM **y otorga acceso como si el atacante fuera la víctima**.

### Ejemplo:
- Si el atacante relaye el hash NTLM de un Domain Admin a un controlador de dominio vía LDAP:
  - Puede modificar usuarios, delegaciones, políticas, agregar nuevos administradores, etc.
- Si relaye el hash de un administrador local a un servidor vía SMB:
  - Puede ejecutar comandos, cargar malware, crear usuarios, extraer secretos, etc.

---

## 3. ¿Por qué es tan crítico?

- **No requiere conocer la contraseña**: El atacante no necesita crackear el hash, solo reusarlo en tiempo real.
- **Privilegios heredados**: Gana exactamente los mismos privilegios que la víctima en el servicio de destino.
- **Escalada vertical y lateral**:  
  - **Vertical**: De usuario estándar a administrador, si la víctima es admin.
  - **Lateral**: De un host a otro, comprometiendo toda la red si la víctima es privilegiada en muchos sistemas.
- **Impacto inmediato**: Acceso, persistencia, movimiento lateral y dominio completo.

---

## 4. ¿Por qué no ocurre esto con todos los ataques?

- La **escalada depende de los privilegios de la víctima**. Si la víctima es una cuenta de bajo privilegio, el acceso que obtiene el atacante será limitado.
- Si el atacante logra relayar a servicios críticos **sin SMB/LDAP signing**, puede escalar de un foothold inicial a todo el dominio.

---

## 5. Defensa hiper-experta

- **Obligar SMB/LDAP signing**: Impide el relay, aunque el atacante intercepte autenticaciones.
- **Segmentar red y restringir privilegios**: Minimiza el movimiento lateral y el impacto de un posible relay.
- **Desactivar NTLM en lo posible**: Migrar a Kerberos y protocolos modernos.
- **Monitorizar autenticaciones NTLM entre hosts críticos**: IOC clave para detección temprana.

---

## 6. Resumen ejecutivo

- **El relay NTLM permite escalar privilegios** porque traslada la autenticación de una cuenta privilegiada a cualquier servicio interno vulnerable, sin requerir la contraseña ni interacción adicional.
- **Mitigar el relay** es crítico para evitar que un compromiso puntual se convierta en un dominio total.

---
# ¿Por qué la coerción NTLM (Coerce, PetitPotam, etc.) es peligrosa en entornos Windows?

---

## 1. ¿Qué es la coerción NTLM?

La **coerción NTLM** (Coerce, PetitPotam, PrinterBug, DFSCoerce, etc.) es una técnica donde el atacante **fuerza a un sistema Windows (servidor, DC, equipo privilegiado) a autenticarse contra un recurso controlado por el atacante**. Esto se logra explotando funciones legítimas de Windows expuestas por RPC/DCE-RPC que aceptan rutas UNC arbitrarias o llamadas remotas.

---

## 2. ¿Cómo funciona la coerción?

1. El atacante identifica un servicio o función vulnerable (por ejemplo, EFSRPC, Print Spooler, DFS, EventLog, FSRVP, etc.) expuesto por la víctima.
2. Invoca esa función de forma remota y **le indica como destino una ruta UNC bajo su control** (ej: \\attacker_server\share).
3. **La víctima inicia una autenticación NTLM** hacia el recurso del atacante, exponiendo su hash NTLM (usualmente de máquina o cuenta privilegiada).
4. El atacante **captura el hash NTLM** y puede:
    - Intentar crackearlo (fuerza bruta/offline).
    - Usarlo en un ataque de relay NTLM para autenticarse en otros servicios internos.

---

## 3. ¿Por qué es tan peligrosa la coerción?

### A. Exposición de hashes privilegiados
- Permite capturar **hashes de cuentas privilegiadas** (ejemplo: equipos, Domain Admins, servicios críticos) que normalmente **nunca deberían salir del host**.
- Hashes de equipos como DCs pueden distribuirse rápidamente para tomar control total del dominio.

### B. No requiere MiTM ni interacción de usuario
- A diferencia del relay clásico, **no depende de estar en posición de MiTM ni de engañar a usuarios**.
- Solo requiere que la víctima tenga servicios RPC vulnerables expuestos y accesibles en red.

### C. “Enabler” de ataques de relay y movimiento lateral
- Sola, la coerción solo expone hashes.
- **Combinada con relay**, permite comprometer hosts críticos y escalar privilegios en toda la red.
- Es el paso inicial para ataques devastadores tipo ransomware, APT, dominio total.

### D. Difícil de detectar si no se monitorean logs y pipes RPC
- Los logs nativos de Windows rara vez alertan sobre coerción si no hay reglas de hunting avanzadas.
- El atacante puede probar múltiples funciones/coerción sin ser detectado en entornos poco maduros.

---

## 4. Ejemplo de ataque encadenado

1. **Coerción**: Atacante fuerza a DC1 a autenticarse en \\attacker\share usando EFSRPC.
2. **Captura de hash**: Atacante obtiene el hash de DC1.
3. **Relay**: Atacante usa el hash para autenticarse en DC2 vía LDAP/SMB.
4. **Dominio completo**: Atacante compromete el dominio o despliega ransomware.

---

## 5. Defensa hiper-experta

- **Parcheo constante**: Aplicar actualizaciones críticas de Windows que cierran vectores de coerción.
- **Restricción de servicios RPC**: Deshabilitar servicios vulnerables, aplicar claves de registro defensivas (ej: EfsDisabled=1, Print Spooler solo local).
- **Segmentación y hardening**: Limitar acceso a puertos RPC/SMB desde redes no confiables.
- **SMB/LDAP signing obligatorio**: Rompe la cadena de relay incluso si hay coerción.
- **Monitoreo avanzado**: Buscar actividad anómala en pipes como \PIPE\efsrpc, \PIPE\spoolss, logs de autenticación NTLM entre hosts críticos.

---







