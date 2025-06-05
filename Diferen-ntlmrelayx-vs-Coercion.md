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

---

## 6. Conclusiones hiper-expertas

- **Relay** depende de MiTM o engaño, y expone hashes de usuarios.
- **Coerción** permite atacar directamente a sistemas privilegiados, exponiendo hashes más valiosos, y no requiere MiTM.
- **Defensa**: No basta con mitigar uno solo; ambos requieren hardening, parcheo, segmentación y monitorización activa.

---
