# Responder vs ntlmrelayx: Funcionamiento y peligro real del relay NTLM

---

## 1. ¿Qué hace Responder?

- **Responder** es una herramienta que simula varios servicios en la red (SMB, HTTP, FTP, LDAP, etc.).
- Su objetivo principal es **capturar hashes NTLM** de usuarios o equipos que, por error o manipulación, intentan resolver nombres en la red (usando LLMNR, NBT-NS, WPAD).
- Responder **escucha y responde** a peticiones de resolución de nombres, haciendo que la víctima le envíe sus credenciales NTLM pensando que es un servidor legítimo.

---

## 2. ¿Qué hace ntlmrelayx?

- **ntlmrelayx.py** (Impacket) es una herramienta que **recibe una autenticación NTLM** (normalmente capturada por Responder u otra técnica) y **la reenvía (relay) en tiempo real** a otro servicio interno vulnerable (SMB, LDAP, HTTP, etc.).
- **No crea un servicio ficticio** en el sentido tradicional:
    - ntlmrelayx **escucha y acepta autenticaciones entrantes** (puede simular un share SMB), pero su objetivo principal es reutilizar la autenticación instantáneamente para autenticarse en otro servidor de la red.
- **El atacante NO necesita crackear el hash**:
    - Simplemente lo usa para abrir una sesión autenticada en el destino, suplantando a la víctima.

---

## 3. Flujo típico de ataque con Responder y ntlmrelayx

```
Usuario víctima           Atacante (Responder/ntlmrelayx)         Servicio víctima (SMB/LDAP/etc)
      |-----------------------|----------------------|----------------------|
      |--- Petición SMB ----->|                      |                      |
      |                      |<--- Responder ------- |                      |
      |--- Autenticación NTLM/Hash ---->             |                      |
      |                      |----> ntlmrelayx ------|--- Autenticación --->|
      |                      |                      |                      |
      |                      |<--- Sesión abierta ---|                      |
```

- **Responder** engaña a la víctima y capta la autenticación NTLM.
- **ntlmrelayx** toma esa autenticación y la "relaya" (reenvía) a un servicio real interno (ej: SMB de un servidor), **logrando acceso con los privilegios de la víctima**.
- **No hay servicio ficticio en el destino**:
    - El destino es real, el atacante solo “presenta” la autenticación de la víctima.

---

## 4. Puntos clave de experto

- **Responder** = Captura hashes (y puede también relayar, pero de forma limitada).
- **ntlmrelayx** = Relay en tiempo real, permite acceso real usando el hash capturado.
- **El relay es peligroso** porque permite acceso inmediato con privilegios de la víctima, sin necesidad de crackear el hash.
- **El “servicio ficticio” es solo el punto de escucha; el acceso se da en servicios reales internos**.

---

## 5. Resumen ejecutivo

- **Responder** intercepta y engaña para capturar hashes NTLM.
- **ntlmrelayx** toma ese hash/autenticación y lo usa al instante para acceder a servicios internos, suplantando a la víctima.
- **No es necesario crackear el hash**; el atacante obtiene acceso directo.
- El peligro es máximo si la víctima tiene privilegios elevados (ej: admin local o Domain Admin).

---
