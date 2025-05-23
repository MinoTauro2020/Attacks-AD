# Funcionamiento de ataques LLMNR/NBT-NS/WPAD/Responder y Mitigaciones

---

## Índice

1. [¿Qué son LLMNR, NBT-NS y WPAD?](#1-qué-son-llmnr-nbt-ns-y-wpad)
2. [¿Por qué existen y para qué se usan?](#2-por-qué-existen-y-para-qué-se-usan)
3. [¿Por qué son vulnerables?](#3-por-qué-son-vulnerables)
4. [¿Qué obtiene el atacante?](#4-qué-obtiene-el-atacante)
5. [¿Por qué sigue funcionando?](#5-por-qué-sigue-funcionando)
6. [Condiciones para ser vulnerable](#6-condiciones-para-ser-vulnerable)
7. [Por qué NTLMv1 es especialmente peligroso](#7-por-qué-ntlmv1-es-especialmente-peligroso)
8. [¿Y si la máquina solo usa NTLMv2?](#8-y-si-la-máquina-solo-usa-ntlmv2)
9. [Funcionamiento del ataque paso a paso](#9-funcionamiento-del-ataque-paso-a-paso)
10. [Mitigaciones recomendadas](#10-mitigaciones-recomendadas)
11. [Resumen visual del ataque](#11-resumen-visual-del-ataque)
12. [Resumen de mitigaciones](#12-resumen-de-mitigaciones)

---

## 1. ¿Qué son LLMNR, NBT-NS y WPAD?

| Protocolo | Descripción                                                                                  |
|-----------|---------------------------------------------------------------------------------------------|
| LLMNR     | (Link-Local Multicast Name Resolution) Permite a equipos Windows resolver nombres en red local si el DNS falla. |
| NBT-NS    | (NetBIOS Name Service) Protocolo antiguo para resolución de nombres NetBIOS.                 |
| WPAD      | (Web Proxy Auto-Discovery Protocol) Descubre automáticamente servidores proxy en la red.      |

---

## 2. ¿Por qué existen y para qué se usan?

| Motivo             | Explicación                                                                                         |
|--------------------|----------------------------------------------------------------------------------------------------|
| Resolución alterna | Cuando DNS no resuelve, Windows recurre a LLMNR/NBT-NS para preguntar a la red por un nombre.      |
| Descubrimiento     | WPAD permite a los equipos encontrar de forma automática un proxy configurado en la red interna.    |

---

## 3. ¿Por qué son vulnerables?

| Motivo de vulnerabilidad | Detalle                                                                                  |
|-------------------------|------------------------------------------------------------------------------------------|
| Falta de autenticidad   | Cualquier equipo de la red puede responder a peticiones LLMNR/NBT-NS/WPAD.              |
| Suplantación            | El atacante puede responder y hacerse pasar por el recurso buscado por la víctima.       |
| Autenticación automática| Windows intenta autenticarse automáticamente (NTLM) al recurso falso del atacante.       |

---

## 4. ¿Qué obtiene el atacante?

| Escenario         | Resultado                                                                                           |
|-------------------|----------------------------------------------------------------------------------------------------|
| Captura de hash   | El atacante obtiene el hash NTLM de la víctima.                                                     |
| Relay de hash     | El atacante puede relayar la autenticación a otros servicios (SMB, LDAP, HTTP) con ntlmrelayx.py.  |
| Contraseña débil  | Si el hash es NTLMv1 o la contraseña es débil, puede crackearla y obtenerla en texto claro.        |

---

## 5. ¿Por qué sigue funcionando?

| Motivo                             | Explicación                                                                                      |
|------------------------------------|-------------------------------------------------------------------------------------------------|
| Protocolos activos por defecto     | LLMNR, NBT-NS y WPAD suelen estar habilitados en sistemas Windows modernos.                      |
| NTLM sigue siendo común            | NTLM se usa mucho por compatibilidad, incluso cuando Kerberos está disponible.                   |
| Falta de concienciación            | Muchos usuarios no saben que estos mecanismos están activos o los riesgos que suponen.           |
| Compatibilidad con sistemas antiguos| NTLMv1 sigue habilitado en muchas redes por compatibilidad con dispositivos legacy.              |

---

## 6. Condiciones para ser vulnerable

| Condición                                    | Riesgo que implica                                                                      |
|----------------------------------------------|----------------------------------------------------------------------------------------|
| LLMNR, NBT-NS o WPAD habilitados             | Permiten que un atacante suplante recursos de red y capture autenticaciones.           |
| NTLMv1 habilitado                            | Los hashes capturados se pueden crackear fácilmente.                                   |
| NTLMv2 pero contraseñas débiles              | Hashes difíciles de crackear, pero posible si la contraseña es débil.                  |
| Servicios SMB/LDAP/HTTP sin signing          | Permiten relay de autenticación NTLM (v1 o v2).                                        |
| SMB signing/LDAP signing deshabilitado       | El relay es posible si la firma digital no está activada en estos servicios.           |
| Usuarios accediendo a nombres erróneos       | Más oportunidades para que el ataque funcione.                                         |

---

## 7. Por qué NTLMv1 es especialmente peligroso

| Motivo         | Detalle                                                                                      |
|----------------|---------------------------------------------------------------------------------------------|
| Algoritmo débil| Hashes NTLMv1 son vulnerables a ataques por diccionario y fuerza bruta.                     |
| Crackeo rápido | Herramientas como Hashcat o John pueden crackear NTLMv1 en minutos/hora si la contraseña no es robusta. |
| NTLMv2 es mejor| NTLMv2 utiliza salting y desafíos más robustos, dificultando el crackeo offline.            |

---

## 8. ¿Y si la máquina solo usa NTLMv2?

| Escenario                 | ¿Qué pasa?                                                                                 |
|---------------------------|-------------------------------------------------------------------------------------------|
| Captura de hash NTLMv2    | Se puede capturar con Responder, pero crackearlo es muy difícil si la contraseña es buena.|
| Relay de autenticación    | El relay sigue siendo posible si los servicios no tienen mitigaciones (SMB/LDAP signing). |
| Contraseña fuerte         | Aunque el hash se capture, no podrá crackearse prácticamente nunca.                       |

---

## 9. Funcionamiento del ataque paso a paso

| Paso | Descripción                                                                                           |
|------|------------------------------------------------------------------------------------------------------|
| 1    | Usuario accede a un recurso no existente (por ejemplo, `\\servidor-que-no-existe`).                  |
| 2    | DNS no puede resolver el nombre.                                                                     |
| 3    | Windows envía petición LLMNR/NBT-NS/WPAD a la red preguntando "¿Quién es servidor-que-no-existe?".   |
| 4    | El atacante responde como si fuera el servidor buscado.                                              |
| 5    | Windows intenta autenticarse (NTLM) automáticamente contra el atacante.                              |
| 6    | El atacante captura el hash NTLM o lo relayea a otro servicio.                                       |

---

## 10. Mitigaciones recomendadas

| Mitigación                                      | ¿Qué previene?                                                     |
|-------------------------------------------------|--------------------------------------------------------------------|
| Desactivar LLMNR/NBT-NS/WPAD                    | Evita la suplantación de respuestas en la red.                     |
| Forzar solo NTLMv2                              | Elimina hashes débiles, dificulta el crackeo offline.              |
| Habilitar SMB Signing en servidores y clientes  | Bloquea el relay de autenticación en SMB.                          |
| Habilitar LDAP Signing y Channel Binding        | Bloquea el relay de autenticación en LDAP.                         |
| Usar contraseñas largas y robustas              | Dificulta el crackeo de hashes NTLMv2 capturados.                  |
| Segmentar/red endurecida                        | Limita el alcance del atacante en la red.                          |
| Migrar servicios a Kerberos                     | Elimina por completo el uso de NTLM para autenticación.            |
| Revisar y actualizar dispositivos legacy        | Evitar que requieran NTLMv1 por compatibilidad.                    |

---

## 11. Resumen visual del ataque

```
Usuario pide acceso a \\recurso-inexistente
    ↓
DNS no resuelve el nombre
    ↓
Windows pregunta vía LLMNR/NBT-NS/WPAD
    ↓
El atacante responde "¡Soy yo!"
    ↓
La víctima intenta autenticarse (NTLM)
    ↓
El atacante captura/relaya el hash
```

---

## 12. Resumen de mitigaciones

| Mitigación                                 | Impacto principal                                     |
|--------------------------------------------|-------------------------------------------------------|
| Desactivar LLMNR/NBT-NS/WPAD               | Ataque Responder deja de funcionar.                   |
| Solo NTLMv2 + contraseñas robustas         | Hashes capturados no se pueden crackear.              |
| SMB Signing (habilitado)                   | Relay sobre SMB no es posible.                        |
| LDAP Signing + Channel Binding             | Relay sobre LDAP no es posible.                       |
| Segmentación de red                        | Difícil que el atacante llegue a las víctimas.        |
| Kerberos everywhere                        | NTLM deja de usarse, Responder deja de ser efectivo.  |

---

**Nota:**  
Lo ideal es combinar todas las mitigaciones para una defensa en profundidad. No dependas solo de una.
