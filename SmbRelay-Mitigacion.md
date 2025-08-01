# 🛡️ Checklist Hiper Experto: Protección Total contra SMB Relay, LDAP Relay, HTTP Relay y Variaciones Legacy

Red Team | Purple Team | Threat Hunter | Blue Team | Threat Intelligence

---

## 1️⃣ Checklist de Hardening y Protección

### 🔒 **Protocolos y Configuraciones Legacy**

- [ ] **Deshabilitar SMBv1** en todos los endpoints y servidores.
    - *Afecta:* Relay SMB, ransomware, exploits tipo EternalBlue.
    - *Acción:*  
      ```powershell
      Set-SmbServerConfiguration -EnableSMB1Protocol $false
      ```
    - *Hipótesis si no es posible:*  
      - **Segmentar y aislar** los sistemas que requieran SMBv1 en VLANs separadas y sin conectividad directa con activos críticos o DCs.
      - **Limitar el acceso** solo a los sistemas estrictamente necesarios mediante ACLs en firewalls internos.
      - **Monitorear exhaustivamente** el tráfico SMBv1 y establecer alertas ante cualquier actividad inesperada.

- [ ] **Forzar SMB Signing (firma obligatoria)** en todos los servidores y clientes.
    - *Afecta:* Previene SMB relay tradicional.
    - *Acción:*  
      ```powershell
      Set-SmbServerConfiguration -RequireSecuritySignature $true
      Set-SmbClientConfiguration -RequireSecuritySignature $true
      ```
    - *Hipótesis si no es posible:*  
      - **Aplicar SMB signing solo en sistemas críticos** y limitar acceso SMB desde/entre dispositivos legacy.
      - **Segmentación estricta** de redes legacy.
      - **Alertar** sobre cualquier conexión SMB sin signing.

- [ ] **Deshabilitar NTLMv1 y LM Hashes** (solo permitir NTLMv2).
    - *Afecta:* Ataques de relay, crackeo de hashes, autenticación débil.
    - *Acción para NTLMv1:*  
      ```powershell
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5
      ```
    - *Acción para LM Hashes:*  
      ```powershell
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1
      ```
    - *GPO para ambos:*  
      - **LAN Manager authentication level** → "Send NTLMv2 response only. Refuse LM & NTLM".
      - **No almacenar valor LM hash en el próximo cambio de contraseña** → "Habilitado".
    - *Hipótesis si no es posible:*  
      - **Limitar acceso** de las cuentas que requieran NTLMv1/LM solo a los sistemas necesarios y minimizar privilegios.
      - **Monitorizar activamente** autenticaciones LM/NTLMv1 y bloquear cuentas ante uso indebido o fuera de horario.
      - **Forzar cambios de contraseña** periódicos en cuentas legacy y revisar su uso.

- [ ] **Auditar y restringir NTLM en el dominio** (NTLM auditing y restricciones de uso).
    - *Afecta:* Relay a cualquier protocolo NTLM, movimiento lateral.
    - *Acción:* Política GPO “Network Security: Restrict NTLM: Audit Incoming NTLM Traffic”
    - *Hipótesis si no es posible:*  
      - **Aplicar restricciones NTLM solo en DCs, servidores de ficheros y sistemas críticos**.
      - **Bloquear NTLM entre segmentos** mediante reglas de firewall.
      - **Alertar y revisar** cada uso de NTLM fuera de lo esperado.

- [ ] **Forzar LDAP Signing y Channel Binding** en DCs y sistemas críticos.
    - *Afecta:* LDAP relay, abuso de RBCD, LAPS/gMSA, Shadow Credentials.
    - *Acción:*  
      - GPO: “Domain controller: LDAP server signing requirements” → "Require signing".
      - Habilitar Channel Binding Tokens (CBT) en LDAP.
    - *Hipótesis si no es posible:*  
      - **Permitir signing solo en controladores de dominio y servicios críticos**.
      - **Limitar conexiones LDAP sin signing** solo a direcciones IP permitidas.
      - **Monitorear y alertar** sobre cualquier uso de LDAP sin signing.

- [ ] **Forzar HTTP Signing / Extended Protection for Authentication (EPA/Channel Binding) en servicios web internos**
    - *Afecta:* HTTP relay, relay a OWA, EWS, IIS, Exchange, SharePoint, etc.
    - *Acción:*  
      - Habilitar "Extended Protection for Authentication" en IIS, Exchange, SharePoint y cualquier servicio web Windows integrado.
      - Configura NTLM/Negotiate con Channel Binding Tokens (CBT) y Service Principal Names (SPN) correctamente.
      - Documentación: [Microsoft EPA Hardening](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/extended-protection-for-authentication)
    - *Hipótesis si no es posible:*  
      - **Limitar acceso HTTP/NTLM solo a redes de confianza** mediante firewalls y reverse proxies.
      - **Auditar y alertar** sobre autenticaciones NTLM en servicios web.
      - **Aplicar hardening alternativo** (MFA, controles de sesión, acceso restringido).

- [ ] **Eliminar sistemas legacy** (XP, 2003, 2008, 7, appliances sin soporte).
    - *Afecta:* Superficie de ataque legacy, relay y exploits conocidos.
    - *Hipótesis si no es posible:*  
      - **Segmenta y aísla** estos sistemas en VLANs separadas.
      - **Limita acceso** a un número mínimo de administradores y usuarios.
      - **Implementa EDR, monitorizacion y alertas reforzadas**.

- [ ] **Segmentar y aislar dispositivos legacy irremplazables** (impresoras, NAS, appliances).
    - *Afecta:* Minimiza el riesgo lateral y acceso directo de relay.
    - *Acción/Hipótesis:*  
      - **Permitir solo puertos/protocolos necesarios**.
      - **Aplicar firewalls internos y listas de control de acceso**.
      - **Deshabilitar acceso directo a internet y a DCs**.

- [ ] **Actualizar y endurecer políticas de contraseñas** (no passwords legacy, rotación, longitud, complejidad).

---

## 2️⃣ Checklist de Hunting & Detección

### 🔎 **Detección de Relay y Uso de Legacy**

- [ ] **Detectar uso de SMBv1, NTLMv1 y LM Hashes**
    - *PowerShell:*  
      ```powershell
      Get-SmbServerConfiguration | Select EnableSMB1Protocol
      Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel"
      Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash"
      ```
    - *SIEM Query:*  
      ```kql
      SecurityEvent
      | where EventID == 4624
      | where AuthenticationPackageName == "NTLM"
      | where LmPackageName != "-"
      ```
- [ ] **Alertar sobre autenticaciones NTLM y Kerberos anómalas**  
    - *Cuentas máquina realizando S4U2Self/S4U2Proxy (eventos 4769, 4768)*
    - *Cuentas no estándar solicitando tickets para usuarios privilegiados*
- [ ] **Monitorizar cambios en atributos críticos de AD**
    - *msDS-AllowedToActOnBehalfOfOtherIdentity (evento 5136)*
    - *msDS-KeyCredentialLink*
    - *Solicitudes y emisión de certificados ADCS*
- [ ] **Detectar conexiones SMB/LDAP/HTTP internas desde hosts inesperados**
    - *Pivoting, proxy SOCKS, movimientos laterales*
- [ ] **Auditar logs DNS para registros sospechosos añadidos**
    - *--add-dns-record en ntlmrelayx abuse*
- [ ] **Monitorizar acceso a LAPS/gMSA y shares antiguos**
    - *Uso anómalo de cuentas admin locales o de servicio*
- [ ] **Detectar y alertar sobre intentos de relay HTTP**  
    - *Logs de IIS/Exchange/SharePoint con errores de autenticación o EPA, correlación de origen/destino*
    - *Logs con “NTLM” en servicios web internos y errores 401/403 repetidos*
- [ ] **Alertar sobre tráfico NTLM a DCs y autenticaciones NTLM remotas**

---

## 3️⃣ Variaciones de Relay a cubrir y protección específica

| Vector         | Protección crítica                        | Hunting/detección clave                  |
|----------------|------------------------------------------|------------------------------------------|
| **SMB Relay**  | SMB signing, desactivar SMBv1            | Detección de SMBv1/NTLMv1/LM, eventos 4624  |
| **LDAP Relay** | LDAP signing, channel binding             | Eventos 5136 (atributos), logs LDAP      |
| **HTTP Relay** | EPA (Extended Protection), HTTP Channel Binding | Logs IIS/EWS, anomalías NTLM en web      |
| **RBCD/S4U**   | Monitorear cambios delegación/RBCD        | Eventos 5136, 4769, 4768, hunting S4U    |
| **ShadowCreds**| Monitor msDS-KeyCredentialLink            | Cambios de atributo, PKINIT anómalo      |
| **ADCS**       | Hardening plantillas, limitar enrollment  | Solicitudes/anomalías en certificados    |
| **DNS abuse**  | Monitorear cambios DNS                    | Logs DNS server, registros maliciosos    |
| **SOCKS/pivot**| Segmentar/apagar legacy, EDR/IDS internos | Tráfico inusual, correlación autenticaciones |

---

## 4️⃣ Recomendaciones Finales de Threat Intelligence

- **Evalúa y prioriza el hardening de legacy y autenticación web: los adversarios buscarán siempre el eslabón más débil.**
- **Si no puedes aplicar el hardening ideal, prioriza segmentación, monitorizacion, restricciones de acceso y visibilidad.**
- **Automatiza escaneos de legacy y relay con herramientas open source y comerciales.**
- **Implementa dashboards de visibilidad y alertas específicas en el SIEM.**
- **Educa a IT y SecOps sobre el riesgo real de mantener activos legacy y configuraciones inseguras, incluyendo servicios web internos vulnerables a HTTP relay.**

---

