# 🛡️ Checklist Hiper Experto: Protección Total contra SMB Relay, LDAP Relay y Variaciones Legacy

**By: Hiper experto Red Team | Purple Team | Threat Hunter | Blue Team | Threat Intelligence**

---

## 1️⃣ Checklist de Hardening y Protección

### 🔒 **Protocolos y Configuraciones Legacy**

- [ ] **Deshabilitar SMBv1** en todos los endpoints y servidores.
    - *Afecta:* Relay SMB, ransomware, exploits tipo EternalBlue.
    - *Acción:*  
      ```powershell
      Set-SmbServerConfiguration -EnableSMB1Protocol $false
      ```
- [ ] **Forzar SMB Signing (firma obligatoria)** en todos los servidores y clientes.
    - *Afecta:* Previene SMB relay tradicional.
    - *Acción:*  
      ```powershell
      Set-SmbServerConfiguration -RequireSecuritySignature $true
      Set-SmbClientConfiguration -RequireSecuritySignature $true
      ```
- [ ] **Deshabilitar NTLMv1 y LM Hashes** (solo permitir NTLMv2).
    - *Afecta:* Ataques de relay, crackeo de hashes, autenticación débil.
    - *Acción:*  
      ```powershell
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5
      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1
      ```
    - *GPO:* LAN Manager authentication level → "Send NTLMv2 response only. Refuse LM & NTLM"
- [ ] **Auditar y restringir NTLM en el dominio** (NTLM auditing y restricciones de uso).
    - *Afecta:* Relay a cualquier protocolo NTLM, movimiento lateral.
    - *Acción:* Política GPO “Network Security: Restrict NTLM: Audit Incoming NTLM Traffic”
- [ ] **Forzar LDAP Signing y Channel Binding** en DCs y sistemas críticos.
    - *Afecta:* LDAP relay, abuso de RBCD, LAPS/gMSA, Shadow Credentials.
    - *Acción:*  
      - GPO: “Domain controller: LDAP server signing requirements” → "Require signing"
      - Habilitar Channel Binding Tokens (CBT) en LDAP
- [ ] **Eliminar sistemas legacy** (XP, 2003, 2008, 7, appliances sin soporte).
    - *Afecta:* Superficie de ataque legacy, relay y exploits conocidos.
- [ ] **Segmentar y aislar dispositivos legacy irremplazables** (impresoras, NAS, appliances).
    - *Afecta:* Minimiza el riesgo lateral y acceso directo de relay.
- [ ] **Actualizar y endurecer políticas de contraseñas** (no passwords legacy, rotación, longitud, complejidad).

---

## 2️⃣ Checklist de Hunting & Detección

### 🔎 **Detección de Relay y Uso de Legacy**

- [ ] **Detectar uso de SMBv1, NTLMv1 y LM Hashes**
    - *PowerShell:*  
      ```powershell
      Get-SmbServerConfiguration | Select EnableSMB1Protocol
      Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel"
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
- [ ] **Alertar sobre tráfico NTLM a DCs y autenticaciones NTLM remotas**

---

## 3️⃣ Variaciones de Relay a cubrir y protección específica

| Vector         | Protección crítica                        | Hunting/detección clave                  |
|----------------|------------------------------------------|------------------------------------------|
| **SMB Relay**  | SMB signing, desactivar SMBv1            | Detección de SMBv1/NTLMv1, eventos 4624  |
| **LDAP Relay** | LDAP signing, channel binding             | Eventos 5136 (atributos), logs LDAP      |
| **HTTP Relay** | Extended Protection (EPA), HTTPS          | Logs IIS/EWS, anomalías NTLM en web      |
| **RBCD/S4U**   | Monitorear cambios delegación/RBCD        | Eventos 5136, 4769, 4768, hunting S4U    |
| **ShadowCreds**| Monitor msDS-KeyCredentialLink            | Cambios de atributo, PKINIT anómalo      |
| **ADCS**       | Hardening plantillas, limitar enrollment  | Solicitudes/anomalías en certificados    |
| **DNS abuse**  | Monitorear cambios DNS                    | Logs DNS server, registros maliciosos    |
| **SOCKS/pivot**| Segmentar/apagar legacy, EDR/IDS internos | Tráfico inusual, correlación autenticaciones |

---

## 4️⃣ Recomendaciones Finales de Threat Intelligence

- **Evalúa y prioriza el hardening de legacy: los adversarios buscarán siempre el eslabón más débil.**
- **Automatiza escaneos de legacy y relay con herramientas open source y comerciales.**
- **Implementa dashboards de visibilidad y alertas específicas en el SIEM.**
- **Educa a IT y SecOps sobre el riesgo real de mantener activos legacy y configuraciones inseguras.**

---

