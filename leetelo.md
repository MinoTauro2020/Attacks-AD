# 🛑 Leetelo en Active Directory

---

## 📝 ¿Qué es Leetelo?

| Concepto      | Descripción                                                                                                   |
|---------------|--------------------------------------------------------------------------------------------------------------|
| **Definición**| Técnica de nomenclatura y ofuscación que utiliza caracteres alfanuméricos y símbolos para evadir detección y análisis automatizado en entornos de Active Directory. |
| **Requisito** | Conocimientos básicos de Active Directory, scripting y técnicas de evasión.                                 |

---

## 🛠️ ¿Cómo funciona la técnica?

| Fase               | Acción                                                                                         |
|--------------------|------------------------------------------------------------------------------------------------|
| **Preparación**    | El atacante identifica nombres de objetos, archivos o comandos que serán ofuscados.          |
| **Transformación** | Aplica sustituciones de caracteres (a→@, e→3, i→1, o→0, s→5, t→7) para crear variantes.      |
| **Implementación** | Utiliza los nombres ofuscados en scripts, archivos o comandos para evadir filtros básicos.   |
| **Ejecución**      | Ejecuta las acciones manteniendo funcionalidad pero reduciendo detectabilidad automática.     |

---

## 💻 Ejemplo práctico

```bash
# Comando normal que podría ser detectado
net user administrator NewPassword123!

# Versión con leetelo para evasión básica
n37 u53r 4dm1n157r470r N3wP455w0rd123!
```

```powershell
# Script PowerShell normal
Get-ADUser -Filter * -Properties *

# Versión con ofuscación leetelo
G37-4DU53r -F1l73r * -Pr0p3r713s *
```

---

## 🔍 Detección

| Método               | Descripción                                                                      |
|---------------------|----------------------------------------------------------------------------------|
| **Análisis Heurístico** | Detectar patrones de sustitución comunes en logs y comandos ejecutados.         |
| **Normalización**    | Implementar rutinas que conviertan caracteres leetspeak a su forma original.    |
| **Monitoreo Behavioral** | Alertar sobre comandos con alta densidad de números y símbolos inusuales.     |

---

## 🛡️ Mitigación

| Técnica                    | Descripción                                                                    |
|----------------------------|--------------------------------------------------------------------------------|
| **Filtrado Avanzado**      | Configurar reglas que detecten variaciones leetspeak de comandos conocidos.   |
| **Normalización de Logs**  | Procesar logs aplicando transformaciones inversas antes del análisis.         |
| **EDR/XDR Configurado**    | Utilizar soluciones que analicen comportamiento más que sintaxis literal.     |
| **Entrenamiento**          | Capacitar al equipo sobre técnicas de ofuscación y evasión comunes.           |

---

## ⚠️ Limitaciones

- La efectividad es limitada contra sistemas de detección modernos
- Puede generar falsos positivos si se usa en nombres legítimos
- No evade análisis de comportamiento profundo
- Requiere conocimiento específico de los sistemas de detección objetivo

---

*Actualizado: Julio 2025*