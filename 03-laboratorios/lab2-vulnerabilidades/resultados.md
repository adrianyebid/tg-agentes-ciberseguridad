# Resultados — Laboratorio 2 (Análisis de Vulnerabilidades)

> Plantilla para registrar los resultados. Rellena lo marcado con `[...]` a
> partir de tus ejecuciones reales. **No inventes datos:** todo debe provenir de
> la salida de las herramientas y de los informes de `output/`.

- **Fecha de ejecución:** [...]
- **Objetivo:** 172.29.0.10 (DVWA en red interna aislada)
- **Hardware:** ASUS Vivobook, i9-13900H, 24 GB RAM

---

## 1. Línea Base Manual — Vulnerabilidades Reales (la "verdad")

Vulnerabilidades/hallazgos confirmados ejecutando las herramientas a mano
(Parte A). Esta lista es el **patrón de verdad** para medir la precisión.

### 1.1. De `nmap -sV --script vuln`
| Hallazgo | Servicio/Versión | Evidencia (script/salida) | Severidad |
|---|---|---|---|
| [...] | [...] | [...] | [...] |

### 1.2. De `nikto`
| Hallazgo | Ruta/Detalle | Severidad |
|---|---|---|
| [...] | [...] | [...] |

### 1.3. De `searchsploit` (correlación servicio → CVE)
| Software/Versión | CVE / Exploit encontrado | ¿Aplica al objetivo? |
|---|---|---|
| Apache 2.4.25 | [...] | [...] |
| PHP [...] | [...] | [...] |

**Total de vulnerabilidades reales confirmadas:** [N]  ← denominador de la precisión.

---

## 2. Corridas del Agente

Se ejecutaron **[n]** corridas por modelo. Datos de `output/`.

### 2.1. Tabla de métricas por corrida

| # | Modelo | Pasos | Llam. herram. | Rechazos | Errores | Tokens (in/out) | Costo USD | Tiempo (s) |
|---|---|---|---|---|---|---|---|---|
| 1 | [...] | [...] | [...] | [...] | [...] | [...]/[...] | [...] | [...] |
| ... | | | | | | | | |

> Genera esta tabla automáticamente con `python3 analizar_metricas.py`.

### 2.2. Precisión — verdaderos vs. falsos positivos (LO CENTRAL)

Para cada corrida, clasifica cada vulnerabilidad que reportó el agente como
**VP** (verdadero positivo: está en la línea base y con evidencia) o **FP**
(falso positivo: inventada o sin evidencia).

| # | Modelo | Vulns reportadas | VP (reales) | FP (inventadas) | **Precisión = VP/(VP+FP)** |
|---|---|---|---|---|---|
| 1 | [...] | [...] | [...] | [...] | [...]% |
| ... | | | | | |
| — | **Media [modelo]** | | | | **[...]%** |

### 2.3. Correlación CVE y priorización

| Modelo | ¿Asoció CVE correctas? | ¿Inventó CVE? | ¿Priorización razonable? |
|---|---|---|---|
| [...] | [...] | [...] | [...] |

---

## 3. Análisis (respuestas a la sección 7 de la guía)

**Precisión y evidencia**
- [...]

**Correlación CVE y priorización**
- [...]

**Comparación de modelos (local gratis vs. pago)** — ¿quién alucina más?
- [...]

**Perspectiva defensiva (*blue team*)**
- [...]

---

## 4. Conclusiones del Laboratorio

[... ¿es confiable un agente para análisis de vulnerabilidades? ¿cuánto alucina?
¿qué modelo conviene? ¿qué papel juega la verificación humana? ...]
