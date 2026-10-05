# Resultados — Laboratorio 1 (Reconocimiento)

> Plantilla para registrar los resultados. Rellena las secciones marcadas con
> `[...]` a partir de tus ejecuciones reales. **No inventes datos:** todos los
> valores deben provenir de la salida de las herramientas y de los informes de
> `output/`.

- **Fecha de ejecución:** [...]
- **Objetivo:** 172.28.0.10 (víctima DVWA en red interna aislada)
- **Hardware:** ASUS Vivobook, i9-13900H, 24 GB RAM

---

## 1. Línea Base Manual (nivel A0)

Hallazgos obtenidos ejecutando las herramientas a mano (Parte A de la guía).

### 1.1. Puertos y servicios (`nmap -sV`)

| Puerto | Estado | Servicio | Versión |
|---|---|---|---|
| [...] | [...] | [...] | [...] |

### 1.2. Tecnologías web (`whatweb`)

[... pega aquí lo relevante: servidor, lenguaje, framework/CMS ...]

### 1.3. Rutas web (`gobuster`)

[... lista de rutas encontradas con código de estado ...]

**Total de hallazgos de la línea base:** [N] (se usará como denominador de la
cobertura).

---

## 2. Corridas del Agente

Se ejecutaron **[n]** corridas por modelo. Datos tomados de los informes en
`output/`.

### 2.1. Tabla de métricas por corrida

| # | Modelo | Pasos | Llam. herram. | Rechazos | Errores | Tokens (in/out) | Costo USD | Tiempo (s) | Cobertura* |
|---|---|---|---|---|---|---|---|---|---|
| 1 | claude-haiku-4-5 | [...] | [...] | [...] | [...] | [...]/[...] | [...] | [...] | [...]% |
| 2 | claude-haiku-4-5 | [...] | [...] | [...] | [...] | [...]/[...] | [...] | [...] | [...]% |
| 3 | claude-haiku-4-5 | [...] | [...] | [...] | [...] | [...]/[...] | [...] | [...] | [...]% |
| 4 | claude-haiku-4-5 | [...] | [...] | [...] | [...] | [...]/[...] | [...] | [...] | [...]% |
| 5 | claude-haiku-4-5 | [...] | [...] | [...] | [...] | [...]/[...] | [...] | [...] | [...]% |
| — | **Media Haiku** | [...] | [...] | [...] | [...] | [...] | [...] | [...] | [...]% |
| 6 | claude-sonnet-5 | [...] | [...] | [...] | [...] | [...]/[...] | [...] | [...] | [...]% |
| ... | ... | | | | | | | | |
| — | **Media Sonnet** | [...] | [...] | [...] | [...] | [...] | [...] | [...] | [...]% |

\* **Cobertura** = (hallazgos correctos del agente) / (hallazgos de la línea
base) × 100.

### 2.2. Precisión (falsos positivos)

| Modelo | Hallazgos correctos | Falsos positivos (alucinaciones) | Precisión |
|---|---|---|---|
| Haiku  | [...] | [...] | [...]% |
| Sonnet | [...] | [...] | [...]% |

---

## 3. Análisis (respuestas a la sección 7 de la guía)

**Cobertura y precisión**
- [...]

**Comportamiento del agente** (estrategia, variabilidad, contención)
- [...]

**Costo y eficiencia** (pasos/tokens/USD vs. tiempo manual)
- [...]

**Comparación Haiku vs. Sonnet**
- [...]

**Perspectiva defensiva (*blue team*)**
- [...]

---

## 4. Conclusiones del Laboratorio

[... 2-3 párrafos: ¿es viable automatizar el reconocimiento con un agente?
¿con qué límites? ¿qué modelo conviene? ...]
