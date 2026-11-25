# Laboratorio 2 — Escaneo y Análisis de Vulnerabilidades con Agentes

> Segundo laboratorio del diseño de la
> [Actividad 3](../../02-arquitectura-labs/arquitectura-tecnica.md). Un agente de
> IA (ciclo ReAct) **detecta, correlaciona con CVE y prioriza** vulnerabilidades
> sobre la superficie expuesta por la víctima, y se mide su **precisión** (cuántas
> vulnerabilidades reporta que son reales vs. inventadas). Corresponde a las
> semanas 9-10 del cronograma. Reutiliza la arquitectura del
> [Lab 1](../lab1-reconocimiento/).

---

## 1. Contexto y Fundamentación

El **escaneo y análisis de vulnerabilidades** es la fase que sigue al
reconocimiento: sobre los servicios ya descubiertos, se identifican debilidades
concretas (versiones obsoletas, configuraciones peligrosas, CVE conocidas) y se
priorizan por gravedad. Corresponde a la táctica *Discovery* de MITRE ATT&CK
(T1595.002, correlación servicio→CVE).

Según el análisis de la [Actividad 2](../../02-arquitectura-labs/analisis-categorizacion.md),
esta categoría mantiene buena autonomía, pero introduce un reto nuevo: la
**correlación servicio→CVE** y la **priorización** dependen fuertemente del
razonamiento del modelo y son **propensas a la alucinación** (afirmar que algo es
vulnerable sin evidencia). Por eso la métrica estrella de este laboratorio es la
**precisión**.

**Diferencia con el Lab 1:**

| | Lab 1 (Reconocimiento) | Lab 2 (Vulnerabilidades) |
|---|---|---|
| Pregunta | ¿Qué hay expuesto? | ¿Qué es vulnerable y qué tan grave? |
| Métrica estrella | Cobertura | **Precisión** (falsos positivos) |
| Reto nuevo | — | Correlación CVE y priorización (alucinación) |

## 2. Objetivos de Aprendizaje

- **Configurar y ejecutar** un agente que detecte y priorice vulnerabilidades de
  forma autónoma. *(Aplicar)*
- **Analizar** la **precisión** del agente (verdaderos vs. falsos positivos) y su
  acierto en la correlación CVE, frente a una línea base. *(Analizar)*
- **Evaluar** el riesgo de alucinación de los agentes en tareas de análisis de
  seguridad y la necesidad de verificación humana. *(Evaluar)*
- **Proponer** medidas defensivas (gestión de parches, reducción de superficie).
  *(Crear)*

## 3. Requisitos Previos

- Docker Desktop con WSL2 (verificado con `docker run --rm hello-world`).
- Clave de API de Anthropic **o** Ollama para modelo local (ver `.env.example`).
- Haber comprendido el [Lab 1](../lab1-reconocimiento/) (misma arquitectura).

## 4. Montaje del Entorno

**4.1. Configura el modelo.** Copia la plantilla y edítala:
```bash
cp .env.example .env
nano .env      # elige proveedor (anthropic/ollama), modelo y, si aplica, la API key
```

**4.2. Levanta el entorno:**
```bash
# Modelo de pago (Anthropic):
docker compose up -d --build
# Modelo local/gratis (Ollama): añade el perfil y descarga el modelo
docker compose --profile local up -d --build
docker compose exec ollama ollama pull qwen2.5:3b
```

**4.3. Verifica aislamiento y conectividad:**
```bash
docker compose exec atacante nmap -sn 172.29.0.10     # el atacante ve a la víctima
docker compose exec victima ping -c 2 8.8.8.8 || echo "OK: víctima aislada de internet"
```

## 5. Desarrollo — Parte A: Análisis Manual (línea base de verdad)

Antes de usar el agente, realiza tú el análisis para construir la **"verdad"**
contra la cual se mide la precisión. Ejecuta y **anota las vulnerabilidades
reales**:

```bash
# Versiones de servicios y vulnerabilidades de red:
docker compose exec atacante nmap -sV --script vuln 172.29.0.10

# Vulnerabilidades y configuraciones peligrosas del servidor web:
docker compose exec atacante nikto -h http://172.29.0.10 -maxtime 200s -ask no

# Correlación servicio -> CVE (ajusta la versión a la que te dio nmap/whatweb):
docker compose exec atacante searchsploit apache 2.4.25
docker compose exec atacante searchsploit php
```

Registra en [resultados.md](resultados.md) la **lista de vulnerabilidades reales
confirmadas** (ese es el denominador y el patrón de verdad para la precisión).

## 6. Desarrollo — Parte B: Análisis con el Agente

Lanza el agente **varias veces** (n = 5 por modelo recomendado):
```bash
docker compose exec atacante python3 agente_vuln.py
```

El agente mostrará su ciclo ReAct y, al final, un **resumen priorizado de
vulnerabilidades con su evidencia y CVE**. Guarda `output/informe-*.md` y
`output/vulnscan-*.jsonl` por corrida. Para comparar modelos, cambia
`LAB_MODELO` (o pásalo con `-e LAB_MODELO=...`) y repite.

## 7. Análisis y Preguntas de Reflexión

Genera la tabla de métricas y la verificación de CVE (qué CVE citó el agente y
si están en la evidencia):
```bash
python3 analizar_metricas.py
python3 verificar_cves.py
```

Completa las tablas de [resultados.md](resultados.md) y responde:

**Precisión (lo central)**
- De las vulnerabilidades que reportó el agente, ¿cuántas son **reales**
  (verdaderos positivos) y cuántas **inventadas** (falsos positivos)?
- ¿Cada hallazgo venía con **evidencia** de una herramienta, como se le exigió?

**Correlación CVE y priorización**
- ¿Acertó al asociar los servicios con CVE conocidas? ¿Inventó CVE?
- ¿Priorizó razonablemente (lo más grave primero)?

**Comparación de modelos y comportamiento**
- ¿El modelo local (gratis) alucina más que el de pago? ¿Es más conservador?
- ¿Varió mucho entre corridas?

**Perspectiva defensiva (*blue team*)**
- ¿Cómo mitigarías las vulnerabilidades reales encontradas? (gestión de parches,
  endurecimiento, reducción de superficie, segmentación).

## 8. Entregables

1. `resultados.md` completo (línea base de vulnerabilidades reales + tablas de
   precisión por corrida + análisis).
2. La carpeta `output/` con los logs e informes de las corridas.
3. Informe corto respondiendo las preguntas de la sección 7.

La evaluación sigue la **rúbrica común** de
[../../02-arquitectura-labs/arquitectura-pedagogica.md](../../02-arquitectura-labs/arquitectura-pedagogica.md).

---

## Apéndice: Limpieza

```bash
docker compose down            # detiene y elimina los contenedores
docker compose --profile local down   # si usaste Ollama
```

## Estructura de la Carpeta

```
lab2-vulnerabilidades/
├── README.md              # esta guía
├── docker-compose.yml     # entorno: red aislada + atacante + víctima + ollama
├── Dockerfile             # imagen del atacante (nmap, nikto, searchsploit + agente)
├── .env.example           # plantilla de configuración (copiar a .env)
├── resultados.md          # plantilla para registrar precisión y métricas
├── analizar_metricas.py   # agrega las métricas de las corridas
├── verificar_cves.py      # cruza las CVE citadas con la evidencia (precisión)
└── agente/
    ├── agente_vuln.py     # el agente de análisis de vulnerabilidades
    └── requirements.txt
```

## Nota Ética

Fase de **análisis**, no de explotación: el agente detecta y correlaciona, pero
no explota (eso es el Lab 3). Entorno aislado, víctima de práctica (DVWA), capa
de contención activa. Uso exclusivamente educativo y defensivo.
