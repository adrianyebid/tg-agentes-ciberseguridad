# Laboratorio 1 — Reconocimiento Automatizado con Agentes

> Primera materialización del diseño de la
> [Actividad 3](../../02-arquitectura-labs/arquitectura-tecnica.md). Un agente
> de IA (ciclo ReAct) enumera de forma autónoma la superficie expuesta por una
> máquina víctima en una red Docker aislada, y se compara su desempeño con un
> reconocimiento manual. Corresponde a las semanas 7-8 del cronograma.

---

## 1. Contexto y Fundamentación

El **reconocimiento** es la primera fase de un ciberataque (Cyber Kill Chain
[14]) y la táctica *Reconnaissance* de MITRE ATT&CK [13]: consiste en recolectar
información sobre el objetivo (hosts, puertos, servicios, versiones,
tecnologías) **antes** de intentar cualquier explotación.

Según el análisis de la [Actividad 2](../../02-arquitectura-labs/analisis-categorizacion.md),
esta es la categoría con **mayor autonomía demostrada (hasta A3) y menor
riesgo**: sus técnicas son de solo lectura, no modifican el objetivo, y la
salida de las herramientas es fácil de interpretar por un LLM. Por eso es el
laboratorio base, sobre el que se construyen los Labs 2 y 3.

**Técnicas ATT&CK cubiertas:** T1018 (descubrimiento de hosts), T1046 (escaneo
de servicios/puertos), T1592 (fingerprinting de tecnologías), T1595.003
(enumeración de rutas web).

## 2. Objetivos de Aprendizaje

- **Configurar y ejecutar** un agente ReAct que enumere de forma autónoma una
  víctima. *(Aplicar)*
- **Analizar** la cobertura del agente frente a un reconocimiento manual
  mediante métricas objetivas. *(Analizar)*
- **Evaluar** las ventajas, límites, costo y riesgos del uso de un agente de IA
  en esta fase. *(Evaluar)*
- **Proponer** medidas defensivas de detección del reconocimiento. *(Crear)*

## 3. Requisitos Previos

- **Docker Desktop** con integración **WSL2** activada (verificado con
  `docker run --rm hello-world` desde Ubuntu/WSL).
- **Clave de API de Anthropic** (se configura en el paso 4).
- Conocimientos básicos de redes (IP, puertos) y de línea de comandos Linux.
- Trabajar desde **WSL (Ubuntu)**, no desde PowerShell.

> **Nota sobre la ubicación de los archivos.** El repositorio está en el lado
> Windows. Desde WSL se accede vía `/mnt/c/...`. Para evitar la lentitud de
> montar OneDrive, se recomienda **copiar esta carpeta a tu HOME de WSL** antes
> de trabajar:
> ```bash
> cp -r "/mnt/c/Users/ASUS/OneDrive/Desktop/tg-agentes-ciberseguridad/03-laboratorios/lab1-reconocimiento" ~/lab1
> cd ~/lab1
> ```
> Al terminar, copia la carpeta `output/` de vuelta al repo para versionar los
> resultados.

## 4. Montaje del Entorno

**4.1. Configura tu clave de API.** En la carpeta del laboratorio (junto a
`docker-compose.yml`):

```bash
cp .env.example .env
nano .env     # pega tu ANTHROPIC_API_KEY real y guarda (Ctrl+O, Enter, Ctrl+X)
```

**4.2. Levanta el entorno** (construye la imagen del atacante y arranca ambas
máquinas):

```bash
docker compose up -d --build
```

**4.3. Verifica el aislamiento y la conectividad interna:**

```bash
# El atacante ve a la víctima en la red interna:
docker compose exec atacante ping -c 2 172.28.0.10

# Pero la víctima NO tiene salida a internet (debe fallar / no resolver):
docker compose exec victima ping -c 2 8.8.8.8 || echo "OK: víctima aislada de internet"
```

Si el primer comando responde y el segundo falla, el entorno está correcto.

## 5. Desarrollo — Parte A: Reconocimiento Manual (línea base)

Antes de usar el agente, realiza tú mismo el reconocimiento. Esto crea la
**línea base (nivel A0)** contra la cual se mide al agente. Ejecuta y **anota
todos los hallazgos** (puertos, servicios, versiones, tecnologías, rutas):

```bash
# Descubrimiento de puertos, servicios y versiones:
docker compose exec atacante nmap -sV -T4 172.28.0.10

# Tecnologías web:
docker compose exec atacante whatweb http://172.28.0.10

# Rutas/directorios web:
docker compose exec atacante gobuster dir -u http://172.28.0.10 \
    -w /usr/share/dirb/wordlists/common.txt -q
```

Registra los resultados en la sección correspondiente de
[resultados.md](resultados.md) (columna "Manual").

## 6. Desarrollo — Parte B: Reconocimiento con el Agente

Lanza el agente **varias veces** (se recomienda **n = 5** corridas, por el
carácter no determinista del LLM):

```bash
docker compose exec atacante python3 agente_recon.py
```

El agente mostrará en vivo su ciclo ReAct (🧠 razonamiento, ⚙️ herramienta,
└─ observación). Al terminar imprime las **métricas** de la corrida y guarda:

- `output/recon-<fecha>.jsonl` — log completo, paso a paso.
- `output/informe-<fecha>.md`  — métricas + resumen final del agente.

Repite el comando para cada corrida. Para probar el otro modelo y compararlo,
edita `LAB_MODELO=claude-sonnet-5` en `.env` y vuelve a ejecutar.

## 7. Análisis y Preguntas de Reflexión

Completa la tabla de métricas en [resultados.md](resultados.md) y responde:

**Cobertura y precisión**
- ¿Qué porcentaje de los hallazgos manuales descubrió el agente (cobertura)?
- ¿Reportó el agente algo que NO existe (alucinaciones / falsos positivos)?
- ¿Hubo hallazgos que el agente encontró y tú no?

**Comportamiento del agente**
- ¿Qué estrategia siguió? ¿El orden de las herramientas fue razonable?
- ¿Varió mucho entre corridas? ¿Y entre Haiku y Sonnet?
- ¿Se rechazó alguna acción por la capa de contención? ¿Por qué?

**Costo y eficiencia**
- ¿Cuántos pasos, tokens y USD costó en promedio una corrida?
- ¿Compensa la autonomía frente al tiempo del reconocimiento manual?

**Perspectiva defensiva (*blue team*)**
- ¿Cómo detectarías este reconocimiento desde el lado defensivo? (patrones de
  escaneo en un IDS como Snort/Suricata, *rate limiting*, reducción de la
  superficie expuesta, ofuscación de *banners*).

## 8. Entregables

1. `resultados.md` completo (línea base manual + tabla de métricas de las n
   corridas + análisis).
2. La carpeta `output/` con los logs JSONL e informes de las corridas.
3. Un informe corto (puede ser la propia sección de análisis de
   `resultados.md`) que responda las preguntas de la sección 7.

La evaluación sigue la **rúbrica común** definida en
[../../02-arquitectura-labs/arquitectura-pedagogica.md](../../02-arquitectura-labs/arquitectura-pedagogica.md).

---

## Apéndice: Limpieza del Entorno

```bash
docker compose down            # detiene y elimina los contenedores
docker compose down --rmi all  # además elimina las imágenes construidas
```

## Estructura de la Carpeta

```
lab1-reconocimiento/
├── README.md              # esta guía
├── docker-compose.yml     # entorno: red aislada + atacante + víctima
├── Dockerfile             # imagen del atacante (herramientas + agente)
├── .env.example           # plantilla de configuración (copiar a .env)
├── resultados.md          # plantilla para registrar hallazgos y métricas
├── agente/
│   ├── agente_recon.py    # el agente ReAct
│   └── requirements.txt   # dependencias Python
└── output/                # (generado) logs e informes de cada corrida
```
