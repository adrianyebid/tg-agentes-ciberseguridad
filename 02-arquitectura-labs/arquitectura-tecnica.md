# Arquitectura Técnica de los Laboratorios

> **Actividad 3 (semanas 5-6), parte técnica.** Define el entorno
> virtualizado, los componentes del agente de IA y las métricas comunes a los
> tres laboratorios, sobre la base del análisis y los criterios de selección de
> la Actividad 2 ([analisis-categorizacion.md](analisis-categorizacion.md)). El
> diseño pedagógico (objetivos, guías, rúbricas) se trata en
> [arquitectura-pedagogica.md](arquitectura-pedagogica.md).

## 1. Principios de Diseño

La arquitectura se rige por cinco principios derivados de los criterios de
selección y las consideraciones éticas de la Actividad 2:

1. **Aislamiento por defecto.** El entorno no tiene salida a internet salvo la
   estrictamente necesaria para que el agente consulte la API del modelo. Las
   máquinas víctima nunca son alcanzables desde fuera del laboratorio.
2. **Reproducibilidad.** Todo el entorno se define como código
   (`docker-compose.yml`), de modo que cualquier evaluador pueda recrearlo de
   forma determinista con un solo comando.
3. **Contención del agente.** El agente solo puede ejecutar herramientas de una
   **lista blanca** y solo contra objetivos de una **lista blanca de IP**.
   Nunca ejecuta comandos arbitrarios del sistema del operador.
4. **Trazabilidad total.** Cada paso del ciclo del agente (pensamiento, acción,
   observación) queda registrado con marca de tiempo, para auditar el
   comportamiento y alimentar las métricas.
5. **Supervisión humana.** El operador puede abortar en cualquier momento, y
   las acciones de riesgo alto (Actividad 2) requieren aprobación explícita.

## 2. Arquitectura del Entorno Virtualizado

### 2.1. Topología de Red

El entorno se despliega con **Docker Desktop sobre WSL2** (Windows 11). Se
define una **red Docker interna aislada** (`internal: true`, sin acceso al
host ni a internet) que conecta el contenedor atacante con las máquinas
víctima. El contenedor atacante tiene una segunda interfaz, restringida por
reglas de salida, únicamente hacia la API del modelo.

```
                    ┌─────────────────────────────────────────────┐
                    │                 Host (Windows 11 + WSL2)     │
                    │                                              │
   API del modelo   │   ┌──────────────┐      red interna aislada │
   (api.anthropic   │   │  ATACANTE    │      (sin salida a        │
   .com) ◄──────────┼───┤  agente IA   │       internet)          │
   solo salida      │   │  (Python +   │                          │
   HTTPS del        │   │  Kali tools) │─────┐                    │
   atacante         │   └──────────────┘     │                    │
                    │                        ▼                    │
                    │              ┌──────────────────┐           │
                    │              │  VÍCTIMA 1        │  Lab 1-2  │
                    │              │  (servicios       │           │
                    │              │   vulnerables)    │           │
                    │              └──────────────────┘           │
                    │              ┌──────────────────┐           │
                    │              │  VÍCTIMA 2 .. N   │  Lab 3    │
                    │              │  (red multi-equipo)│          │
                    │              └──────────────────┘           │
                    └─────────────────────────────────────────────┘
```

### 2.2. Componentes del Entorno

| Componente | Rol | Implementación |
|---|---|---|
| **Contenedor atacante** | Aloja el agente de IA y las herramientas ofensivas. | Imagen base con Python 3.11 + herramientas (`nmap`, `whatweb`, `gobuster`, `nikto`, `searchsploit`, etc.). Punto de partida: imagen ligera de Kali o Debian + instalación de paquetes. |
| **Contenedor(es) víctima** | Objetivo del ataque, con servicios vulnerables controlados. | Imágenes reproducibles: p. ej. `vulnerables/web-dvwa`, `citizenstig/dvwa`, o servicios construidos a medida. Para Lab 3, varias instancias en la red interna. |
| **Red interna** | Segmento aislado atacante↔víctima. | `docker network` con `internal: true`; direccionamiento fijo (p. ej. `172.28.0.0/24`) para que la lista blanca sea estable. |
| **Volumen de resultados** | Persiste logs, capturas y métricas de cada corrida. | Volumen Docker montado en el atacante; los artefactos se copian al repo para análisis. |

### 2.3. Elección de Máquinas Víctima por Laboratorio

- **Lab 1 (Reconocimiento):** una víctima con varios servicios y una aplicación
  web, para que haya puertos, versiones y tecnologías que enumerar. DVWA o una
  imagen con `ssh` + `http` + un servicio adicional son suficientes.
- **Lab 2 (Escaneo):** la misma superficie del Lab 1, pero con vulnerabilidades
  conocidas y versiones específicas, de modo que exista una correlación
  servicio→CVE verificable (línea base conocida para medir precisión).
- **Lab 3 (Explotación):** una víctima con una vulnerabilidad explotable
  confirmada y, como extensión, una segunda víctima alcanzable solo desde la
  primera (para movimiento lateral). *Snapshots* reversibles obligatorios.

## 3. Arquitectura del Agente de IA

### 3.1. Visión General (ciclo ReAct)

El agente implementa el patrón **ReAct** [1]: alterna *razonamiento*
(*Thought*), *acción* (*Action*, invocar una herramienta) y *observación*
(*Observation*, el resultado), en un bucle, hasta cumplir el objetivo o agotar
un límite de iteraciones.

```
  Objetivo + reglas (prompt del sistema)
             │
             ▼
   ┌──────────────────────┐
   │  LLM (Messages API)  │◄───────────────┐
   │  decide: Thought     │                │
   │  + Action(tool,args) │                │ Observation
   └──────────┬───────────┘                │ (salida de la herramienta,
              │ Action                      │  truncada/resumida)
              ▼                             │
   ┌──────────────────────┐                │
   │ CAPA DE CONTENCIÓN    │                │
   │ · ¿tool en whitelist? │                │
   │ · ¿objetivo en IP     │                │
   │   whitelist?          │                │
   │ · ¿requiere aprobación│                │
   │   humana?             │                │
   └──────────┬───────────┘                │
              │ (permitido)                 │
              ▼                             │
   ┌──────────────────────┐                │
   │ EJECUTOR de           │────────────────┘
   │ herramientas (subproc)│
   │ + REGISTRO (log)      │
   └──────────────────────┘
```

### 3.2. Componentes del Agente

| Componente | Responsabilidad | Notas de implementación |
|---|---|---|
| **Núcleo de razonamiento (LLM)** | Decidir el siguiente paso e interpretar observaciones. | Messages API de Anthropic; modelo `claude-haiku-4-5` por defecto, conmutable a `claude-sonnet-5` con un parámetro. Autenticación por API key leída de `.env`. |
| **Definición de herramientas** | Catálogo cerrado de herramientas que el agente puede invocar, con su esquema de argumentos. | Se exponen como *tools* a la API (o se parsean del texto en una implementación ReAct manual). Cada una envuelve un binario del contenedor atacante. |
| **Capa de contención** | Validar cada acción antes de ejecutarla. | Verifica: herramienta ∈ lista blanca; objetivo ∈ IP permitidas; si la técnica es de riesgo alto, exige aprobación humana (modo A2). Rechaza y devuelve error como observación si no cumple. |
| **Ejecutor de herramientas** | Correr el comando y capturar salida. | `subprocess` con *timeout* por herramienta; captura `stdout`/`stderr`/código de salida; trunca o resume salidas largas para no desbordar el contexto. |
| **Memoria / estado** | Conservar hallazgos entre pasos. | Historial de mensajes (contexto) + un registro estructurado de hallazgos (hosts, puertos, servicios…) reutilizable entre fases y laboratorios. |
| **Registro (logging)** | Trazabilidad total. | Cada ciclo escribe: timestamp, Thought, Action+args, Observation (resumida), decisión de contención, tokens usados. Formato JSONL + resumen legible. |
| **Supervisor / límites** | Evitar bucles infinitos y gasto excesivo. | Límite de iteraciones, *timeout* global, tope de tokens/costo; interrupción manual (Ctrl-C) segura. |

### 3.3. Lista Blanca de Herramientas (base, Lab 1)

La lista crece por laboratorio. Para el Lab 1 se parte de herramientas de solo
lectura / reconocimiento:

| Herramienta | Uso | Técnica (ATT&CK) |
|---|---|---|
| `nmap` | Descubrimiento de hosts, puertos, versiones. | T1018, T1046 |
| `whatweb` | *Fingerprinting* de tecnologías web. | T1592 |
| `gobuster` / `ffuf` | Enumeración de rutas/directorios web. | T1595.003 |
| `dnsrecon` / `dig` | Enumeración DNS (si aplica). | T1590 |

> Herramientas intrusivas (`nikto`, `sqlmap`, `metasploit`) **no** se incluyen
> en el Lab 1; se habilitan en los Labs 2 y 3 junto con sus controles.

### 3.4. Controles de Seguridad (resumen operativo)

| Control | Qué previene | Cómo |
|---|---|---|
| Lista blanca de IP | Que el agente ataque fuera del laboratorio. | La capa de contención rechaza objetivos no incluidos. |
| Lista blanca de herramientas | Ejecución de comandos arbitrarios. | Solo se pueden invocar herramientas del catálogo. |
| Red interna sin internet | Fuga o impacto externo. | `internal: true`; solo el atacante tiene salida HTTPS a la API. |
| Aprobación humana (A2) | Acciones destructivas/irreversibles. | Pausa y pide confirmación en técnicas de riesgo alto. |
| Snapshots / recreación | Daño irreversible a la víctima. | `docker compose down && up` restaura el estado; snapshots en Lab 3. |
| Límite de iteraciones/tokens | Bucles infinitos y gasto. | Supervisor aborta al superar el umbral. |
| Registro completo | Falta de auditoría. | Log JSONL de cada paso. |

## 4. Métricas Comunes de Evaluación

Todos los laboratorios comparan el desempeño del agente contra una **línea base
manual (A0)** usando un conjunto común de métricas. Cada laboratorio añade las
suyas específicas.

| Métrica | Definición | Cómo se mide | Aplica a |
|---|---|---|---|
| **Cobertura** | % de activos/hallazgos esperados que el agente descubre. | Hallazgos del agente ÷ hallazgos de la línea base (conocida). | Todos |
| **Precisión** | % de hallazgos del agente que son correctos (no alucinados). | Verdaderos positivos ÷ (VP + falsos positivos). | Lab 2, 3 |
| **Tiempo** | Duración total de la corrida. | Marca de inicio y fin. | Todos |
| **Nº de pasos** | Iteraciones del ciclo ReAct hasta terminar. | Conteo en el log. | Todos |
| **Costo / tokens** | Tokens de entrada+salida y costo estimado. | `usage` de la respuesta de la API, acumulado. | Todos |
| **Tasa de éxito** | ¿Logró el objetivo de la fase? (binario o por intentos). | Comprobación del objetivo del lab. | Lab 2, 3 |
| **Intervenciones humanas** | Nº de aprobaciones/correcciones necesarias. | Conteo en el log. | Lab 3 |
| **Errores / alucinaciones** | Acciones inválidas, rechazadas por contención o falsas. | Conteo en el log. | Todos |

> **Rigor experimental:** cada configuración se ejecuta **varias veces** (p. ej.
> n=5) para reportar media y variabilidad, dado que el comportamiento del LLM no
> es determinista. La línea base manual se documenta una vez por laboratorio y
> sirve de referencia fija.

## 5. Stack Tecnológico Resumido

| Capa | Tecnología | Justificación |
|---|---|---|
| Virtualización | Docker Desktop + WSL2 (Windows 11) | Ligero, reproducible, aislamiento de red nativo. |
| Agente | Python 3.11 + SDK `anthropic` | Lenguaje estándar para agentes; SDK oficial gestiona auth y reintentos. |
| Modelo | `claude-haiku-4-5` (→ `claude-sonnet-5`) | Bajo costo por corrida; conmutable para comparar calidad. |
| Herramientas ofensivas | nmap, whatweb, gobuster, (nikto/sqlmap/metasploit en labs posteriores) | Estándar de la industria, salida interpretable por el LLM. |
| Víctimas | Imágenes Docker vulnerables (DVWA, etc.) | Reproducibles y diseñadas para entrenamiento. |
| Registro/análisis | Logs JSONL + Markdown | Auditable y fácil de convertir en tablas para el informe. |

Este diseño técnico se materializa, laboratorio por laboratorio, en
[../03-laboratorios/](../03-laboratorios/), empezando por el Lab 1. Los aspectos
de aprendizaje y evaluación se definen en
[arquitectura-pedagogica.md](arquitectura-pedagogica.md).
