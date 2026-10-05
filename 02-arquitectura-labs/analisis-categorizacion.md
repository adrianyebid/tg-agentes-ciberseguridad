# Análisis y Categorización de Ciberataques Ejecutables con Agentes de IA

> **Actividad 2 (semanas 3-4).** Este documento profundiza la categorización
> inicial realizada en el estado del arte
> ([../01-estado-del-arte/ciberataques.md](../01-estado-del-arte/ciberataques.md))
> y la convierte en un instrumento de análisis a nivel de **técnica**, con el
> objetivo explícito de **seleccionar y justificar** qué ataques se
> implementarán en los tres laboratorios prácticos. Es el puente entre la
> revisión bibliográfica (Actividad 1) y el diseño de la arquitectura
> (Actividad 3).

## 1. Objetivo y Alcance

El estado del arte estableció **cuatro categorías** de ataques ejecutables por
agentes (reconocimiento, escaneo/enumeración, explotación, y movimiento
lateral/post-explotación) y las mapeó a los marcos Cyber Kill Chain [14] y
MITRE ATT&CK [13]. Esa categorización responde a la pregunta *"¿qué fases de un
ataque puede cubrir un agente?"*.

Esta actividad responde a tres preguntas más finas, necesarias para diseñar los
laboratorios:

1. **¿Qué técnicas concretas** (no solo fases) puede ejecutar un agente, y con
   qué herramientas?
2. **¿Cuánta autonomía real** tiene el agente en cada técnica, según la
   evidencia de la literatura? No es lo mismo "sugerir un comando" que
   "planificar, ejecutar e interpretar una cadena de comandos sin intervención
   humana".
3. **¿Qué técnicas son adecuadas para un laboratorio** reproducible, medible y
   éticamente seguro en el entorno descrito en la Actividad 3?

## 2. Marco de Análisis

Para analizar cada técnica de forma homogénea se definen tres dimensiones.

### 2.1. Mapeo a MITRE ATT&CK

Cada técnica se identifica con su **táctica** (el *objetivo* del adversario) y
su **ID de técnica** en MITRE ATT&CK [13]. Esto ancla el análisis a un marco
estándar y permite, más adelante, documentar los laboratorios en un lenguaje
reconocible por la comunidad de seguridad.

### 2.2. Escala de Autonomía del Agente

Se propone una escala ordinal de 0 a 4 para medir **cuánto del trabajo asume el
agente** frente al operador humano. Esta escala es un aporte propio de este
trabajo, inspirada en la distinción *human-in-the-loop* / *human-on-the-loop*
discutida en los marcos de riesgo [11][12] y en los niveles de autonomía
usados en otros dominios (p. ej. conducción autónoma).

| Nivel | Nombre | Descripción | Rol del humano |
|---|---|---|---|
| **A0** | Manual | El agente no interviene; sirve de línea base. | Ejecuta todo. |
| **A1** | Asistido | El agente sugiere comandos o interpreta salidas, pero el humano ejecuta. | Decide y ejecuta. |
| **A2** | Semiautónomo | El agente planifica y ejecuta herramientas, pero pide aprobación en pasos sensibles. | Supervisa y aprueba (*on-the-loop*). |
| **A3** | Autónomo supervisado | El agente ejecuta la cadena completa de la fase sin aprobación paso a paso; el humano observa y puede abortar. | Observa; puede detener. |
| **A4** | Autónomo | El agente planifica, ejecuta e interpreta toda la fase y decide la transición a la siguiente sin intervención. | Define objetivo inicial y revisa el resultado. |

> **Nota sobre la evidencia:** los niveles que se asignan más abajo reflejan la
> **máxima autonomía demostrada en la literatura revisada**, no necesariamente
> la que se habilitará en los laboratorios. Por principio ético (sección 6 y
> Actividad 3), los laboratorios de este trabajo se operarán con controles que
> fuerzan como máximo **A3**, manteniendo siempre la capacidad humana de
> abortar y, en las técnicas destructivas, aprobación explícita (A2).

### 2.3. Dificultad y Riesgo

- **Dificultad para el agente** (Baja/Media/Alta): qué tan propensa es la
  técnica a fallos de razonamiento, alucinaciones o cadenas largas de varios
  pasos, según la evidencia.
- **Riesgo en el laboratorio** (Bajo/Medio/Alto): potencial de daño o
  irreversibilidad si la técnica se ejecuta de forma autónoma (p. ej. borrado
  de datos, impacto fuera del entorno aislado). Esta dimensión condiciona qué
  controles de seguridad exige cada laboratorio.

## 3. Matriz de Técnicas por Categoría

### 3.1. Categoría 1 — Reconocimiento

| Técnica | Táctica / ID ATT&CK | Herramientas típicas del agente | Autonomía demostrada | Dificultad | Riesgo | Evidencia |
|---|---|---|---|---|---|---|
| Enumeración de subdominios / DNS | Reconnaissance / T1590 | `dnsrecon`, `amass`, `dig` | A3 | Baja | Bajo | [5][8] |
| Descubrimiento de hosts en red | Reconnaissance / T1018 | `nmap -sn`, `fping` | A3 | Baja | Bajo | [5] |
| *Fingerprinting* de tecnologías web | Reconnaissance / T1592 | `whatweb`, `wappalyzer`, cabeceras HTTP | A3 | Baja | Bajo | [5][8] |
| Enumeración de directorios/rutas web | Reconnaissance / T1595.003 | `gobuster`, `ffuf`, `dirb` | A3 | Baja | Bajo | [5][8] |
| OSINT sobre personas/organización | Reconnaissance / T1589-T1591 | navegador, buscadores, `theHarvester` | A2 | Media | Bajo | [8] |

**Síntesis:** el reconocimiento es la categoría con **mayor autonomía
demostrada y menor riesgo**. Las técnicas son de solo lectura (no modifican el
objetivo), sus herramientas producen salida estructurada fácil de interpretar
por el LLM, y el patrón "reconocer antes de atacar" emerge de forma natural del
razonamiento del agente [8]. Es, por tanto, el candidato ideal para el primer
laboratorio.

### 3.2. Categoría 2 — Escaneo y Enumeración de Vulnerabilidades

| Técnica | Táctica / ID ATT&CK | Herramientas típicas del agente | Autonomía demostrada | Dificultad | Riesgo | Evidencia |
|---|---|---|---|---|---|---|
| Escaneo de puertos y versiones | Discovery / T1046 | `nmap -sV`, `nmap -sC` | A3 | Baja | Bajo | [5][6] |
| Escaneo de vulnerabilidades web | Discovery / T1595.002 | `nikto`, `wpscan` | A3 | Media | Medio | [5] |
| Correlación servicio→CVE | Discovery / T1046 | `searchsploit`, bases CVE/NVD | A2 | Media | Bajo | [7][10] |
| Enumeración local post-acceso | Discovery / T1082, T1083 | comandos del SO, `linpeas` | A3 | Media | Medio | [6] |
| Priorización de vulnerabilidades | — (razonamiento) | contexto + criterio del LLM | A2 | Alta | Bajo | [10] |

**Síntesis:** el escaneo mantiene buena autonomía pero introduce dos retos. La
**correlación servicio→CVE** y la **priorización** dependen fuertemente de la
calidad del razonamiento del modelo y son propensas a alucinaciones (p. ej.
afirmar que un servicio es vulnerable sin evidencia), lo que CyberSecEval 2 [10]
mide explícitamente. Algunas herramientas (`nikto`, `wpscan`) son
intrusivas/ruidosas, elevando el riesgo a Medio. Es un buen candidato para el
segundo laboratorio, que debe incorporar métricas de *precisión* (verdaderos vs.
falsos positivos).

### 3.3. Categoría 3 — Explotación

| Técnica | Táctica / ID ATT&CK | Herramientas típicas del agente | Autonomía demostrada | Dificultad | Riesgo | Evidencia |
|---|---|---|---|---|---|---|
| Explotación de CVE conocida (*one-day*) | Initial Access / T1190 | `metasploit`, exploits públicos | A3 | Media | Alto | [7] |
| Inyección SQL | Initial Access / T1190 | `sqlmap`, *payloads* manuales | A3 | Media | Alto | [8] |
| Cross-Site Scripting (XSS) | Initial Access / T1059.007 | *payloads* en navegador | A2 | Media | Medio | [8] |
| *Path traversal* / LFI | Initial Access / T1190 | peticiones HTTP manipuladas | A2 | Media | Alto | [8] |
| Ejecución de comandos (RCE) | Execution / T1059 | *shells*, `msfvenom` | A2 | Alta | Alto | [5][7] |

**Síntesis:** la explotación es donde la autonomía demostrada es **alta pero el
riesgo también** (ejecución de código arbitrario, posible daño al objetivo). La
literatura muestra éxito notable en *one-day exploitation* [7] e inyección web
[8], pero con mayor dependencia del *prompting* y más fallos en cadenas largas.
Para un laboratorio, estas técnicas **exigen controles estrictos**: lista blanca
de objetivos, *snapshots* reversibles y, para las de riesgo Alto, aprobación
humana (A2). Fundamenta el tercer laboratorio.

### 3.4. Categoría 4 — Movimiento Lateral y Post-Explotación

| Técnica | Táctica / ID ATT&CK | Herramientas típicas del agente | Autonomía demostrada | Dificultad | Riesgo | Evidencia |
|---|---|---|---|---|---|---|
| Escalación de privilegios local | Privilege Escalation / T1548 | `linpeas`, binarios SUID, `sudo` | A3 | Media | Alto | [6] |
| Descubrimiento de credenciales | Credential Access / T1552 | lectura de archivos de config | A3 | Media | Alto | [6] |
| Descubrimiento de red interna | Discovery / T1046, T1018 | `nmap` desde el host comprometido | A3 | Media | Medio | [9] |
| Movimiento lateral | Lateral Movement / T1021 | SSH, credenciales reutilizadas | A2 | Alta | Alto | [9] |
| Persistencia | Persistence / T1053, T1136 | `cron`, nuevos usuarios | A2 | Alta | Alto | [9] |

**Síntesis:** es la categoría **más compleja y de mayor riesgo**. Requiere
mantener coherencia en tareas largas de varios pasos y varios equipos, lo que
AutoAttacker [9] aborda con una arquitectura **multiagente** (roles de
planificación, resumen y ejecución). Para este trabajo se aborda como extensión
del tercer laboratorio, con el entorno multi-equipo descrito en la Actividad 3,
y manteniendo controles de aprobación en persistencia y movimiento lateral.

## 4. Clasificación según Capacidades del Agente

Más allá de la fase del ataque, es útil clasificar las técnicas por **qué
capacidad del agente exigen**, porque esto determina directamente la
complejidad del código del agente que se construirá (Actividad 3 y labs):

| Capacidad exigida | Descripción | Técnicas representativas | Implicación de diseño |
|---|---|---|---|
| **Solo razonamiento** | El agente decide/interpreta sin ejecutar nada nuevo. | Priorización de CVE, correlación servicio→CVE. | Una llamada al LLM; sin bucle de herramientas. |
| **Razonamiento + herramientas** (ReAct) | Ciclo pensar→ejecutar→observar sobre un objetivo. | Reconocimiento, escaneo de puertos. | Bucle ReAct con lista blanca de herramientas. |
| **Razonamiento + herramientas + memoria** | Cadenas largas donde el estado previo importa. | Explotación multi-paso, escalación de privilegios. | ReAct + memoria/estado + límite de iteraciones. |
| **Multiagente / roles** | División de tareas entre varios agentes coordinados. | Movimiento lateral en red multi-equipo. | Orquestación de varios agentes (planificador/ejecutor). |

El **Laboratorio 1** se sitúa deliberadamente en el nivel *razonamiento +
herramientas* (ReAct), el más estudiado y estable [1][5][8], lo que lo hace
idóneo como primer laboratorio y base reutilizable para los siguientes.

## 5. Criterios de Selección de Ataques para los Laboratorios

No toda técnica analizada es apta para un laboratorio académico. Se definen
**cinco criterios**; cada técnica candidata se evalúa contra ellos:

1. **Reproducibilidad:** debe poder montarse de forma determinista en un
   entorno virtualizado y aislado (Docker), sin depender de servicios externos
   ni de internet.
2. **Valor pedagógico:** debe ilustrar con claridad una fase del ataque y el
   rol del agente en ella, y conectar con los marcos ATT&CK / Kill Chain.
3. **Mensurabilidad:** debe permitir definir métricas objetivas (cobertura,
   precisión, tiempo, nº de pasos, tokens/costo) comparables contra una línea
   base manual (A0).
4. **Seguridad ética:** su ejecución autónoma no debe poder causar daño fuera
   del entorno aislado, y las técnicas destructivas deben poder confinarse con
   controles (lista blanca, *snapshots*, aprobación humana).
5. **Factibilidad técnica:** debe ser implementable con el hardware y el stack
   acordados (Docker sobre WSL2, agente en Python + Messages API), en el tiempo
   del cronograma.

### 5.1. Resultado de la Evaluación

| Categoría / técnica núcleo | C1 Repro. | C2 Pedag. | C3 Medir | C4 Ética | C5 Factib. | Decisión |
|---|:--:|:--:|:--:|:--:|:--:|---|
| **Reconocimiento** (puertos, servicios, web) | ✅ | ✅ | ✅ | ✅ | ✅ | **Lab 1 — núcleo** |
| **Escaneo/enum. de vulnerabilidades** | ✅ | ✅ | ✅ | ⚠️ ruido | ✅ | **Lab 2 — núcleo** |
| **Explotación** (CVE *one-day*, SQLi) | ✅ | ✅ | ✅ | ⚠️ control | ✅ | **Lab 3 — núcleo** |
| **Escalación de privilegios** | ✅ | ✅ | ✅ | ⚠️ control | ✅ | **Lab 3 — extensión** |
| **Movimiento lateral multi-equipo** | ⚠️ | ✅ | ⚠️ | ⚠️ control | ⚠️ tiempo | **Lab 3 — opcional/avanzado** |
| OSINT sobre personas reales | ❌ | ⚠️ | ❌ | ❌ | — | **Excluido** (datos reales, no reproducible, riesgo de privacidad) |

**Leyenda:** ✅ cumple · ⚠️ cumple con condiciones · ❌ no cumple.

### 5.2. Conclusión: Alcance de los Tres Laboratorios

- **Laboratorio 1 — Reconocimiento (semanas 7-8):** agente ReAct que enumera de
  forma autónoma (hasta A3) hosts, puertos, servicios y tecnologías de una
  máquina víctima en red Docker aislada. Riesgo bajo, alta autonomía, ideal
  como base.
- **Laboratorio 2 — Escaneo de vulnerabilidades (semanas 9-10):** el agente
  escanea y **prioriza** vulnerabilidades sobre la superficie del Lab 1,
  midiendo precisión (falsos positivos) y acierto en la correlación CVE.
- **Laboratorio 3 — Explotación y post-explotación (semanas 11-12):** el agente
  explota una vulnerabilidad confirmada en el Lab 2 y, como extensión, escala
  privilegios y (opcional) se mueve lateralmente en una red multi-equipo, con
  controles estrictos y aprobación humana en las técnicas de riesgo alto.

Los tres laboratorios comparten el **mismo agente base** (ciclo ReAct + lista
blanca de herramientas + registro), que se irá ampliando laboratorio a
laboratorio. El diseño de ese agente y del entorno es el objeto de la
**Actividad 3** ([arquitectura-tecnica.md](arquitectura-tecnica.md) y
[arquitectura-pedagogica.md](arquitectura-pedagogica.md)).

## 6. Consideraciones Éticas de la Selección

Coherente con los marcos de riesgo revisados (MITRE ATLAS [11], OWASP Top 10
for LLM Applications [12]) y con la sección de uso dual del estado del arte:

- Se **excluye** toda técnica que, por naturaleza, requiera datos o sistemas
  reales de terceros (p. ej. OSINT sobre personas reales).
- Las técnicas de riesgo Alto se habilitan solo bajo controles verificables:
  **lista blanca de objetivos** (el agente solo puede actuar sobre las IP del
  laboratorio), **entorno sin salida a internet** salvo hacia la API del
  modelo, **snapshots reversibles**, **registro completo** de cada acción, y
  **aprobación humana** en las acciones destructivas o irreversibles.
- La autonomía operativa se limita a **A3** como máximo; A4 se documenta como
  capacidad existente en la literatura, no como modo de operación de los
  laboratorios.

Estos controles son un requisito de entrada para el diseño de la arquitectura
técnica de la Actividad 3.
