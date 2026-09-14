# Agentes Inteligentes basados en LLM: Fundamentos, Frameworks y Aplicaciones en Ciberseguridad

## 1. Introducción

Un **agente inteligente** es un sistema de software capaz de percibir su
entorno, razonar sobre esa información y actuar sobre el entorno para
cumplir un objetivo, generalmente de forma autónoma y a través de ciclos
iterativos de percepción-decisión-acción. Con la llegada de los modelos de
lenguaje de gran escala (*Large Language Models*, LLM) con capacidades
avanzadas de razonamiento, la industria y la academia han desarrollado una
nueva generación de agentes —los **agentes basados en LLM**— en los que el
modelo de lenguaje actúa como el "cerebro" o núcleo de razonamiento del
agente, orquestando el uso de herramientas externas (buscadores, shells,
APIs, navegadores, exploits, etc.), manteniendo memoria de largo plazo y
descomponiendo objetivos complejos en subtareas ejecutables [1]-[3].

Esta capacidad de razonar y actuar de forma encadenada es lo que ha hecho
que estos agentes pasen de ser simples chatbots a **operadores autónomos**
capaces de completar tareas de varios pasos sin intervención humana
constante, incluyendo tareas de ciberseguridad ofensiva y defensiva, que es
el foco de este trabajo de grado.

## 2. Arquitectura General de un Agente basado en LLM

La literatura converge en identificar cuatro componentes principales en la
arquitectura de un agente basado en LLM [2], [3]:

1. **Núcleo de razonamiento (LLM)**: el modelo de lenguaje que interpreta el
   objetivo, genera planes y decide qué acción tomar en cada paso.
2. **Planificación**: descomposición del objetivo en subtareas, ya sea
   mediante planificación explícita (generar un plan completo antes de
   actuar) o mediante planificación reactiva paso a paso.
3. **Memoria**: almacenamiento de contexto de corto plazo (la conversación
   actual) y de largo plazo (bases de conocimiento externas, bases
   vectoriales, resultados de acciones previas), que permite al agente
   recordar información relevante a través de múltiples pasos o sesiones.
4. **Uso de herramientas (*tool use*)**: capacidad de invocar funciones,
   APIs, comandos de shell, navegadores web o cualquier otro recurso
   externo para obtener información o modificar el entorno, y de
   interpretar el resultado de esa invocación para decidir el siguiente
   paso.

### 2.1. El patrón ReAct

El patrón arquitectónico más influyente para agentes basados en LLM es
**ReAct** (*Reasoning and Acting*), propuesto por Yao et al. [1]. ReAct
intercala pasos explícitos de razonamiento en lenguaje natural
("Thought: …") con acciones concretas ("Action: …") y observaciones del
resultado de esa acción ("Observation: …"), en un ciclo que se repite hasta
alcanzar el objetivo. Este patrón es la base de facto de la mayoría de los
frameworks de agentes actuales, incluyendo herramientas específicas de
ciberseguridad como PentestGPT [5].

### 2.2. Arquitecturas multiagente

A partir de 2023 surgió un segundo paradigma: en lugar de un único agente
que resuelve toda la tarea, se orquestan **varios agentes especializados**
que colaboran, cada uno con un rol distinto (por ejemplo, un agente
"planificador", uno "ejecutor" y uno "revisor"), comunicándose entre sí en
lenguaje natural. Este enfoque, formalizado por frameworks como AutoGen
[4], mejora el desempeño en tareas complejas de varios pasos —como las que
son típicas de una prueba de penetración— al permitir división de trabajo,
verificación cruzada entre agentes y especialización de roles.

## 3. Frameworks Generales para Construcción de Agentes

| Framework | Organización / Autor | Paradigma | Relevancia para ciberseguridad |
|---|---|---|---|
| **LangChain** [15] | LangChain Inc. | Cadenas de razonamiento + herramientas (*tool calling*), agentes ReAct | Framework de facto para prototipar agentes con acceso a shells, APIs de escaneo y bases de conocimiento de vulnerabilidades. |
| **AutoGPT** [16] | Significant Gravitas (open source) | Agente autónomo único con bucle de objetivo-planificación-ejecución-reflexión | Uno de los primeros agentes completamente autónomos; referencia histórica para agentes "sin supervisión" aplicados a reconocimiento OSINT. |
| **AutoGen** [4] | Microsoft Research | Multiagente conversacional (roles especializados) | Usado en investigaciones de automatización de pentesting por su capacidad de dividir tareas entre agentes "atacante" y "verificador". |
| **CrewAI** [17] | Comunidad open source | Multiagente orientado a "equipos" (*crews*) con roles y procesos definidos | Facilita modelar un equipo ofensivo (reconocimiento, explotación, reporte) como agentes independientes coordinados. |
| **Semantic Kernel** [18] | Microsoft | Orquestación de *plugins*/herramientas sobre LLM, orientado a integración empresarial | Relevante para integrar agentes de seguridad dentro de flujos SOC/SIEM existentes. |

Estos frameworks no son en sí mismos herramientas de ciberseguridad, pero
constituyen la base tecnológica sobre la cual se han construido los agentes
ofensivos y defensivos descritos en la siguiente sección, y sobre la cual
se apoyará el diseño de los laboratorios prácticos de este trabajo de
grado (actividades 3 a 6).

## 4. Agentes de IA Aplicados a Ciberseguridad Ofensiva

### 4.1. Automatización de pruebas de penetración

**PentestGPT** [5] es, según la literatura revisada, la primera herramienta
que utiliza un LLM como orquestador completo de una prueba de penetración,
dividiendo la tarea en tres módulos —razonamiento, generación de tareas y
ejecución— y manteniendo un árbol de tareas de pentesting que representa el
estado de la prueba en curso. Los autores evalúan la herramienta contra
máquinas de plataformas de entrenamiento como HackTheBox y demuestran que
supera a un uso "ingenuo" de un LLM (sin estructura de agente) en tasa de
resolución de máquinas.

**hackingBuddyGPT** [6], presentado por Happe y Cito, evalúa el uso de LLM
como agentes para escalación de privilegios en máquinas Linux ya
comprometidas, comparando el desempeño de distintos modelos y mostrando que
un LLM guiado por un ciclo de retroalimentación (comando → resultado →
siguiente comando) puede identificar vectores de escalación de privilegios
sin conocimiento previo específico de la máquina objetivo.

### 4.2. Explotación autónoma de vulnerabilidades

Fang et al. demuestran en dos trabajos relacionados que agentes basados en
LLM (usando el patrón ReAct sobre modelos como GPT-4) son capaces de:

- **Explotar vulnerabilidades de un día** (*one-day vulnerabilities*), es
  decir, vulnerabilidades ya conocidas y con CVE publicado, a partir
  únicamente de la descripción de la CVE, sin necesitar el detalle técnico
  del exploit [7]. En su experimento, el agente logró explotar
  exitosamente una proporción significativa de un conjunto de
  vulnerabilidades reales del mundo real, evidenciando que la ventana de
  tiempo entre la publicación de un CVE y su explotación automatizada por
  agentes de IA puede acortarse drásticamente.
- **Hackear sitios web de forma autónoma** [8], incluyendo la detección y
  explotación de vulnerabilidades como inyección SQL y *cross-site
  scripting* (XSS) sin conocimiento previo de la vulnerabilidad específica
  presente en el sitio, únicamente con acceso a un navegador controlado por
  el agente y a las herramientas típicas de un atacante web.

**AutoAttacker** [9] propone una arquitectura multiagente (planificador,
navegador de resultados, generador de resúmenes y ejecutor) guiada por un
LLM para automatizar las fases de post-explotación de un ataque dentro de
un entorno controlado, demostrando capacidad de encadenar múltiples
técnicas sin intervención humana.

### 4.3. Evaluación de riesgo: CyberSecEval

Meta AI publicó **CyberSecEval 2** [10], un conjunto de pruebas (*benchmark*)
diseñado específicamente para medir qué tan susceptibles son los LLM a ser
utilizados como componente central de ciberataques (generación de código
malicioso, explotación asistida, *prompt injection*, entre otros), y qué
tan seguros son al ser usados como asistentes de codificación. Este tipo de
evaluaciones estandarizadas es clave para dimensionar el riesgo real del
uso de agentes de IA en ataques, y para justificar la necesidad de
laboratorios controlados como los que se implementarán en este trabajo de
grado.

## 5. Agentes de IA Aplicados a Ciberseguridad Defensiva

Si bien la literatura académica sobre uso **defensivo** de agentes de IA es
menos extensa que la ofensiva, existen líneas de trabajo consolidadas:

- **Automatización de *blue team* y respuesta a incidentes**: agentes que
  correlacionan alertas de SIEM, generan hipótesis de compromiso y
  proponen o ejecutan acciones de contención, siguiendo el mismo patrón
  ReAct pero orientado a tareas defensivas.
- **Generación asistida de reglas de detección** (p. ej. reglas Sigma o
  YARA) a partir de la descripción de una técnica de ataque, usando el LLM
  para traducir el conocimiento de MITRE ATT&CK [13] a artefactos de
  detección concretos.
- **Simulación de adversarios (*purple teaming*)**: uso de agentes
  ofensivos como los descritos en la sección 4 dentro de entornos
  controlados para generar tráfico y artefactos de ataque realistas, que
  luego alimentan y validan las capacidades de detección del *blue team*.
  Este es, precisamente, el enfoque metodológico que adoptarán los
  laboratorios prácticos de este trabajo de grado.

## 6. Marcos de Riesgo y Gobernanza para Agentes de IA en Seguridad

- **MITRE ATLAS** [11] (*Adversarial Threat Landscape for Artificial
  Intelligence Systems*) extiende la lógica de MITRE ATT&CK [13] a
  tácticas y técnicas específicas de ataques contra y mediante sistemas de
  IA, incluyendo *prompt injection*, envenenamiento de datos de
  entrenamiento y evasión de modelos.
- **OWASP Top 10 for LLM Applications** [12] identifica los diez riesgos
  de seguridad más críticos en aplicaciones que integran LLM, varios de los
  cuales aplican directamente a agentes autónomos (p. ej. *excessive
  agency*, ejecución insegura de *plugins*, y *prompt injection* como
  vector para secuestrar el comportamiento de un agente).

Estos marcos serán utilizados como referencia normativa en el diseño de la
arquitectura de los laboratorios (actividad 3), tanto para estructurar los
escenarios de ataque como para definir controles y límites de seguridad de
los entornos virtualizados.

## 7. Síntesis para el Trabajo de Grado

La revisión evidencia que:

1. Existe una base tecnológica madura (frameworks como LangChain, AutoGen y
   CrewAI) para construir agentes de IA orientados a tareas de
   ciberseguridad sin necesidad de desarrollar infraestructura desde cero.
2. Existe evidencia académica reproducible de que agentes de IA pueden
   ejecutar autónomamente fases completas de un ciberataque
   (reconocimiento, explotación, post-explotación), lo cual justifica
   organizarlas como categorías de análisis (ver
   [ciberataques.md](ciberataques.md)) y como base de los tres laboratorios
   prácticos planteados en el cronograma.
3. Existen marcos de riesgo (MITRE ATLAS, OWASP LLM Top 10) que permiten
   encuadrar el diseño de los laboratorios dentro de una taxonomía
   reconocida por la industria, en lugar de una clasificación ad hoc.
