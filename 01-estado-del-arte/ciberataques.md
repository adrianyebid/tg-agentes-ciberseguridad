# Categorización de Ciberataques Ejecutables con Agentes de IA

## 1. Marco de Referencia

Para categorizar los ciberataques que pueden ser ejecutados —total o
parcialmente— por agentes inteligentes, este trabajo adopta dos marcos de
referencia complementarios, ampliamente reconocidos en la industria:

- El **Cyber Kill Chain** de Lockheed Martin [14], que describe un ataque
  como una secuencia de siete fases (reconocimiento, preparación de armas,
  entrega, explotación, instalación, comando y control, y acciones sobre
  objetivos).
- El framework **MITRE ATT&CK** [13], que detalla tácticas y técnicas
  específicas observadas en ataques reales, organizadas en categorías como
  *Reconnaissance*, *Initial Access*, *Execution*, *Privilege Escalation*,
  *Lateral Movement*, entre otras.

Combinando ambos marcos con las fases explícitamente mencionadas en el
cronograma del proyecto (reconocimiento, escaneo, explotación y movimiento
lateral), se definen cuatro categorías de análisis, cada una mapeada a la
evidencia encontrada en la literatura sobre agentes de IA capaces de
ejecutarlas.

## 2. Categoría 1 — Reconocimiento

**Definición (Kill Chain / ATT&CK):** recolección de información sobre el
objetivo (activos expuestos, tecnologías utilizadas, empleados,
infraestructura de red) previa a cualquier intento de explotación.

**Capacidades demostradas por agentes de IA:**

- Automatización de **OSINT** (*Open Source Intelligence*): un agente con
  acceso a un navegador y a motores de búsqueda puede planificar y ejecutar
  de forma autónoma una secuencia de búsquedas para enumerar subdominios,
  identificar tecnologías web (mediante *fingerprinting* de cabeceras HTTP,
  archivos `robots.txt`, metadatos), y correlacionar información de
  empleados en redes profesionales con fines de posterior ingeniería
  social.
- Herramientas como **PentestGPT** [5] incluyen explícitamente un módulo de
  razonamiento que, en la fase inicial de una prueba, decide qué
  información recolectar y qué herramientas de reconocimiento invocar
  (p. ej. `nmap`, `whatweb`, `gobuster`), interpretando la salida de cada
  herramienta para decidir el siguiente paso sin intervención humana.
- El agente descrito por Fang et al. para hackeo autónomo de sitios web [8]
  comienza cada intento con una fase de reconocimiento del sitio (mapeo de
  formularios, parámetros y rutas) antes de intentar cualquier técnica de
  explotación, demostrando que el patrón "reconocer antes de atacar" emerge
  naturalmente del razonamiento del LLM sin necesidad de codificarlo
  explícitamente como regla.

**Relevancia para el trabajo de grado:** esta categoría corresponde
directamente al **Laboratorio 1 — Reconocimiento automatizado con agentes**
(semanas 7-8), en el cual se diseñará un entorno controlado donde un agente
deberá enumerar de forma autónoma los servicios y tecnologías expuestas por
una máquina víctima.

## 3. Categoría 2 — Escaneo y Enumeración de Vulnerabilidades

**Definición (ATT&CK):** identificación activa de puertos, servicios,
versiones de software y debilidades conocidas (CVE) sobre los activos
descubiertos en la fase de reconocimiento.

**Capacidades demostradas por agentes de IA:**

- Invocación autónoma de escáneres de puertos y de vulnerabilidades
  (p. ej. `nmap` con detección de versiones, `nikto`, escáneres de CVE),
  interpretando su salida en lenguaje natural para decidir qué
  vulnerabilidad priorizar.
- **hackingBuddyGPT** [6] muestra a un LLM enumerando de forma iterativa la
  configuración de un sistema Linux (procesos, permisos de archivos,
  binarios con permisos SUID, tareas *cron*) para identificar
  configuraciones erróneas explotables, un proceso que en pentesting
  manual se conoce como enumeración de post-acceso, pero que aquí se
  automatiza como parte del ciclo de razonamiento del agente.
- El *benchmark* **CyberSecEval 2** [10] incluye pruebas específicas sobre
  la capacidad (y el riesgo) de que un LLM identifique correctamente
  vulnerabilidades explotables a partir de código fuente o de resultados de
  escaneo, lo cual es un indicador cuantitativo de la madurez de los
  agentes en esta fase.

**Relevancia para el trabajo de grado:** corresponde al **Laboratorio 2 —
Escaneo y análisis de vulnerabilidades con agentes** (semanas 9-10), donde
se evaluará la capacidad de un agente para priorizar vulnerabilidades reales
sobre una superficie de ataque previamente identificada.

## 4. Categoría 3 — Explotación

**Definición (Kill Chain / ATT&CK):** aprovechamiento de una vulnerabilidad
identificada para obtener ejecución de código, acceso no autorizado o
control sobre el sistema objetivo.

**Capacidades demostradas por agentes de IA:**

- **Explotación de vulnerabilidades de un día (*one-day exploitation*):**
  Fang et al. [7] demuestran que un agente basado en GPT-4 con arquitectura
  ReAct, al recibir únicamente la descripción textual de una CVE (sin
  detalles del exploit), es capaz de generar y ejecutar de forma autónoma
  el ataque correspondiente contra un conjunto de vulnerabilidades reales,
  con una tasa de éxito significativamente mayor que la de agentes sin
  acceso a la descripción de la CVE. Este resultado es especialmente
  relevante porque reduce la barrera técnica tradicionalmente asociada a la
  explotación de vulnerabilidades conocidas.
- **Explotación web autónoma sin conocimiento previo de la vulnerabilidad:**
  el mismo grupo de investigación [8] extiende el resultado anterior a un
  escenario más realista, donde el agente no conoce de antemano qué
  vulnerabilidad está presente en el sitio web objetivo, debiendo
  descubrirla (inyección SQL, XSS, *path traversal*, entre otras) y
  explotarla en el mismo flujo autónomo.
- **PentestGPT** [5] soporta explícitamente la fase de explotación dentro de
  su ciclo de razonamiento, sugiriendo y en algunos casos ejecutando
  *payloads* o comandos de explotación específicos según el servicio
  identificado en la fase de escaneo.

**Relevancia para el trabajo de grado:** junto con la Categoría 4, esta
categoría fundamenta el **Laboratorio 3 — Explotación y post-explotación
con agentes** (semanas 11-12).

## 5. Categoría 4 — Movimiento Lateral y Post-Explotación

**Definición (ATT&CK, táctica *Lateral Movement* / *Privilege
Escalation*):** una vez obtenido acceso inicial a un sistema, técnicas para
escalar privilegios, mantener persistencia y desplazarse hacia otros
sistemas de la red objetivo.

**Capacidades demostradas por agentes de IA:**

- **Escalación de privilegios:** hackingBuddyGPT [6] se enfoca
  específicamente en esta fase, evaluando la capacidad de distintos LLM
  para identificar, en una máquina Linux ya comprometida, el vector de
  escalación de privilegios correcto (binarios SUID mal configurados,
  tareas programadas ejecutadas por usuarios privilegiados, credenciales
  expuestas en archivos de configuración, entre otros) a partir únicamente
  de la interacción iterativa comando-observación con el sistema.
- **Encadenamiento de técnicas de post-explotación:** AutoAttacker [9]
  propone una arquitectura multiagente específicamente diseñada para
  automatizar la fase de post-explotación completa dentro de un entorno de
  simulación, incluyendo movimiento lateral entre sistemas, demostrando que
  la división de roles entre agentes (planificación, resumen de resultados,
  ejecución) mejora la capacidad de mantener coherencia en tareas largas de
  varios pasos, un requisito típico del movimiento lateral en redes con
  múltiples segmentos.

**Relevancia para el trabajo de grado:** esta categoría complementa el
**Laboratorio 3**, en el que, además de la explotación inicial, se evaluará
la capacidad del agente de mantener y expandir el acceso obtenido dentro de
una red simulada de varios equipos.

## 6. Tabla Resumen de Mapeo

| Categoría | Fase Kill Chain [14] | Táctica ATT&CK [13] | Evidencia principal en literatura | Laboratorio asociado |
|---|---|---|---|---|
| Reconocimiento | Reconnaissance | Reconnaissance | [5], [8] | Lab 1 |
| Escaneo / enumeración | Reconnaissance / Weaponization | Discovery | [6], [10] | Lab 2 |
| Explotación | Exploitation | Initial Access, Execution | [5], [7], [8] | Lab 3 |
| Movimiento lateral / post-explotación | Installation, C2, Actions on Objectives | Privilege Escalation, Lateral Movement | [6], [9] | Lab 3 |

## 7. Consideraciones sobre Uso Dual (*Dual-Use*)

Todas las capacidades descritas en este documento son, por naturaleza,
tecnologías de **doble uso**: las mismas técnicas que permiten a un agente
de IA descubrir y explotar una vulnerabilidad de forma autónoma con fines
de simulación de adversarios (*purple teaming*) o de pentesting autorizado,
podrían ser usadas con fines maliciosos fuera de un entorno controlado. Por
esta razón, y en línea con los marcos de riesgo revisados (MITRE ATLAS
[11], OWASP LLM Top 10 [12]), todos los laboratorios prácticos derivados de
esta categorización se ejecutarán exclusivamente en entornos virtualizados
y aislados, contra activos propios o explícitamente diseñados para
entrenamiento (p. ej. máquinas vulnerables de plataformas como
HackTheBox/VulnHub, o infraestructura desplegada localmente por el autor),
nunca contra sistemas de terceros sin autorización.
