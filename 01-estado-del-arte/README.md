# 01 — Estado del Arte

## Objetivo de la Actividad

Realizar la revisión bibliográfica y del estado del arte sobre el uso de
agentes inteligentes (en particular, agentes basados en modelos de lenguaje
de gran escala, LLM) en el ámbito de la ciberseguridad, cubriendo tanto
frameworks y herramientas disponibles, como casos de uso documentados en la
literatura y en la industria, desde una perspectiva ofensiva (uso en
ciberataques) y defensiva (uso en detección, respuesta y hacking ético).

Corresponde a las semanas 1-2 del cronograma del trabajo de grado.

## Metodología de Revisión

La revisión se realizó combinando:

- **Literatura científica**: artículos publicados en arXiv, y en
  conferencias/journals reconocidos en el área (ICLR, ACM ESEC/FSE, entre
  otros), relacionados con agentes autónomos basados en LLM y su aplicación
  a pruebas de penetración, explotación de vulnerabilidades y evaluación de
  riesgos de seguridad en sistemas de IA.
- **Documentación técnica de la industria**: publicaciones y marcos de
  referencia de organizaciones como MITRE (ATT&CK, ATLAS), OWASP (Top 10
  para aplicaciones LLM) y laboratorios de investigación de empresas de IA
  (p. ej. Meta AI con CyberSecEval).
- **Repositorios y frameworks open source**: herramientas activamente
  mantenidas que implementan agentes de IA orientados a tareas de
  ciberseguridad (ofensivas y defensivas), evaluando su arquitectura,
  alcance y limitaciones.

Los criterios de inclusión priorizaron fuentes de 2022 en adelante, dado que
el uso de LLM como núcleo de razonamiento de agentes autónomos es un
fenómeno reciente, coincidente con la publicación de arquitecturas como
ReAct (2022) y la posterior proliferación de frameworks multiagente
(2023-2024).

## Contenido de la Carpeta

| Archivo | Contenido |
|---|---|
| [agentes-ia.md](agentes-ia.md) | Fundamentos de agentes inteligentes basados en LLM: arquitecturas, componentes, frameworks (LangChain, AutoGPT, AutoGen, CrewAI, Semantic Kernel) y herramientas específicas de ciberseguridad ofensiva y defensiva basadas en agentes. |
| [ciberataques.md](ciberataques.md) | Categorización de ciberataques que pueden ser ejecutados —total o parcialmente— por agentes de IA, organizada según las fases del *Cyber Kill Chain* y el framework MITRE ATT&CK: reconocimiento, escaneo/enumeración, explotación, post-explotación y movimiento lateral. Incluye evidencia documentada en la literatura para cada fase. |
| [referencias.md](referencias.md) | Listado consolidado de referencias bibliográficas en formato IEEE, citadas a lo largo de los documentos de esta carpeta. |

## Principales Hallazgos (Resumen)

1. Los agentes basados en LLM han pasado de ser asistentes conversacionales
   a sistemas capaces de **planificar y ejecutar de forma autónoma
   secuencias de acciones** (razonamiento + uso de herramientas + memoria),
   gracias a arquitecturas como ReAct y a frameworks multiagente como
   AutoGen y CrewAI.
2. Existe evidencia académica reciente (2023-2024) de que estos agentes son
   capaces de **automatizar pruebas de penetración completas** (PentestGPT,
   hackingBuddyGPT), **explotar vulnerabilidades conocidas de un día**
   (*one-day exploitation*) a partir únicamente de su CVE, y en algunos
   casos **descubrir y explotar vulnerabilidades web de forma autónoma**.
3. Persisten limitaciones importantes: dependencia de la calidad del
   *prompting* y del contexto proporcionado, dificultad para tareas de
   explotación complejas de varios pasos, y necesidad de supervisión humana
   ("human-in-the-loop") para escenarios de alto riesgo.
4. Organismos como MITRE y OWASP ya han comenzado a formalizar taxonomías de
   riesgo específicas para sistemas de IA (MITRE ATLAS, OWASP Top 10 for
   LLM Applications), lo cual valida la pertinencia y actualidad de este
   trabajo de grado.
5. El uso defensivo de agentes (automatización de *blue team*, respuesta a
   incidentes, generación de reglas de detección) es un área igualmente
   activa, aunque menos madura en literatura académica que el uso
   ofensivo.

Estos hallazgos fundamentan directamente el diseño de los tres laboratorios
prácticos planteados en el cronograma (reconocimiento, escaneo de
vulnerabilidades, y explotación/post-explotación), que se abordarán en las
actividades siguientes.
