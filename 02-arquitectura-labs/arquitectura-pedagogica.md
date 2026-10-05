# Arquitectura Pedagógica de los Laboratorios

> **Actividad 3 (semanas 5-6), parte pedagógica.** Define los objetivos de
> aprendizaje, la estructura común de las guías de laboratorio, la rúbrica de
> evaluación y la perspectiva defensiva. Complementa la parte técnica
> ([arquitectura-tecnica.md](arquitectura-tecnica.md)) y se apoya en el alcance
> fijado en la Actividad 2
> ([analisis-categorizacion.md](analisis-categorizacion.md)).

## 1. Enfoque Pedagógico

Los laboratorios no buscan solo "lanzar un ataque automatizado", sino que el
estudiante que los realice **comprenda tres cosas**:

1. **La fase del ataque** en sí (qué es reconocer, escanear, explotar) y su
   lugar en los marcos Cyber Kill Chain [14] y MITRE ATT&CK [13].
2. **El rol y los límites del agente de IA**: qué aporta la autonomía, dónde
   falla, cuánto cuesta, y por qué se necesita supervisión humana.
3. **La perspectiva defensiva**: cómo se detecta y mitiga cada técnica,
   cerrando el ciclo ofensivo→defensivo.

El modelo pedagógico es **constructivista y basado en la indagación**: el
estudiante primero ejecuta la fase de forma **manual** (línea base), luego
observa al **agente** hacerla, y finalmente **compara, analiza y reflexiona**
sobre las diferencias. El aprendizaje surge de esa comparación, no de la mera
ejecución.

## 2. Objetivos de Aprendizaje (Taxonomía de Bloom)

Se definen objetivos generales comunes y objetivos específicos por laboratorio,
redactados con verbos de la taxonomía de Bloom revisada (de menor a mayor orden
cognitivo: Recordar, Comprender, Aplicar, Analizar, Evaluar, Crear).

### 2.1. Objetivos Generales (los tres laboratorios)

Al finalizar los laboratorios, el estudiante será capaz de:

- **Comprender** el funcionamiento de un agente de IA basado en LLM (ciclo
  ReAct) aplicado a una fase de un ciberataque. *(Comprender)*
- **Aplicar** herramientas de seguridad ofensiva dentro de un entorno
  virtualizado y aislado, tanto de forma manual como orquestadas por un agente.
  *(Aplicar)*
- **Analizar** el desempeño del agente frente a una línea base manual mediante
  métricas objetivas (cobertura, precisión, tiempo, costo). *(Analizar)*
- **Evaluar** las capacidades, limitaciones y riesgos éticos del uso de agentes
  de IA en ciberataques. *(Evaluar)*
- **Proponer** medidas defensivas de detección y mitigación frente a la técnica
  estudiada. *(Crear)*

### 2.2. Objetivos Específicos por Laboratorio

| Lab | Objetivo específico | Nivel Bloom |
|---|---|---|
| **1 — Reconocimiento** | Configurar un agente ReAct que enumere de forma autónoma hosts, puertos, servicios y tecnologías de una víctima, y comparar su cobertura con un reconocimiento manual. | Aplicar / Analizar |
| **2 — Escaneo** | Evaluar la capacidad del agente para detectar y **priorizar** vulnerabilidades reales, midiendo su precisión (falsos positivos) frente a una línea base conocida. | Analizar / Evaluar |
| **3 — Explotación** | Analizar la capacidad del agente para explotar una vulnerabilidad confirmada y, como extensión, escalar privilegios/moverse lateralmente, valorando el rol de la supervisión humana. | Analizar / Evaluar / Crear |

## 3. Plantilla Común de Guía de Laboratorio

Toda guía de laboratorio en [../03-laboratorios/](../03-laboratorios/) sigue la
misma estructura de ocho secciones, para dar consistencia y comparabilidad:

1. **Contexto y fundamentación.** Qué fase del ataque se estudia, su lugar en
   ATT&CK/Kill Chain, y por qué importa (enlaza al estado del arte y al análisis
   de la Actividad 2).
2. **Objetivos de aprendizaje.** Los específicos del laboratorio (sección 2.2).
3. **Requisitos previos.** Software (Docker, Python, `.env` con API key),
   conocimientos y laboratorios anteriores necesarios.
4. **Montaje del entorno.** Pasos reproducibles para levantar la red y las
   víctimas (`docker compose up`), y verificación de que todo está aislado.
5. **Desarrollo — Parte A (manual, línea base).** El estudiante ejecuta la fase
   a mano y registra los hallazgos. Esto crea la referencia de comparación.
6. **Desarrollo — Parte B (con el agente).** Se ejecuta el agente (varias
   corridas), se observa su ciclo ReAct y se recogen los logs y métricas.
7. **Análisis y preguntas de reflexión.** Comparación agente vs. manual con las
   métricas; preguntas guía (cobertura, errores, costo, límites, ética) y la
   perspectiva defensiva.
8. **Entregables.** Qué debe producir el estudiante (logs, tabla de métricas,
   informe corto de análisis).

## 4. Rúbrica de Evaluación

Rúbrica común para calificar el trabajo del estudiante en cada laboratorio,
sobre 100 puntos. Los niveles de logro son: **Insuficiente (0-59%)**,
**Aceptable (60-79%)**, **Bueno (80-89%)**, **Excelente (90-100%)** del puntaje
del criterio.

| Criterio | Peso | Qué evalúa |
|---|:--:|---|
| **Montaje y reproducibilidad** | 15% | El entorno se levanta correctamente y de forma aislada; se evidencia la verificación. |
| **Ejecución de la línea base manual** | 15% | La fase manual se realiza y documenta correctamente; la línea base es válida. |
| **Ejecución del agente** | 20% | El agente se configura y ejecuta; se recogen logs y se realizan varias corridas. |
| **Análisis con métricas** | 25% | Comparación rigurosa agente vs. manual usando las métricas definidas; interpretación correcta de los resultados. |
| **Reflexión crítica y ética** | 15% | Discusión de capacidades, límites, costo, riesgos y uso dual del agente. |
| **Perspectiva defensiva** | 10% | Propuesta de detección/mitigación pertinente para la técnica estudiada. |

> Esta rúbrica es también el marco con el que el propio trabajo de grado
> **evaluará y documentará** los resultados de cada laboratorio (Actividad 7,
> semanas 13-14).

## 5. Perspectiva Defensiva (ofensivo → defensivo)

Cada laboratorio cierra conectando la técnica ofensiva con su contraparte
defensiva (*blue team*), coherente con el enfoque de doble uso del estado del
arte y con los marcos de riesgo [11][12]:

| Lab | Técnica ofensiva | Detección / mitigación a discutir |
|---|---|---|
| **1 — Reconocimiento** | Escaneo de puertos y *fingerprinting*. | Detección de escaneos en IDS (p. ej. patrones de Snort/Suricata), *rate limiting*, reducción de superficie expuesta, *banners* ofuscados. |
| **2 — Escaneo** | Escaneo de vulnerabilidades. | Correlación de logs, alertas por tráfico de escáneres conocidos, gestión de parches, segmentación. |
| **3 — Explotación** | Explotación y escalación. | Detección de explotación (WAF, EDR), principio de mínimo privilegio, *hardening*, monitoreo de integridad, respuesta a incidentes. |

Además, al ser los atacantes **agentes de IA**, se introduce una reflexión
transversal sobre defensa específica frente a ataques automatizados por IA:
mayor velocidad y escala del adversario, y la necesidad de defensas igualmente
automatizadas.

## 6. Trazabilidad Objetivos ↔ Laboratorios ↔ Marcos

Para evidenciar la coherencia del diseño, cada laboratorio queda trazado a los
objetivos específicos del trabajo de grado y a los marcos de referencia:

| Lab | Objetivo específico del TG (CLAUDE.md) | Categoría (Actividad 2) | Marco ATT&CK |
|---|---|---|---|
| 1 | Obj. 2 (reconocimiento) + Obj. 4 (implementar labs) | Reconocimiento | Reconnaissance |
| 2 | Obj. 2 (escaneo) + Obj. 4 + Obj. 5 (evaluar) | Escaneo/enumeración | Discovery |
| 3 | Obj. 2 (explotación, mov. lateral) + Obj. 4 + Obj. 5 | Explotación + Post-explotación | Initial Access, Execution, Privilege Escalation, Lateral Movement |

Con la arquitectura técnica y pedagógica definidas, el siguiente paso del
cronograma es la **implementación del Laboratorio 1** (semanas 7-8) en
[../03-laboratorios/lab1-reconocimiento/](../03-laboratorios/lab1-reconocimiento/),
que será la primera materialización concreta de todo este diseño.
