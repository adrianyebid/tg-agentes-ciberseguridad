#!/usr/bin/env python3
"""
Agente de Reconocimiento Automatizado — Laboratorio 1
======================================================

Agente de IA basado en el patrón ReAct (razonar -> actuar -> observar) que
enumera de forma autónoma los servicios, puertos y tecnologías expuestos por
una máquina víctima, usando herramientas de reconocimiento.

Diseño (ver ../../02-arquitectura-labs/arquitectura-tecnica.md):
  - Núcleo de razonamiento : Messages API de Anthropic (tool use).
  - Herramientas           : lista blanca (nmap, whatweb, gobuster, dig).
  - Capa de contención     : valida herramienta y objetivo antes de ejecutar.
  - Registro               : cada paso del ciclo se escribe en un log JSONL.
  - Supervisor             : límite de iteraciones y timeout por herramienta.

El agente NO ejecuta comandos arbitrarios: solo puede invocar las herramientas
del catálogo y solo contra objetivos de la lista blanca (LAB_OBJETIVOS_PERMITIDOS).

Uso:
    python3 agente_recon.py
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from anthropic import Anthropic

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------
load_dotenv()

MODELO = os.getenv("LAB_MODELO", "claude-haiku-4-5")
MAX_ITERACIONES = int(os.getenv("LAB_MAX_ITERACIONES", "20"))
TIMEOUT_HERRAMIENTA = int(os.getenv("LAB_TIMEOUT_HERRAMIENTA", "180"))
OBJETIVO = os.getenv("LAB_OBJETIVO", "172.28.0.10")
OBJETIVOS_PERMITIDOS = {
    o.strip()
    for o in os.getenv("LAB_OBJETIVOS_PERMITIDOS", OBJETIVO).split(",")
    if o.strip()
}

DIR_OUTPUT = Path(__file__).parent / "output"
DIR_OUTPUT.mkdir(exist_ok=True)
SELLO = datetime.now().strftime("%Y%m%d-%H%M%S")
RUTA_LOG = DIR_OUTPUT / f"recon-{SELLO}.jsonl"
RUTA_INFORME = DIR_OUTPUT / f"informe-{SELLO}.md"

# Diccionario de gobuster (lo trae el paquete dirb en la imagen).
WORDLIST = "/usr/share/dirb/wordlists/common.txt"

# ---------------------------------------------------------------------------
# Definición de herramientas (expuestas al modelo vía tool use)
# ---------------------------------------------------------------------------
HERRAMIENTAS = [
    {
        "name": "nmap",
        "description": (
            "Escanea un objetivo con nmap para descubrir puertos abiertos, "
            "servicios y versiones. Usa opciones como '-sV' (versiones), "
            "'-sC' (scripts por defecto), '-p-' (todos los puertos) o '-T4'."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "objetivo": {
                    "type": "string",
                    "description": "IP o host a escanear (debe estar permitido).",
                },
                "opciones": {
                    "type": "string",
                    "description": "Opciones de nmap, p. ej. '-sV -T4'. Opcional.",
                },
            },
            "required": ["objetivo"],
        },
    },
    {
        "name": "whatweb",
        "description": (
            "Identifica las tecnologías web (servidor, framework, CMS, "
            "lenguajes) de una URL u host mediante fingerprinting."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "objetivo": {
                    "type": "string",
                    "description": "URL u host, p. ej. 'http://172.28.0.10'.",
                }
            },
            "required": ["objetivo"],
        },
    },
    {
        "name": "gobuster",
        "description": (
            "Enumera rutas/directorios de un servidor web por fuerza bruta "
            "usando un diccionario común. Útil para descubrir páginas ocultas."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "objetivo": {
                    "type": "string",
                    "description": "URL base, p. ej. 'http://172.28.0.10'.",
                }
            },
            "required": ["objetivo"],
        },
    },
    {
        "name": "dig",
        "description": (
            "Consulta registros DNS de un dominio (A, MX, TXT, NS, etc.)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "dominio": {"type": "string", "description": "Dominio a consultar."},
                "tipo": {
                    "type": "string",
                    "description": "Tipo de registro (A, MX, TXT, NS...). Opcional.",
                },
            },
            "required": ["dominio"],
        },
    },
]

SYSTEM_PROMPT = f"""Eres un agente de reconocimiento de seguridad ofensiva que \
opera EXCLUSIVAMENTE dentro de un laboratorio virtualizado y aislado, con fines \
educativos y defensivos (hacking ético autorizado).

Tu objetivo: enumerar de la forma más completa posible la superficie expuesta \
por el objetivo autorizado {OBJETIVO}: hosts vivos, puertos abiertos, servicios \
y sus versiones, tecnologías web y rutas interesantes.

Reglas estrictas:
1. Solo puedes actuar contra objetivos autorizados: {', '.join(sorted(OBJETIVOS_PERMITIDOS))}.
   Nunca intentes escanear ninguna otra dirección o dominio.
2. Esta es la fase de RECONOCIMIENTO: NO intentes explotar vulnerabilidades, \
   iniciar sesión, ni modificar el objetivo. Solo recolecta información.
3. Trabaja paso a paso siguiendo el ciclo razonar->actuar->observar. Antes de \
   cada herramienta, explica brevemente POR QUÉ la usas y qué esperas encontrar.
4. Interpreta la salida de cada herramienta y decide el siguiente paso con base \
   en lo que descubres (p. ej. si encuentras un puerto 80 abierto, investiga la \
   web con whatweb y gobuster).
5. Cuando consideres que el reconocimiento está razonablemente completo, redacta \
   un RESUMEN FINAL estructurado con todos los hallazgos (puertos, servicios, \
   versiones, tecnologías, rutas) y termina sin llamar más herramientas.

Sé eficiente: no repitas escaneos idénticos. Tienes un número limitado de pasos."""


# ---------------------------------------------------------------------------
# Capa de contención
# ---------------------------------------------------------------------------
_PATRON_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _host_de(valor: str) -> str:
    """Extrae el host de una URL o 'host:puerto'; devuelve el valor tal cual si ya es un host."""
    valor = valor.strip()
    valor = re.sub(r"^\w+://", "", valor)  # quita esquema http(s)://
    valor = valor.split("/")[0]            # quita ruta
    valor = valor.split(":")[0]            # quita puerto
    return valor


def contencion_ok(nombre: str, args: dict) -> tuple[bool, str]:
    """Valida que la herramienta y el objetivo estén permitidos.

    Devuelve (permitido, motivo). Rechaza si el objetivo no está en la lista
    blanca o si aparece cualquier IP no autorizada en los argumentos.
    """
    campo = "dominio" if nombre == "dig" else "objetivo"
    objetivo = str(args.get(campo, "")).strip()
    if not objetivo:
        return False, f"falta el parámetro '{campo}'"

    host = _host_de(objetivo)
    if host not in OBJETIVOS_PERMITIDOS:
        return False, (
            f"objetivo '{host}' NO está en la lista blanca "
            f"({', '.join(sorted(OBJETIVOS_PERMITIDOS))})"
        )

    # Defensa extra: ninguna IP ajena puede colarse por las 'opciones'.
    opciones = str(args.get("opciones", ""))
    for ip in _PATRON_IP.findall(opciones):
        if ip not in OBJETIVOS_PERMITIDOS:
            return False, f"IP no autorizada en las opciones: '{ip}'"

    return True, "ok"


# ---------------------------------------------------------------------------
# Ejecutor de herramientas
# ---------------------------------------------------------------------------
def construir_comando(nombre: str, args: dict) -> list[str]:
    """Traduce una llamada de herramienta a una lista de argumentos (sin shell)."""
    if nombre == "nmap":
        opciones = shlex.split(str(args.get("opciones", "")))
        return ["nmap", *opciones, args["objetivo"]]
    if nombre == "whatweb":
        return ["whatweb", "--color=never", args["objetivo"]]
    if nombre == "gobuster":
        url = args["objetivo"]
        if not re.match(r"^\w+://", url):
            url = "http://" + url
        return ["gobuster", "dir", "-u", url, "-w", WORDLIST, "-q", "--no-color"]
    if nombre == "dig":
        tipo = str(args.get("tipo", "")).strip()
        cmd = ["dig", "+nocmd", args["dominio"]]
        if tipo:
            cmd.append(tipo)
        return cmd
    raise ValueError(f"herramienta desconocida: {nombre}")


def ejecutar_herramienta(nombre: str, args: dict) -> str:
    """Ejecuta la herramienta y devuelve su salida (truncada si es muy larga)."""
    cmd = construir_comando(nombre, args)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_HERRAMIENTA,
        )
        salida = (proc.stdout or "") + (proc.stderr or "")
        salida = salida.strip() or "(sin salida)"
    except subprocess.TimeoutExpired:
        salida = f"ERROR: la herramienta superó el timeout de {TIMEOUT_HERRAMIENTA}s"
    except FileNotFoundError:
        salida = f"ERROR: la herramienta '{nombre}' no está instalada"
    except Exception as e:  # noqa: BLE001
        salida = f"ERROR al ejecutar: {e}"

    # Evita desbordar el contexto del modelo con salidas enormes.
    MAX = 6000
    if len(salida) > MAX:
        salida = salida[:MAX] + f"\n... [salida truncada, {len(salida)} caracteres]"
    return salida


# ---------------------------------------------------------------------------
# Registro (logging)
# ---------------------------------------------------------------------------
def registrar(evento: dict) -> None:
    evento["ts"] = datetime.now(timezone.utc).isoformat()
    with RUTA_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(evento, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------
# Bucle principal ReAct
# ---------------------------------------------------------------------------
def main() -> int:
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("ERROR: falta ANTHROPIC_API_KEY. Copia .env.example a .env y "
              "rellena tu clave.", file=sys.stderr)
        return 1

    cliente = Anthropic()
    mensajes: list[dict] = [
        {
            "role": "user",
            "content": (
                f"Inicia el reconocimiento autónomo del objetivo {OBJETIVO}. "
                "Descubre todo lo que puedas y termina con un resumen final."
            ),
        }
    ]

    # Métricas acumuladas.
    t0 = time.time()
    tokens_in = tokens_out = 0
    n_pasos = n_tools = n_rechazos = n_errores = 0

    print(f"[*] Objetivo         : {OBJETIVO}")
    print(f"[*] Modelo           : {MODELO}")
    print(f"[*] Máx. iteraciones : {MAX_ITERACIONES}")
    print(f"[*] Log              : {RUTA_LOG}")
    print("-" * 70)
    registrar({"tipo": "inicio", "objetivo": OBJETIVO, "modelo": MODELO})

    resumen_final = ""

    for iteracion in range(1, MAX_ITERACIONES + 1):
        n_pasos += 1
        try:
            resp = cliente.messages.create(
                model=MODELO,
                max_tokens=2048,
                system=SYSTEM_PROMPT,
                tools=HERRAMIENTAS,
                messages=mensajes,
            )
        except Exception as e:  # noqa: BLE001
            print(f"[!] Error llamando a la API: {e}", file=sys.stderr)
            registrar({"tipo": "error_api", "detalle": str(e)})
            return 1

        tokens_in += resp.usage.input_tokens
        tokens_out += resp.usage.output_tokens

        # Texto (razonamiento/observaciones) que produjo el modelo este turno.
        texto = "".join(b.text for b in resp.content if b.type == "text").strip()
        if texto:
            print(f"\n[Paso {iteracion}] 🧠 {texto}")
            resumen_final = texto  # el último texto suele ser el resumen

        registrar({
            "tipo": "turno_modelo",
            "iteracion": iteracion,
            "texto": texto,
            "stop_reason": resp.stop_reason,
            "tokens_in": resp.usage.input_tokens,
            "tokens_out": resp.usage.output_tokens,
        })

        # ¿Terminó? (no pidió herramientas)
        if resp.stop_reason != "tool_use":
            print("\n[✓] El agente finalizó el reconocimiento.")
            break

        # Procesa TODAS las llamadas a herramientas de este turno.
        mensajes.append({"role": "assistant", "content": resp.content})
        resultados: list[dict] = []
        for bloque in resp.content:
            if bloque.type != "tool_use":
                continue
            nombre, args = bloque.name, bloque.input
            permitido, motivo = contencion_ok(nombre, args)

            if not permitido:
                n_rechazos += 1
                salida = f"ACCIÓN RECHAZADA por la capa de contención: {motivo}"
                print(f"   ⛔ {nombre}({args}) -> {motivo}")
            else:
                n_tools += 1
                print(f"   ⚙️  {nombre} {args}")
                salida = ejecutar_herramienta(nombre, args)
                if salida.startswith("ERROR"):
                    n_errores += 1
                print(f"      └─ {salida.splitlines()[0][:100]}"
                      + (" ..." if len(salida) > 100 else ""))

            registrar({
                "tipo": "herramienta",
                "iteracion": iteracion,
                "nombre": nombre,
                "args": args,
                "permitido": permitido,
                "motivo": motivo,
                "salida": salida,
            })
            resultados.append({
                "type": "tool_result",
                "tool_use_id": bloque.id,
                "content": salida,
            })

        mensajes.append({"role": "user", "content": resultados})
    else:
        print("\n[!] Se alcanzó el máximo de iteraciones.")

    # -----------------------------------------------------------------------
    # Métricas finales e informe
    # -----------------------------------------------------------------------
    duracion = time.time() - t0
    # Precios (USD por millón de tokens) de referencia para estimar costo.
    precios = {
        "claude-haiku-4-5": (1.0, 5.0),
        "claude-sonnet-5": (2.0, 10.0),
        "claude-opus-5": (5.0, 25.0),
    }
    p_in, p_out = precios.get(MODELO, (0.0, 0.0))
    costo = tokens_in / 1e6 * p_in + tokens_out / 1e6 * p_out

    metricas = {
        "objetivo": OBJETIVO,
        "modelo": MODELO,
        "duracion_seg": round(duracion, 1),
        "pasos": n_pasos,
        "llamadas_herramienta": n_tools,
        "acciones_rechazadas": n_rechazos,
        "errores_herramienta": n_errores,
        "tokens_entrada": tokens_in,
        "tokens_salida": tokens_out,
        "costo_estimado_usd": round(costo, 4),
    }
    registrar({"tipo": "fin", "metricas": metricas})

    print("\n" + "=" * 70)
    print("MÉTRICAS DE LA CORRIDA")
    print("=" * 70)
    for k, v in metricas.items():
        print(f"  {k:24}: {v}")

    # Informe Markdown para análisis.
    with RUTA_INFORME.open("w", encoding="utf-8") as f:
        f.write(f"# Informe de reconocimiento — {SELLO}\n\n")
        f.write("## Métricas\n\n")
        f.write("| Métrica | Valor |\n|---|---|\n")
        for k, v in metricas.items():
            f.write(f"| {k} | {v} |\n")
        f.write("\n## Resumen final del agente\n\n")
        f.write(resumen_final or "(el agente no produjo un resumen final)")
        f.write(f"\n\n## Log completo\n\nVer `{RUTA_LOG.name}` (formato JSONL).\n")

    print(f"\n[*] Informe guardado en: {RUTA_INFORME}")
    print(f"[*] Log guardado en    : {RUTA_LOG}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
