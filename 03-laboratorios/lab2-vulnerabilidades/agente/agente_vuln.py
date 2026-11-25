#!/usr/bin/env python3
"""
Agente de Análisis de Vulnerabilidades — Laboratorio 2 (multi-modelo)
=====================================================================

Agente de IA basado en el patrón ReAct (razonar -> actuar -> observar) que,
sobre la superficie expuesta por una máquina víctima, **detecta, correlaciona
con CVE y prioriza vulnerabilidades**, justificando cada hallazgo con evidencia.

Reutiliza la arquitectura del Lab 1 (ciclo ReAct, capa de contención, registro,
métricas y soporte multi-modelo Ollama/Anthropic). Cambia respecto al Lab 1:
  - Herramientas de análisis de vulnerabilidades: nmap (scripts vuln), whatweb,
    nikto (escáner web) y searchsploit (correlación servicio/versión -> CVE).
  - Misión enfocada en PRECISIÓN: el agente debe justificar cada vulnerabilidad
    con evidencia de las herramientas, para poder medir falsos positivos.

Esta es la fase de ANÁLISIS: NO explota las vulnerabilidades (eso es el Lab 3).
El agente solo puede invocar herramientas de la lista blanca y solo contra
objetivos de la lista blanca (LAB_OBJETIVOS_PERMITIDOS).

Uso:
    python3 agente_vuln.py
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

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------
load_dotenv()

PROVEEDOR = os.getenv("LAB_PROVEEDOR", "ollama").lower().strip()
_MODELOS_DEFECTO = {"ollama": "qwen2.5:3b", "anthropic": "claude-haiku-4-5"}
MODELO = os.getenv("LAB_MODELO") or _MODELOS_DEFECTO.get(PROVEEDOR, "qwen2.5:3b")
OLLAMA_URL = os.getenv("LAB_OLLAMA_URL", "http://ollama:11434/v1")

MAX_ITERACIONES = int(os.getenv("LAB_MAX_ITERACIONES", "25"))
TIMEOUT_HERRAMIENTA = int(os.getenv("LAB_TIMEOUT_HERRAMIENTA", "300"))
OBJETIVO = os.getenv("LAB_OBJETIVO", "172.29.0.10")
OBJETIVOS_PERMITIDOS = {
    o.strip()
    for o in os.getenv("LAB_OBJETIVOS_PERMITIDOS", OBJETIVO).split(",")
    if o.strip()
}

DIR_OUTPUT = Path(__file__).parent / "output"
DIR_OUTPUT.mkdir(exist_ok=True)
SELLO = datetime.now().strftime("%Y%m%d-%H%M%S")
RUTA_LOG = DIR_OUTPUT / f"vulnscan-{SELLO}.jsonl"
RUTA_INFORME = DIR_OUTPUT / f"informe-{SELLO}.md"

# ---------------------------------------------------------------------------
# Catálogo canónico de herramientas (independiente del proveedor)
# ---------------------------------------------------------------------------
HERRAMIENTAS_BASE = [
    {
        "name": "nmap",
        "description": (
            "Escanea un objetivo con nmap. Para análisis de vulnerabilidades usa "
            "'-sV' (versiones) y '--script vuln' (scripts de detección de "
            "vulnerabilidades conocidas). Ej. de opciones: '-sV --script vuln'."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "objetivo": {"type": "string", "description": "IP o host a escanear (debe estar permitido)."},
                "opciones": {"type": "string", "description": "Opciones de nmap, p. ej. '-sV --script vuln'."},
            },
            "required": ["objetivo"],
        },
    },
    {
        "name": "whatweb",
        "description": "Identifica tecnologías web (servidor, versión, framework, CMS) de una URL u host.",
        "schema": {
            "type": "object",
            "properties": {
                "objetivo": {"type": "string", "description": "URL u host, p. ej. 'http://172.29.0.10'."},
            },
            "required": ["objetivo"],
        },
    },
    {
        "name": "nikto",
        "description": (
            "Escáner de vulnerabilidades web: busca archivos/configuraciones "
            "peligrosas, versiones obsoletas y problemas conocidos en un servidor web."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "objetivo": {"type": "string", "description": "URL u host del servidor web, p. ej. 'http://172.29.0.10'."},
            },
            "required": ["objetivo"],
        },
    },
    {
        "name": "searchsploit",
        "description": (
            "Busca en la base de datos de Exploit-DB vulnerabilidades y CVE "
            "conocidas asociadas a un software y versión. NO explota nada: solo "
            "correlaciona. Ej. de consulta: 'apache 2.4.25' o 'php 7.0'."
        ),
        "schema": {
            "type": "object",
            "properties": {
                "consulta": {"type": "string", "description": "Software y versión a buscar, p. ej. 'apache 2.4.25'."},
            },
            "required": ["consulta"],
        },
    },
]


def tools_anthropic() -> list[dict]:
    return [
        {"name": h["name"], "description": h["description"], "input_schema": h["schema"]}
        for h in HERRAMIENTAS_BASE
    ]


def tools_openai() -> list[dict]:
    return [
        {"type": "function", "function": {"name": h["name"], "description": h["description"], "parameters": h["schema"]}}
        for h in HERRAMIENTAS_BASE
    ]


SYSTEM_PROMPT = f"""Eres un agente de análisis de vulnerabilidades de seguridad \
que opera EXCLUSIVAMENTE dentro de un laboratorio virtualizado y aislado, con \
fines educativos y defensivos (hacking ético autorizado).

Tu objetivo: sobre el host autorizado {OBJETIVO}, DETECTAR vulnerabilidades, \
CORRELACIONARLAS con CVE/exploits conocidos y PRIORIZARLAS por gravedad.

Reglas estrictas:
1. Solo puedes actuar contra objetivos autorizados: {', '.join(sorted(OBJETIVOS_PERMITIDOS))}.
2. Esta es la fase de ANÁLISIS: NO intentes EXPLOTAR las vulnerabilidades, ni \
   iniciar sesión, ni modificar el objetivo. Solo detectar y clasificar.
3. Trabaja paso a paso (razonar->actuar->observar). Flujo sugerido: identifica \
   servicios y versiones (nmap -sV), busca vulnerabilidades web (nikto) y de red \
   (nmap --script vuln), y correlaciona cada servicio/versión con CVE conocidas \
   usando searchsploit (p. ej. 'apache 2.4.25').
4. REGLA CLAVE DE RIGOR: cada vulnerabilidad o CVE que reportes DEBE estar \
   respaldada por EVIDENCIA concreta de la salida de una herramienta. NO afirmes \
   que algo es vulnerable si no lo observaste. Si no estás seguro, dilo \
   explícitamente en vez de inventar. Es preferible omitir una vulnerabilidad \
   dudosa que reportar una falsa.
5. Cuando termines, redacta un RESUMEN FINAL con una lista priorizada de \
   vulnerabilidades. Para CADA UNA indica: (a) nombre/descripción, (b) la \
   EVIDENCIA que la respalda (qué herramienta y qué mostró), (c) CVE si aplica, \
   y (d) severidad estimada (Crítica/Alta/Media/Baja). Termina sin llamar más \
   herramientas.

Sé eficiente: no repitas escaneos idénticos. Tienes un número limitado de pasos."""


# ---------------------------------------------------------------------------
# Capa de contención
# ---------------------------------------------------------------------------
_PATRON_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _host_de(valor: str) -> str:
    valor = valor.strip()
    valor = re.sub(r"^\w+://", "", valor)
    valor = valor.split("/")[0]
    valor = valor.split(":")[0]
    return valor


def contencion_ok(nombre: str, args: dict) -> tuple[bool, str]:
    """Valida que la herramienta y el objetivo estén permitidos.

    searchsploit es una consulta LOCAL a la base de Exploit-DB (no toca la red
    ni el objetivo), por lo que se permite sin validar IP.
    """
    if nombre == "searchsploit":
        if not str(args.get("consulta", "")).strip():
            return False, "falta el parámetro 'consulta'"
        return True, "ok"

    objetivo = str(args.get("objetivo", "")).strip()
    if not objetivo:
        return False, "falta el parámetro 'objetivo'"

    host = _host_de(objetivo)
    if host not in OBJETIVOS_PERMITIDOS:
        return False, (
            f"objetivo '{host}' NO está en la lista blanca "
            f"({', '.join(sorted(OBJETIVOS_PERMITIDOS))})"
        )

    opciones = str(args.get("opciones", ""))
    for ip in _PATRON_IP.findall(opciones):
        if ip not in OBJETIVOS_PERMITIDOS:
            return False, f"IP no autorizada en las opciones: '{ip}'"

    return True, "ok"


# ---------------------------------------------------------------------------
# Ejecutor de herramientas
# ---------------------------------------------------------------------------
def construir_comando(nombre: str, args: dict) -> list[str]:
    if nombre == "nmap":
        opciones = shlex.split(str(args.get("opciones", "")))
        return ["nmap", *opciones, args["objetivo"]]
    if nombre == "whatweb":
        return ["whatweb", "--color=never", args["objetivo"]]
    if nombre == "nikto":
        url = args["objetivo"]
        if not re.match(r"^\w+://", url):
            url = "http://" + url
        # -maxtime acota la duración; -ask no evita prompts de actualización.
        return ["nikto", "-h", url, "-maxtime", f"{max(TIMEOUT_HERRAMIENTA - 30, 60)}s", "-ask", "no"]
    if nombre == "searchsploit":
        # Solo búsqueda (correlación); los términos se pasan como argumentos.
        return ["searchsploit", *shlex.split(str(args["consulta"]))]
    raise ValueError(f"herramienta desconocida: {nombre}")


def ejecutar_herramienta(nombre: str, args: dict) -> str:
    try:
        cmd = construir_comando(nombre, args)
    except (ValueError, KeyError) as e:
        return f"ERROR: argumentos inválidos para la herramienta: {e}"
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_HERRAMIENTA)
        salida = (proc.stdout or "") + (proc.stderr or "")
        salida = salida.strip() or "(sin salida)"
    except subprocess.TimeoutExpired:
        salida = f"ERROR: la herramienta superó el timeout de {TIMEOUT_HERRAMIENTA}s"
    except FileNotFoundError:
        salida = f"ERROR: la herramienta '{nombre}' no está instalada"
    except Exception as e:  # noqa: BLE001
        salida = f"ERROR al ejecutar: {e}"

    MAX = 8000
    if len(salida) > MAX:
        salida = salida[:MAX] + f"\n... [salida truncada, {len(salida)} caracteres]"
    return salida


# ---------------------------------------------------------------------------
# Registro
# ---------------------------------------------------------------------------
def registrar(evento: dict) -> None:
    evento["ts"] = datetime.now(timezone.utc).isoformat()
    with RUTA_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(evento, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------
# Capa de abstracción del modelo
# ---------------------------------------------------------------------------
def crear_cliente():
    if PROVEEDOR == "anthropic":
        from anthropic import Anthropic
        return Anthropic()
    from openai import OpenAI
    return OpenAI(base_url=OLLAMA_URL, api_key=os.getenv("LAB_OLLAMA_API_KEY", "ollama"))


def mensajes_iniciales() -> list[dict]:
    peticion = (
        f"Analiza las vulnerabilidades del objetivo {OBJETIVO}. Detecta, "
        "correlaciona con CVE y prioriza, con evidencia. Termina con un resumen final."
    )
    if PROVEEDOR == "anthropic":
        return [{"role": "user", "content": peticion}]
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": peticion},
    ]


def llamar_modelo(cliente, mensajes: list[dict]) -> dict:
    if PROVEEDOR == "anthropic":
        resp = cliente.messages.create(
            model=MODELO, max_tokens=2048, system=SYSTEM_PROMPT,
            tools=tools_anthropic(), messages=mensajes,
        )
        texto = "".join(b.text for b in resp.content if b.type == "text").strip()
        tcs = [{"id": b.id, "nombre": b.name, "args": b.input}
               for b in resp.content if b.type == "tool_use"]
        return {
            "texto": texto, "tool_calls": tcs, "termino": resp.stop_reason != "tool_use",
            "tokens_in": resp.usage.input_tokens, "tokens_out": resp.usage.output_tokens,
            "raw": resp,
        }

    resp = cliente.chat.completions.create(
        model=MODELO, messages=mensajes, tools=tools_openai(), max_tokens=2048,
    )
    msg = resp.choices[0].message
    texto = (msg.content or "").strip()
    tcs = []
    for tc in (msg.tool_calls or []):
        try:
            args = json.loads(tc.function.arguments or "{}")
        except json.JSONDecodeError:
            args = {}
        tcs.append({"id": tc.id, "nombre": tc.function.name, "args": args})
    u = resp.usage
    return {
        "texto": texto, "tool_calls": tcs, "termino": not tcs,
        "tokens_in": getattr(u, "prompt_tokens", 0) if u else 0,
        "tokens_out": getattr(u, "completion_tokens", 0) if u else 0,
        "raw": msg,
    }


def append_asistente(mensajes: list[dict], res: dict) -> None:
    if PROVEEDOR == "anthropic":
        mensajes.append({"role": "assistant", "content": res["raw"].content})
    else:
        mensajes.append(res["raw"].model_dump(exclude_none=True))


def append_resultados(mensajes: list[dict], resultados: list[tuple[str, str]]) -> None:
    if PROVEEDOR == "anthropic":
        bloques = [{"type": "tool_result", "tool_use_id": tid, "content": salida}
                   for tid, salida in resultados]
        mensajes.append({"role": "user", "content": bloques})
    else:
        for tid, salida in resultados:
            mensajes.append({"role": "tool", "tool_call_id": tid, "content": salida})


# ---------------------------------------------------------------------------
# Bucle principal ReAct
# ---------------------------------------------------------------------------
def main() -> int:
    if PROVEEDOR == "anthropic" and not os.getenv("ANTHROPIC_API_KEY"):
        print("ERROR: con LAB_PROVEEDOR=anthropic falta ANTHROPIC_API_KEY en .env.", file=sys.stderr)
        return 1
    if PROVEEDOR not in ("ollama", "anthropic"):
        print(f"ERROR: LAB_PROVEEDOR='{PROVEEDOR}' no soportado (usa 'ollama' o 'anthropic').", file=sys.stderr)
        return 1

    try:
        cliente = crear_cliente()
    except ImportError as e:
        print(f"ERROR: falta instalar la librería del proveedor: {e}", file=sys.stderr)
        return 1

    mensajes = mensajes_iniciales()

    t0 = time.time()
    tokens_in = tokens_out = 0
    n_pasos = n_tools = n_rechazos = n_errores = 0

    print(f"[*] Proveedor        : {PROVEEDOR}")
    print(f"[*] Modelo           : {MODELO}")
    print(f"[*] Objetivo         : {OBJETIVO}")
    print(f"[*] Máx. iteraciones : {MAX_ITERACIONES}")
    print(f"[*] Log              : {RUTA_LOG}")
    print("-" * 70)
    registrar({"tipo": "inicio", "proveedor": PROVEEDOR, "objetivo": OBJETIVO, "modelo": MODELO})

    resumen_final = ""

    for iteracion in range(1, MAX_ITERACIONES + 1):
        n_pasos += 1
        try:
            res = llamar_modelo(cliente, mensajes)
        except Exception as e:  # noqa: BLE001
            print(f"[!] Error llamando al modelo: {e}", file=sys.stderr)
            registrar({"tipo": "error_api", "detalle": str(e)})
            return 1

        tokens_in += res["tokens_in"]
        tokens_out += res["tokens_out"]

        if res["texto"]:
            print(f"\n[Paso {iteracion}] 🧠 {res['texto']}")
            resumen_final = res["texto"]

        registrar({
            "tipo": "turno_modelo", "iteracion": iteracion, "texto": res["texto"],
            "termino": res["termino"], "tokens_in": res["tokens_in"], "tokens_out": res["tokens_out"],
        })

        if res["termino"]:
            print("\n[✓] El agente finalizó el análisis de vulnerabilidades.")
            break

        append_asistente(mensajes, res)

        resultados: list[tuple[str, str]] = []
        for tc in res["tool_calls"]:
            nombre, args = tc["nombre"], tc["args"]
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
                primera = salida.splitlines()[0] if salida.splitlines() else ""
                print(f"      └─ {primera[:100]}" + (" ..." if len(salida) > 100 else ""))

            registrar({
                "tipo": "herramienta", "iteracion": iteracion, "nombre": nombre,
                "args": args, "permitido": permitido, "motivo": motivo, "salida": salida,
            })
            resultados.append((tc["id"], salida))

        append_resultados(mensajes, resultados)
    else:
        print("\n[!] Se alcanzó el máximo de iteraciones.")

    # -----------------------------------------------------------------------
    # Métricas finales e informe
    # -----------------------------------------------------------------------
    duracion = time.time() - t0
    precios = {
        "claude-haiku-4-5": (1.0, 5.0),
        "claude-sonnet-5": (2.0, 10.0),
        "claude-opus-5": (5.0, 25.0),
    }
    if PROVEEDOR == "ollama":
        p_in, p_out = 0.0, 0.0
    else:
        p_in, p_out = precios.get(MODELO, (0.0, 0.0))
    costo = tokens_in / 1e6 * p_in + tokens_out / 1e6 * p_out

    metricas = {
        "proveedor": PROVEEDOR,
        "modelo": MODELO,
        "objetivo": OBJETIVO,
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

    with RUTA_INFORME.open("w", encoding="utf-8") as f:
        f.write(f"# Informe de análisis de vulnerabilidades — {SELLO}\n\n")
        f.write("## Métricas\n\n| Métrica | Valor |\n|---|---|\n")
        for k, v in metricas.items():
            f.write(f"| {k} | {v} |\n")
        f.write("\n## Resumen final del agente (vulnerabilidades priorizadas)\n\n")
        f.write(resumen_final or "(el agente no produjo un resumen final)")
        f.write(f"\n\n## Log completo\n\nVer `{RUTA_LOG.name}` (formato JSONL).\n")

    print(f"\n[*] Informe guardado en: {RUTA_INFORME}")
    print(f"[*] Log guardado en    : {RUTA_LOG}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
