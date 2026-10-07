#!/usr/bin/env python3
"""
Analizador de métricas — Laboratorio 1
=======================================

Lee todos los logs `output/*.jsonl` producidos por el agente y genera una
tabla Markdown con las métricas de cada corrida y las MEDIAS por modelo,
lista para pegar en `resultados.md`.

No gasta API: solo procesa los archivos locales.

Uso (desde la carpeta del laboratorio):
    python3 analizar_metricas.py
    # o apuntando a otra carpeta de logs:
    python3 analizar_metricas.py --dir output
"""

from __future__ import annotations

import argparse
import glob
import json
import os
from collections import defaultdict
from statistics import mean, pstdev

# Columnas numéricas que se promedian.
CAMPOS = [
    ("pasos", "Pasos"),
    ("llamadas_herramienta", "Llam. herram."),
    ("acciones_rechazadas", "Rechazos"),
    ("errores_herramienta", "Errores"),
    ("tokens_entrada", "Tokens in"),
    ("tokens_salida", "Tokens out"),
    ("costo_estimado_usd", "Costo USD"),
    ("duracion_seg", "Tiempo (s)"),
]


def cargar_corridas(carpeta: str) -> list[dict]:
    """Extrae el bloque de métricas (evento 'fin') de cada archivo .jsonl."""
    corridas = []
    for ruta in sorted(glob.glob(os.path.join(carpeta, "*.jsonl"))):
        metricas = None
        with open(ruta, encoding="utf-8") as f:
            for linea in f:
                try:
                    ev = json.loads(linea)
                except json.JSONDecodeError:
                    continue
                if ev.get("tipo") == "fin" and "metricas" in ev:
                    metricas = ev["metricas"]
        if metricas:
            metricas["_archivo"] = os.path.basename(ruta)
            corridas.append(metricas)
        else:
            print(f"[!] Sin evento 'fin' (¿corrida incompleta?): {ruta}")
    return corridas


def fmt(valor) -> str:
    if isinstance(valor, float):
        return f"{valor:.4f}" if valor < 1 else f"{valor:.1f}"
    return str(valor)


def tabla_markdown(corridas: list[dict]) -> str:
    if not corridas:
        return "_No se encontraron corridas completas en la carpeta._"

    encabezados = ["#", "Modelo"] + [t for _, t in CAMPOS]
    filas = ["| " + " | ".join(encabezados) + " |",
             "|" + "|".join(["---"] * len(encabezados)) + "|"]

    # Agrupa por modelo, conservando el orden de aparición.
    por_modelo: dict[str, list[dict]] = defaultdict(list)
    for c in corridas:
        por_modelo[c.get("modelo", "¿?")].append(c)

    n = 0
    for modelo, grupo in por_modelo.items():
        for c in grupo:
            n += 1
            fila = [str(n), modelo] + [fmt(c.get(k, "")) for k, _ in CAMPOS]
            filas.append("| " + " | ".join(fila) + " |")
        # Fila de medias del modelo.
        medias = []
        for k, _ in CAMPOS:
            vals = [c[k] for c in grupo if isinstance(c.get(k), (int, float))]
            medias.append(f"{mean(vals):.4f}" if vals and mean(vals) < 1
                          else (f"{mean(vals):.1f}" if vals else "—"))
        filas.append("| — | **Media " + modelo + "** | "
                     + " | ".join(f"**{m}**" for m in medias) + " |")

    return "\n".join(filas)


def resumen(corridas: list[dict]) -> str:
    por_modelo: dict[str, list[dict]] = defaultdict(list)
    for c in corridas:
        por_modelo[c.get("modelo", "¿?")].append(c)
    lineas = ["", "## Resumen por modelo", ""]
    for modelo, grupo in por_modelo.items():
        costos = [c["costo_estimado_usd"] for c in grupo]
        tiempos = [c["duracion_seg"] for c in grupo]
        lineas.append(
            f"- **{modelo}** — {len(grupo)} corrida(s). "
            f"Costo medio ${mean(costos):.4f} (total ${sum(costos):.4f}). "
            f"Tiempo medio {mean(tiempos):.1f}s"
            + (f" (±{pstdev(tiempos):.1f}s)." if len(tiempos) > 1 else ".")
        )
    return "\n".join(lineas)


def main() -> int:
    ap = argparse.ArgumentParser(description="Analiza las métricas del Lab 1.")
    ap.add_argument("--dir", default="output", help="Carpeta con los *.jsonl")
    args = ap.parse_args()

    corridas = cargar_corridas(args.dir)
    print(f"[*] Corridas completas encontradas: {len(corridas)}\n")
    print(tabla_markdown(corridas))
    print(resumen(corridas))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
