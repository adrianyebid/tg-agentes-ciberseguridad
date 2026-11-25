#!/usr/bin/env python3
"""
Verificador de CVE — Laboratorio 2
==================================

Ayuda a medir la PRECISIÓN del agente. Para cada corrida (output/vulnscan-*.jsonl):
  - extrae las CVE citadas en el resumen final,
  - comprueba si cada una aparece literalmente en la salida de las herramientas
    que el agente ejecutó en ESA corrida (evidencia propia),
  - indica si mencionó las dos entradas de searchsploit que sí aplican a
    Apache 2.4.25 (CVE-2019-0211 y Optionsbleed/CVE-2017-9798) y si nombró
    alguna de las "trampas" (resultados de searchsploit que no aplican).

OJO al interpretar "sin evidencia literal": searchsploit muestra TÍTULOS, no
números de CVE. Si el agente traduce un título a su CVE correcta (p. ej.
"OPTIONS Memory Leak" -> CVE-2017-9798) es un acierto con evidencia indirecta.
Revisa manualmente cada caso antes de clasificarlo como falso positivo.

Uso (desde la carpeta del laboratorio):
    python3 verificar_cves.py            # o: python3 verificar_cves.py --dir output
"""

import argparse
import glob
import json
import os
import re

CVE = re.compile(r"CVE-\d{4}-\d{4,7}")
TRAMPAS = ("tomcat", "openfuck", "cxf", "openmeetings", "xerces", "webfroot")


def main() -> int:
    ap = argparse.ArgumentParser(description="Verifica las CVE citadas por el agente.")
    ap.add_argument("--dir", default="output", help="Carpeta con los vulnscan-*.jsonl")
    args = ap.parse_args()

    for log in sorted(glob.glob(os.path.join(args.dir, "vulnscan-*.jsonl"))):
        salidas, resumen, modelo = "", "", "?"
        with open(log, encoding="utf-8") as f:
            for linea in f:
                e = json.loads(linea)
                if e.get("tipo") == "herramienta":
                    salidas += e.get("salida", "") + "\n"
                elif e.get("tipo") == "turno_modelo" and e.get("texto"):
                    resumen = e["texto"]
                elif e.get("tipo") == "inicio":
                    modelo = e.get("modelo", "?")
        if not resumen:
            continue
        citadas = sorted(set(CVE.findall(resumen)))
        evidencia = set(CVE.findall(salidas))
        sin_literal = [c for c in citadas if c not in evidencia]
        r = resumen.lower()
        cve_0211 = any(k in r for k in ("2019-0211", "apache2ctl", "graceful"))
        optionsbleed = any(k in r for k in ("2017-9798", "optionsbleed", "options memory"))
        trampas = [t for t in TRAMPAS if t in r]
        print(f"{os.path.basename(log)} | {modelo}")
        print(f"   CVE citadas: {len(citadas)} | sin evidencia literal: {sin_literal or 'ninguna'}")
        print(f"   CVE-2019-0211: {'sí' if cve_0211 else 'no'} | Optionsbleed: {'sí' if optionsbleed else 'no'}"
              f" | trampas nombradas: {trampas or 'ninguna'} (revisa si las acepta o las descarta)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
