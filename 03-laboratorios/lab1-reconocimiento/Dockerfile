# Imagen del contenedor ATACANTE para el Laboratorio 1.
# Base Debian ligera + herramientas de reconocimiento + Python 3 y el agente.
FROM debian:bookworm-slim

# Evita prompts interactivos durante la instalación de paquetes.
ENV DEBIAN_FRONTEND=noninteractive

# Herramientas de reconocimiento (lista blanca del Lab 1) + runtime de Python.
#   nmap      -> descubrimiento de hosts, puertos y versiones
#   whatweb   -> fingerprinting de tecnologías web
#   gobuster  -> enumeración de rutas/directorios web
#   dirb      -> se instala SOLO por su diccionario (common.txt) para gobuster
#   dnsutils  -> dig, para enumeración DNS si aplica
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        whatweb \
        gobuster \
        dirb \
        dnsutils \
        python3 \
        python3-pip \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /agente

# Instala las dependencias de Python primero (mejor cacheo de capas).
COPY agente/requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Copia el código del agente.
COPY agente/ .

# Por defecto el contenedor queda en espera (ver command en docker-compose.yml);
# el agente se lanza manualmente desde la guía con `docker compose exec`.
CMD ["python3", "agente_recon.py"]
