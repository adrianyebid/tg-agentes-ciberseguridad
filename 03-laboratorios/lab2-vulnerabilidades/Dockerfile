# Imagen del contenedor ATACANTE para el Laboratorio 2.
# Base Debian ligera + herramientas de análisis de vulnerabilidades + el agente.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# nikto está en la sección non-free de Debian: se habilita solo para instalarlo.
#   nmap     -> escaneo de servicios y scripts de detección de vulnerabilidades
#   whatweb  -> fingerprinting de tecnologías web
#   nikto    -> escáner de vulnerabilidades web
RUN sed -i 's/Components: main/Components: main contrib non-free/' \
        /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        whatweb \
        nikto \
        git \
        python3 \
        python3-pip \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# searchsploit (Exploit-DB): se instala SOLO el buscador y sus índices CSV.
# Se eliminan a propósito los códigos de exploit y shellcodes: este laboratorio
# correlaciona servicio -> CVE, NO explota (la explotación es el Lab 3).
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
    && rm -rf /opt/exploitdb/.git /opt/exploitdb/exploits /opt/exploitdb/shellcodes \
              /opt/exploitdb/ghdb.xml \
    && ln -s /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

WORKDIR /agente

COPY agente/requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY agente/ .

CMD ["python3", "agente_vuln.py"]
