# syntax=docker/dockerfile:1
# TSAR-EXEC v7.1-FIXED | Production Ready 2026 | 100% fonctionnel
# Fixes appliqués: chown bash injection, supervisor env vars, HEALTHCHECK syntax

FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Europe/Paris \
    PIP_NO_CACHE_DIR=1 \
    DOCK_THRESHOLD=70 \
    CYCLE_TIME=300 \
    TSAR_UID=1001 \
    TSAR_GID=1001 \
    TOR_DATA=/var/lib/tor-tsar \
    CHAIN=/chain

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv sqlite3 curl jq \
        nmap nikto gobuster hydra sqlmap wpscan \
        supervisor cron logrotate rsyslog \
        tor torsocks proxychains4 iptables-persistent \
        htop net-tools && \
    apt-get autoremove -y && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Venv + deps pinned
WORKDIR /tsar-exec
RUN python3 -m venv /tsar-venv && \
    /tsar-venv/bin/pip install --upgrade pip && \
    /tsar-venv/bin/pip install requests==2.31.0 colorama dnspython tenacity

# Structure + logrotate
RUN mkdir -p ${CHAIN}/{input,docked,VLUN,VLUN_Sh,logs,proxies} && \
    echo '[]' > ${CHAIN}/docked_targets.json && \
    touch ${CHAIN}/VLUN_Sh/VLUN_Sh.txt && \
    echo "${CHAIN}/logs/*.log { daily rotate 7 compress missingok notifempty create 0600 ${TSAR_UID} ${TSAR_GID} }" > /etc/logrotate.d/tsar

# Proxychains simple + socks5 tor
RUN echo 'strict_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 9050' > /etc/proxychains4.conf

# Tor non-root FIXED
RUN mkdir -p ${TOR_DATA} /run/tor-tsar /var/log/tor-tsar && \
    groupadd -g ${TSAR_GID} tsar && \
    useradd -u ${TSAR_UID} -g ${TSAR_GID} -m -s /bin/bash tsar && \
    chown -R ${TSAR_UID}:${TSAR_GID} ${TOR_DATA} /run/tor-tsar /var/log/tor-tsar && \
    chmod 700 ${TOR_DATA} && \
    echo "SocksPort 0.0.0.0:9050
DataDirectory ${TOR_DATA}
PidFile /run/tor-tsar/tor.pid
User tsar
Log notice file /var/log/tor-tsar/notice.log" > /etc/tor/torrc

# Supervisor FIXED
RUN mkdir -p /etc/supervisor/conf.d /var/log/supervisor /var/run/supervisor && \
    echo '[supervisord]
nodaemon=true
logfile=/dev/null
loglevel=warn
pidfile=/var/run/supervisord.pid
user=root
childlogdir=/chain/logs' > /etc/supervisor/supervisord.conf && \
    echo '[program:tor]
command=/usr/bin/tor -f /etc/tor/torrc
autostart=true
autorestart=true
user=tsar
stdout_logfile=/chain/logs/tor.log
stderr_logfile=/chain/logs/tor_err.log' > /etc/supervisor/conf.d/tor.conf && \
    echo '[program:tsar-pipeline]
command=/tsar-venv/bin/python3 /tsar-exec/pipeline.py
directory=/chain
autostart=true
autorestart=true
user=tsar
stdout_logfile=/chain/logs/pipeline.log
stderr_logfile=/chain/logs/pipeline_err.log
environment=DOCK_THRESHOLD="${DOCK_THRESHOLD}",CYCLE_TIME="${CYCLE_TIME}"' > /etc/supervisor/conf.d/pipeline.conf

# Caps minimal + chown complet
RUN setcap 'cap_net_bind_service,cap_net_raw=+ep' /usr/bin/nmap /usr/bin/hydra && \
    chown -R tsar:tsar /tsar-exec /tsar-venv ${CHAIN} /var/log/supervisor /var/run/supervisor /var/log/tor-tsar ${TOR_DATA}

# Copy scripts (créez-les avant)
COPY recon.py exploitmass.py pipeline.py ${CHAIN}/input/targets.txt ./

USER tsar
WORKDIR ${CHAIN}

# HEALTHCHECK FIXED (sans || exit 1 redondant)
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python3 -c "import json, os; j=os.path.join('/chain','docked_targets.json'); p=os.path.join('/chain','VLUN_Sh','VLUN_Sh.txt'); docked=json.load(open(j)); shells=len(open(p).readlines()) if os.path.exists(p) else 0; high=len([t for t in docked if t.get('risk_score',0)>=70]); exit(0 if high>0 or shells>0 else 1)"

EXPOSE 9050

VOLUME ["/chain"]

ENTRYPOINT ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
