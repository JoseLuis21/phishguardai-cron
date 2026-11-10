"""Almacenamiento de URLs sin bloquear el analizador; no realiza solicitudes externas."""
import hashlib
import ipaddress
import logging
from urllib.parse import urlsplit
from registro_mysql import conectar

log = logging.getLogger(__name__)

def url_admitida(url):
    if not isinstance(url, str) or len(url) > 4096 or len(url) < 10:
        return False
    try:
        p = urlsplit(url.strip())
        if p.scheme.lower() not in ('http', 'https') or not p.hostname or p.username or p.password:
            return False
        host = p.hostname.lower().rstrip('.')
        if host in ('localhost',) or host.endswith(('.local', '.internal')):
            return False
        try:
            ipaddress.ip_address(host)
            return False
        except ValueError:
            return '.' in host
    except ValueError:
        return False

def encolar_urls(uidvalidity, uid, urls):
    try:
        with conectar() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT id FROM correos_analizados WHERE uidvalidity=%s AND uid=%s', (str(uidvalidity), int(uid)))
                fila = cur.fetchone()
                if not fila:
                    return False
                for url in list(dict.fromkeys(urls or []))[:30]:
                    if not url_admitida(url):
                        continue
                    url = url.strip()
                    digest = hashlib.sha256(url.encode('utf-8')).hexdigest()
                    cur.execute('INSERT INTO vt_urls (url_sha256,url) VALUES (%s,%s) ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id)', (digest,url))
                    cur.execute('INSERT IGNORE INTO correo_urls (correo_id,vt_url_id) VALUES (%s,%s)', (fila['id'],cur.lastrowid))
            conn.commit()
        return True
    except Exception:
        log.exception('No se pudieron encolar URLs; análisis y envío continúan')
        return False
