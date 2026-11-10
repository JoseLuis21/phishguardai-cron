"""GeoIP offline para dominios de URLs y remitentes originales citados.
No abre URLs ni descarga contenido; DNS solo para dominios públicos.
"""
import ipaddress
import logging
import os
import socket
from pathlib import Path
from urllib.parse import urlsplit
from dotenv import load_dotenv
from registro_mysql import conectar
import geoip2.database

BASE = Path(__file__).resolve().parent
load_dotenv(BASE / '.env')
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
LOG = logging.getLogger('geoip')
COUNTRY = BASE / os.getenv('GEOIP_COUNTRY_DB', 'GeoLite2-Country.mmdb')
ASN = BASE / os.getenv('GEOIP_ASN_DB', 'GeoLite2-ASN.mmdb')
LIMITE = min(max(int(os.getenv('GEOIP_LOTE', '30')), 1), 100)
socket.setdefaulttimeout(4)

def dominio_valido(valor):
    if not valor or len(valor) > 253:
        return None
    try:
        host = valor.strip().lower().rstrip('.').encode('idna').decode('ascii')
        if not host or '.' not in host or host.endswith(('.local', '.internal', '.localhost')):
            return None
        if any(not x or len(x) > 63 or x.startswith('-') or x.endswith('-') for x in host.split('.')):
            return None
        if not all(x.replace('-', '').isalnum() for x in host.split('.')):
            return None
        try:
            ipaddress.ip_address(host)
            return None
        except ValueError:
            return host
    except (UnicodeError, ValueError):
        return None

def ip_publica(host):
    # DNS no equivale a visitar el sitio. Se descartan IPs privadas/reservadas.
    direcciones = set()
    for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_global:
            direcciones.add(str(ip))
    return sorted(direcciones)[0] if direcciones else None

def geolocalizar(host, pais_reader, asn_reader):
    host = dominio_valido(host)
    if not host:
        return ('OMITIDA', None, None, None, None, None, host)
    ip = ip_publica(host)
    if not ip:
        return ('SIN_IP', None, None, None, None, None, host)
    pais = pais_reader.country(ip).country
    asn = asn_reader.asn(ip)
    return ('COMPLETADO', ip, pais.name, pais.iso_code,
            ('AS' + str(asn.autonomous_system_number)) if asn.autonomous_system_number else None,
            asn.autonomous_system_organization, host)

def actualizar_url(conn, fila, result):
    estado, ip, pais, codigo, asn, proveedor, dominio = result
    with conn.cursor() as cur:
        cur.execute("""UPDATE vt_urls SET geo_dominio=%s,geo_ip=%s,geo_pais=%s,
            geo_pais_codigo=%s,geo_asn=%s,geo_proveedor=%s,geo_estado=%s,
            geo_fecha_consulta=NOW() WHERE id=%s""",
            (dominio,ip,pais,codigo,asn,proveedor,estado,fila['id']))
    conn.commit()

def actualizar_correo(conn, fila, result):
    estado, ip, pais, codigo, asn, proveedor, _ = result
    with conn.cursor() as cur:
        cur.execute("""UPDATE correos_analizados SET remitente_geo_ip=%s,
            remitente_geo_pais=%s,remitente_geo_pais_codigo=%s,
            remitente_geo_asn=%s,remitente_geo_proveedor=%s,
            remitente_geo_estado=%s,remitente_geo_fecha=NOW() WHERE id=%s""",
            (ip,pais,codigo,asn,proveedor,estado,fila['id']))
    conn.commit()

def procesar(conn, tabla, reader_country, reader_asn):
    if tabla == 'vt_urls':
        consulta = "SELECT id,url FROM vt_urls WHERE geo_estado='PENDIENTE' ORDER BY id LIMIT %s"
    else:
        consulta = "SELECT id,remitente_original_dominio FROM correos_analizados WHERE remitente_geo_estado='PENDIENTE' AND remitente_original_dominio IS NOT NULL ORDER BY id LIMIT %s"
    with conn.cursor() as cur:
        cur.execute(consulta, (LIMITE,))
        filas = cur.fetchall()
    for fila in filas:
        try:
            if tabla == 'vt_urls':
                partes = urlsplit(fila['url'])
                host = partes.hostname if partes.scheme.lower() in ('http','https') else None
            else:
                host = fila['remitente_original_dominio']
            resultado = geolocalizar(host, reader_country, reader_asn)
        except Exception as e:
            LOG.warning('GeoIP %s id=%s: %s', tabla, fila['id'], type(e).__name__)
            resultado = ('ERROR', None, None, None, None, None, None)
        if tabla == 'vt_urls':
            actualizar_url(conn, fila, resultado)
        else:
            actualizar_correo(conn, fila, resultado)
        LOG.info('%s id=%s estado=%s pais=%s',tabla,fila['id'],resultado[0],resultado[3])

def main():
    if not COUNTRY.is_file() or not ASN.is_file():
        raise FileNotFoundError('Faltan GeoLite2-Country.mmdb y/o GeoLite2-ASN.mmdb. Ver README.')
    with geoip2.database.Reader(str(COUNTRY)) as c, geoip2.database.Reader(str(ASN)) as a:
        with conectar() as conn:
            procesar(conn, 'vt_urls', c, a)
            procesar(conn, 'correos_analizados', c, a)

if __name__ == '__main__':
    main()
