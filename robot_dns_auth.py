"""Consulta SPF y DMARC publicados en DNS del dominio citado del remitente.

NO autentica correos individuales ni permite inferir PASS/FAIL del original.
DKIM no se puede verificar por DNS sin selector y firma del mensaje original.
"""
import logging
import re
import ipaddress
import dns.resolver
import dns.exception
from registro_mysql import conectar

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('robot_dns_auth')

resolver = dns.resolver.Resolver(configure=True)
resolver.timeout = 3
resolver.lifetime = 5


def validar_dominio(valor):
    try:
        dominio = str(valor or '').strip().lower().rstrip('.').encode('idna').decode('ascii')
        if len(dominio) > 253 or '.' not in dominio:
            return None
        if not re.fullmatch(r'[a-z0-9.-]+', dominio):
            return None
        partes = dominio.split('.')
        if any(not p or len(p) > 63 or p.startswith('-') or p.endswith('-') for p in partes):
            return None
        try:
            ipaddress.ip_address(dominio)
            return None
        except ValueError:
            return dominio
    except (UnicodeError, ValueError):
        return None


def txt(nombre):
    try:
        respuestas = resolver.resolve(nombre, 'TXT', search=False)
        return [''.join(p.decode('utf-8', 'replace') for p in r.strings) for r in respuestas]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []


def consultar(dominio):
    # Una consulta SPF y una DMARC. No resolver IP ni visitar URLs.
    try:
        spf = [v for v in txt(dominio) if v.lower().startswith('v=spf1')]
        if len(spf) == 1:
            spf_estado, spf_registro = 'PUBLICADO', spf[0][:2000]
        elif len(spf) > 1:
            spf_estado, spf_registro = 'MULTIPLES', None
        else:
            spf_estado, spf_registro = 'AUSENTE', None
    except (dns.exception.DNSException, OSError) as e:
        log.warning('SPF DNS falló para %s: %s', dominio, type(e).__name__)
        spf_estado, spf_registro = 'ERROR', None
    try:
        dmarc = [v for v in txt('_dmarc.' + dominio) if v.lower().startswith('v=dmarc1')]
        if len(dmarc) == 1:
            registro = dmarc[0][:2000]
            match = re.search(r'(?:^|;)\s*p\s*=\s*(none|quarantine|reject)\s*(?:;|$)', registro, re.I)
            dmarc_estado = 'PUBLICADO' if match else 'INVALIDO'
            politica = match.group(1).lower() if match else None
            dmarc_registro = registro
        elif len(dmarc) > 1:
            dmarc_estado, politica, dmarc_registro = 'MULTIPLES', None, None
        else:
            dmarc_estado, politica, dmarc_registro = 'AUSENTE', None, None
    except (dns.exception.DNSException, OSError) as e:
        log.warning('DMARC DNS falló para %s: %s', dominio, type(e).__name__)
        dmarc_estado, politica, dmarc_registro = 'ERROR', None, None
    return spf_estado, spf_registro, dmarc_estado, politica, dmarc_registro


def ejecutar():
    # Hasta 20 registros por cron; la consulta DNS es independiente de VirusTotal.
    with conectar() as conn:
        with conn.cursor() as cur:
            cur.execute('''SELECT id, remitente_original_dominio AS dominio
                FROM correos_analizados
                WHERE remitente_original_dominio IS NOT NULL
                  AND (dns_spf_estado='PENDIENTE' OR dns_dmarc_estado='PENDIENTE')
                ORDER BY id LIMIT 20''')
            pendientes = cur.fetchall()
        for fila in pendientes:
            dominio = validar_dominio(fila['dominio'])
            if dominio:
                spf_estado, spf_reg, dmarc_estado, politica, dmarc_reg = consultar(dominio)
            else:
                spf_estado, spf_reg, dmarc_estado, politica, dmarc_reg = ('INVALIDO', None, 'INVALIDO', None, None)
            with conn.cursor() as cur:
                cur.execute('''UPDATE correos_analizados SET
                    dns_spf_estado=%s, dns_spf_registro=%s,
                    dns_dmarc_estado=%s, dns_dmarc_politica=%s,
                    dns_dmarc_registro=%s, dns_fecha_consulta=NOW()
                    WHERE id=%s''', (spf_estado, spf_reg, dmarc_estado, politica, dmarc_reg, fila['id']))
            conn.commit()
            log.info('Correo id=%s SPF=%s DMARC=%s', fila['id'], spf_estado, dmarc_estado)

if __name__ == '__main__':
    ejecutar()
