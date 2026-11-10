"""Registra únicamente el dominio declarado en el reenvío, no el del solicitante."""
import logging
from email.utils import parseaddr
from registro_mysql import conectar
log = logging.getLogger(__name__)

def registrar_dominio_original(uidvalidity, uid, cuerpo, asunto, extraer_reenvio):
    try:
        info = extraer_reenvio(cuerpo, asunto)
        original = (info.get('campos_originales_citados_no_verificados') or {}).get('from', '')
        correo = parseaddr(original)[1].lower()
        dominio = correo.rsplit('@', 1)[-1].rstrip('.') if '@' in correo else None
        if dominio:
            dominio = dominio.encode('idna').decode('ascii')
        if not dominio or len(dominio) > 253 or '.' not in dominio:
            return False
        with conectar() as conn:
            with conn.cursor() as cur:
                cur.execute("""UPDATE correos_analizados
                    SET remitente_original_dominio=%s,
                        remitente_original_fuente='REENVIO_TEXTO_NO_VERIFICADO',
                        remitente_geo_estado='PENDIENTE'
                    WHERE uidvalidity=%s AND uid=%s AND remitente_original_dominio IS NULL""",
                    (dominio, str(uidvalidity), int(uid)))
            conn.commit()
        return True
    except Exception:
        log.exception('GeoIP: error registrando dominio; continúa correo')
        return False
