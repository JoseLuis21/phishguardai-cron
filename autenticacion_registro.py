"""V9: evidencia del reenvío normal sin aseverar autenticación original.

No interpretes resultados Authentication-Results citados como resultados confiables.
"""
import logging
from registro_mysql import conectar
from evidencia_reenvio import analizar_reenvio

log = logging.getLogger(__name__)


def registrar_autenticacion(uidvalidity, uid, mensaje, cuerpo='', asunto=''):
    evidencia = analizar_reenvio(cuerpo, asunto)
    nota = ('Reenvío tradicional: autenticación SPF/DKIM/DMARC del mensaje original '
            'NO_VERIFICADO. Las cabeceras citadas en el cuerpo pueden ser falsificadas. '
            'Las consultas DNS del dominio NO autentican este mensaje.')
    try:
        with conectar() as conn:
            with conn.cursor() as cur:
                cur.execute('''UPDATE correos_analizados SET
                    auth_spf='NO_VERIFICADO', auth_dkim='NO_VERIFICADO',
                    auth_dmarc='NO_VERIFICADO', auth_fuente='REENVIO_NO_VERIFICADO',
                    auth_confiable=0, auth_nota=%s, auth_fecha=NOW(),
                    auth_original_tipo=%s, auth_original_dominio_citado=%s,
                    auth_original_campos_citados=%s,
                    auth_original_auth_citada=%s,
                    auth_original_fuente=%s
                    WHERE uidvalidity=%s AND uid=%s''',
                    (nota, evidencia['tipo'], evidencia['dominio'],
                     ','.join(evidencia['campos']) or None,
                     int(evidencia['auth_citada']), evidencia['metodo'],
                     str(uidvalidity), int(uid)))
            conn.commit()
        return True
    except Exception:
        log.exception('Error registrando evidencia de reenvío; continúa SMTP')
        return False
