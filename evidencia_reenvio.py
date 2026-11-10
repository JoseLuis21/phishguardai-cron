"""Indicadores NO CONFIABLES citados en un reenvío Gmail tradicional.

Nunca afirma PASS/FAIL de autenticación: no hay acceso a buzón de origen.
"""
import re
from email.utils import parseaddr

MARCADORES = re.compile(
    r'(?im)^\s*(?:-{2,}\s*(?:forwarded message|mensaje reenviado|mensaje original)\s*-{2,}|'
    r'begin forwarded message:|inicio del mensaje reenviado:)',
)
CAMPOS = {
    'from': re.compile(r'(?im)^\s*(?:From|De)\s*:\s*(.{1,300})$'),
    'date': re.compile(r'(?im)^\s*(?:Date|Fecha|Sent|Enviado)\s*:\s*(.{1,300})$'),
    'subject': re.compile(r'(?im)^\s*(?:Subject|Asunto)\s*:\s*(.{1,300})$'),
}
AUTH = re.compile(r'(?im)^\s*(?:Authentication-Results|ARC-Authentication-Results)\s*:\s*(.{1,500})$')


def analizar_reenvio(cuerpo, asunto):
    """Solo indicadores citados; un atacante puede falsificar el texto reenviado."""
    cuerpo = (cuerpo or '')[:12000]
    # Sin marcador, no interpretar cualquier línea From: como cabecera original.
    marcador = MARCADORES.search(cuerpo)
    if not marcador:
        return {'tipo': 'REENVIO_SIN_CABECERAS', 'dominio': None,
                'campos': [], 'auth_citada': False, 'metodo': 'NINGUNO'}
    segmento = cuerpo[marcador.end():marcador.end() + 3500]
    campos = [k for k, patron in CAMPOS.items() if patron.search(segmento)]
    from_citado = CAMPOS['from'].search(segmento)
    direccion = parseaddr(from_citado.group(1))[1].lower() if from_citado else ''
    dominio = direccion.rsplit('@', 1)[-1].rstrip('.') if '@' in direccion else None
    try:
        dominio = dominio.encode('idna').decode('ascii') if dominio else None
    except UnicodeError:
        dominio = None
    if dominio and (len(dominio) > 253 or '.' not in dominio or not re.fullmatch(r'[a-z0-9.-]+', dominio)):
        dominio = None
    # NO guardamos texto completo de las cabeceras; solo constancia de presencia.
    auth_citada = bool(AUTH.search(segmento))
    tipo = 'REENVIO_CON_AUTH_CITADA' if auth_citada else ('REENVIO_CABECERAS_BASICAS' if campos else 'REENVIO_SIN_CABECERAS')
    return {'tipo': tipo, 'dominio': dominio, 'campos': campos,
            'auth_citada': auth_citada, 'metodo': 'CUERPO_REENVIADO_NO_CONFIABLE'}
