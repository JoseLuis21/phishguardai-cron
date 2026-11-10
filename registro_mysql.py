"""Registro opcional de métricas en MySQL para test_correo.py V4.
No requiere Flask ni dashboard. Nunca almacena el cuerpo del correo ni URLs.
"""
import logging
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / '.env')
logger = logging.getLogger(__name__)


def conectar():
    import pymysql
    from pymysql.cursors import DictCursor
    return pymysql.connect(
        host=os.getenv('MYSQL_HOST', 'localhost'),
        port=int(os.getenv('MYSQL_PORT', '3306')),
        user=os.environ['MYSQL_USER'],
        password=os.environ['MYSQL_PASSWORD'],
        database=os.environ['MYSQL_DATABASE'],
        charset='utf8mb4',
        cursorclass=DictCursor,
        autocommit=False,
        connect_timeout=5,
        read_timeout=10,
        write_timeout=10,
    )


def registrar_analisis(uidvalidity, uid, solicitante, asunto, resultado):
    try:
        with conectar() as conn:
            with conn.cursor() as cur:
                cur.execute('''INSERT INTO correos_analizados
                    (uidvalidity, uid, solicitante_email, asunto, clasificacion, riesgo,
                     resumen, recomendacion, tokens_entrada, tokens_salida,
                     attack_tecnica, attack_evidencia)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id),
                    attack_tecnica=COALESCE(attack_tecnica, VALUES(attack_tecnica)),
                    attack_evidencia=COALESCE(attack_evidencia, VALUES(attack_evidencia))''', (
                    str(uidvalidity), int(uid), str(solicitante).lower()[:254], str(asunto)[:500],
                    str(resultado['clasificacion'])[:40], int(resultado['riesgo']),
                    str(resultado.get('resumen', ''))[:5000],
                    str(resultado.get('recomendacion', ''))[:5000],
                    int(resultado.get('tokens_entrada', 0)),
                    int(resultado.get('tokens_salida', 0)),
                    resultado.get('attack_tecnica'),
                    (resultado.get('attack_evidencia') or '')[:500] or None
                ))
                correo_id = cur.lastrowid
                cur.execute('SELECT COUNT(*) AS n FROM indicadores_phishing WHERE correo_id=%s', (correo_id,))
                if cur.fetchone()['n'] == 0:
                    for indicador in resultado.get('indicadores', [])[:8]:
                        cur.execute('INSERT INTO indicadores_phishing (correo_id, descripcion) VALUES (%s,%s)',
                                    (correo_id, str(indicador)[:1000]))
                cur.execute('SELECT COUNT(*) AS n FROM eventos_sistema WHERE correo_id=%s AND tipo=%s',
                            (correo_id, 'ANALISIS_FINALIZADO'))
                if cur.fetchone()['n'] == 0:
                    cur.execute('INSERT INTO eventos_sistema (correo_id, actor_email, tipo, detalle) VALUES (%s,%s,%s,%s)',
                                (correo_id, str(solicitante).lower()[:254], 'ANALISIS_FINALIZADO',
                                 f"{resultado['clasificacion']} ({resultado['riesgo']}/100)"))
                    if resultado['clasificacion'] == 'PHISHING':
                        cur.execute('INSERT INTO eventos_sistema (correo_id, actor_email, tipo, detalle) VALUES (%s,%s,%s,%s)',
                                    (correo_id, str(solicitante).lower()[:254], 'PHISHING_DETECTADO',
                                     f"Riesgo {resultado['riesgo']}/100"))
                    if int(resultado['riesgo']) >= 90:
                        cur.execute('INSERT INTO eventos_sistema (correo_id, actor_email, tipo, detalle) VALUES (%s,%s,%s,%s)',
                                    (correo_id, str(solicitante).lower()[:254], 'AMENAZA_CRITICA',
                                     f"Riesgo {resultado['riesgo']}/100"))
            conn.commit()
        return True
    except Exception:
        logger.exception('Error registrando análisis MySQL; continúa IMAP/SMTP')
        return False


def registrar_envio(uidvalidity, uid):
    try:
        with conectar() as conn:
            with conn.cursor() as cur:
                cur.execute('''UPDATE correos_analizados
                               SET estado_envio='ENVIADO', fecha_envio=COALESCE(fecha_envio,NOW())
                               WHERE uidvalidity=%s AND uid=%s''', (str(uidvalidity), int(uid)))
                cur.execute('SELECT id, solicitante_email FROM correos_analizados WHERE uidvalidity=%s AND uid=%s',
                            (str(uidvalidity), int(uid)))
                fila = cur.fetchone()
                if fila:
                    cur.execute('SELECT COUNT(*) AS n FROM eventos_sistema WHERE correo_id=%s AND tipo=%s',
                                (fila['id'], 'INFORME_ENVIADO'))
                    if cur.fetchone()['n'] == 0:
                        cur.execute('INSERT INTO eventos_sistema (correo_id, actor_email, tipo) VALUES (%s,%s,%s)',
                                    (fila['id'], fila['solicitante_email'], 'INFORME_ENVIADO'))
            conn.commit()
        return True
    except Exception:
        logger.exception('Error registrando envío MySQL; continúa IMAP/SMTP')
        return False
