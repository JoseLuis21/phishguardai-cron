"""Consulta SOLO reportes ya existentes en VirusTotal (no envía URLs para escaneo)."""
import base64
import json
import os
import time
from datetime import datetime
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from dotenv import load_dotenv
from registro_mysql import conectar

load_dotenv(Path(__file__).resolve().parent / '.env')
API_KEY = os.getenv('VT_API_KEY', '')
API = 'https://www.virustotal.com/api/v3/urls/'

def procesar_una():
    with conectar() as conn:
        with conn.cursor() as cur:
            # Sin worker concurrente: cron usa flock. Recuperar trabajos abandonados.
            cur.execute("UPDATE vt_urls SET estado='PENDIENTE' WHERE estado='PROCESANDO' AND fecha_actualizacion < NOW()-INTERVAL 10 MINUTE")
            cur.execute("""SELECT id,url,intentos FROM vt_urls WHERE estado IN ('PENDIENTE','ERROR')
                           AND (proximo_intento IS NULL OR proximo_intento<=NOW())
                           ORDER BY fecha_creacion,id LIMIT 1 FOR UPDATE""")
            fila = cur.fetchone()
            if not fila:
                conn.commit()
                return False
            cur.execute("UPDATE vt_urls SET estado='PROCESANDO', intentos=intentos+1 WHERE id=%s", (fila['id'],))
        conn.commit()
    url_id = base64.urlsafe_b64encode(fila['url'].encode('utf-8')).decode('ascii').rstrip('=')
    req = Request(API+url_id, headers={'x-apikey': API_KEY, 'Accept': 'application/json'}, method='GET')
    estado, estadisticas, payload, retraso = 'ERROR', None, None, 60
    try:
        with urlopen(req, timeout=18) as resp:
            obj = json.load(resp)
        attrs = obj.get('data',{}).get('attributes',{})
        estadisticas = attrs.get('last_analysis_stats') or {}
        payload = json.dumps({'last_analysis_stats':estadisticas, 'last_analysis_date':attrs.get('last_analysis_date'), 'reputation':attrs.get('reputation')}, ensure_ascii=False)
        estado = 'COMPLETADO'
    except HTTPError as exc:
        if exc.code == 404:
            estado, retraso = 'SIN_REPORTE', 0
        elif exc.code == 429:
            retraso = 3600
        elif exc.code in (401,403):
            raise RuntimeError('VirusTotal rechazó la API key o sus permisos') from exc
        else:
            retraso = min(3600, 60 * (2 ** min(fila['intentos'],5)))
    except (URLError,TimeoutError,ValueError):
        retraso = min(3600, 60 * (2 ** min(fila['intentos'],5)))
    with conectar() as conn:
        with conn.cursor() as cur:
            cur.execute("""UPDATE vt_urls SET estado=%s,vt_id=%s,malicious=%s,suspicious=%s,harmless=%s,undetected=%s,
                           respuesta_json=%s,fecha_consulta=NOW(),proximo_intento=IF(%s='ERROR',DATE_ADD(NOW(),INTERVAL %s SECOND),NULL)
                           WHERE id=%s""", (estado,url_id, (estadisticas or {}).get('malicious'),(estadisticas or {}).get('suspicious'),
                           (estadisticas or {}).get('harmless'),(estadisticas or {}).get('undetected'),payload,estado,retraso,fila['id']))
        conn.commit()
    print(f"URL id={fila['id']}: {estado}",flush=True)
    return True

if __name__ == '__main__':
    if not API_KEY:
        raise SystemExit('Configura VT_API_KEY en .env')
    # 3 peticiones por ejecución como máximo, separadas 20s; cron cada minuto.
    for i in range(3):
        if i:
            time.sleep(20)
        if not procesar_una():
            break
