# Integración del frontend (Next.js)

El código frontend **no está incluido en el ZIP de origen**. Este documento solo describe la interfaz de datos conocida, sin presentar archivos Next.js inventados.

La misma base MariaDB contiene `usuarios`, `acciones_analista` y `tokens_activacion`, además de las cinco tablas de análisis. El frontend debe usar un usuario SQL de privilegios limitados; no debe exponer la clave de conexión ni la clave VirusTotal al navegador.

## Reglas de interpretación

- `correos_analizados.riesgo`: escala orientativa 0–100, no probabilidad calibrada.
- `correos_analizados.attack_tecnica`: mapeo de evidencias, no atribución forense.
- `correos_analizados.auth_spf/auth_dkim/auth_dmarc`: el reenvío normal puede causar `NO_VERIFICADO`.
- `dns_spf_estado`, `dns_dmarc_estado`, `dns_dmarc_politica`: datos de publicación del dominio, no estado de autenticación del mensaje.
- `vt_urls.estado`: no convertir `SIN_REPORTE` ni conteos cero en etiqueta «Seguro».
- `vt_urls.url`: dato sensible/no confiable; no crear vínculos clicables hacia páginas sospechosas; neutralizar en presentación (hxxps / [.]).
- `geo_pais` y ASN: atributos de infraestructura, no geolocalización del actor.

## Pendiente para repositorio full-stack

Proporcionar los archivos reales del frontend Next.js (`package.json`, `pnpm-lock.yaml`, `src/`, `public/`, migraciones si existieran y README). Antes de incluirlos, revisar `.env.local`, tokens, logs, archivos `.next/` y credenciales.
