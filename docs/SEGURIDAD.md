# Seguridad y tratamiento de datos

## Repositorio público

**Nunca subir:** `.env`, contraseñas IMAP/SMTP, API keys de OpenAI/VirusTotal, `correos.db`, datos extraídos de correo, logs, volcados de producción ni bases `.mmdb` de MaxMind. `.gitignore` protege archivos futuros, pero **no elimina secretos del historial de Git**.

El SQL `database/schema.sql` contiene únicamente `CREATE TABLE`/índices/relaciones, **sin registros**.

Si el ZIP original o cualquier secreto se publicó accidentalmente, revocar/rotar credenciales y retirar los objetos de la historia del repositorio.

## Diseño de bajo riesgo

- El correo y sus cabeceras citadas se consideran entrada no confiable.
- El mensaje original reenviado normalmente desde Gmail no tiene necesariamente SPF/DKIM/DMARC comprobables; `NO_VERIFICADO` no es `FAIL`.
- La consulta DNS no prueba autenticidad del mensaje.
- No se navega por las URL sospechosas ni se ejecutan adjuntos; VirusTotal consulta reportes previos.
- Los informes intentan neutralizar URL (`hxxps` / `[.]`) y escapar los textos HTML. Verificar clientes de correo en una prueba integrada.
- La base puede contener correos, indicadores, metadatos personales y URLs con tokens. Limitar privilegios y acceso, definir retención y realizar respaldos cifrados.
- La IA puede cometer errores y recibir instrucciones de prompt injection; los resultados deben ser revisados por analistas para incidentes reales.

## Advertencias operativas

1. **Múltiples envíos:** ante caída tras SMTP y antes del avance UID, existe posibilidad de reenvío del informe; el backend no implementa transacción atómica SMTP/DB.
2. **Dependencias:** las versiones no están fijadas; pin y pruebas de integración antes de desplegar producción.
3. **VirusTotal:** estado `SIN_REPORTE` o 0 detecciones no implica inocuidad. Controlar cuota y política de datos de la API.
4. **DNS/GeoIP:** errores `gaierror` requieren diagnóstico; el país de un CDN no identifica un atacante.
5. **Despliegue:** limitar permisos de `.env` y de `correos.db`, y dejar `passenger_wsgi.py` sin credenciales.

No se realizó una auditoría de penetración ni una validación integral de seguridad en hosting durante esta preparación del repositorio.
