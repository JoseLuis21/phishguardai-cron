def application(environ, start_response):

    status = "200 OK"

    headers = [
        ("Content-Type", "text/plain; charset=utf-8")
    ]

    start_response(status, headers)

    mensaje = "Sistema de analisis de phishing iniciado correctamente"

    return [mensaje.encode("utf-8")]