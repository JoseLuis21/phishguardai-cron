import os
import time
import sys
import subprocess

from pathlib import Path
from dotenv import load_dotenv
from imapclient import IMAPClient

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

IMAP_HOST = os.getenv("IMAP_HOST")
IMAP_PORT = int(os.getenv("IMAP_PORT", "993"))
IMAP_USER = os.getenv("IMAP_USER")
IMAP_PASSWORD = os.getenv("IMAP_PASSWORD")

SCRIPT_CORREO = BASE_DIR / "test_correo.py"


def procesar_correos():
    print("Comprobando correos nuevos...", flush=True)

    resultado = subprocess.run(
        [sys.executable, str(SCRIPT_CORREO)],
        cwd=str(BASE_DIR),
        capture_output=True,
        text=True,
        timeout=120
    )

    if resultado.stdout:
        print(resultado.stdout, flush=True)

    if resultado.stderr:
        print(resultado.stderr, flush=True)

    if resultado.returncode != 0:
        print(
            f"Error procesando correos: {resultado.returncode}",
            flush=True
        )


def escuchar():

    while True:
        try:
            print("Conectando a IMAP...", flush=True)

            with IMAPClient(
                IMAP_HOST,
                port=IMAP_PORT,
                ssl=True,
                timeout=30
            ) as servidor:

                servidor.login(IMAP_USER, IMAP_PASSWORD)
                servidor.select_folder("INBOX", readonly=True)

                print("IMAP IDLE conectado", flush=True)

                # Recuperar correos pendientes tras una desconexión
                procesar_correos()

                while True:

                    servidor.idle()

                    print(
                        "Esperando correos nuevos...",
                        flush=True
                    )

                    eventos = servidor.idle_check(timeout=240)

                    servidor.idle_done()

                    if eventos:
                        print(
                            "Actividad detectada en INBOX",
                            flush=True
                        )
                        procesar_correos()

        except KeyboardInterrupt:
            print("Listener detenido.", flush=True)
            break

        except Exception as error:
            print(
                f"Error de conexión: {type(error).__name__}: {error}",
                flush=True
            )

            print(
                "Reintentando en 10 segundos...",
                flush=True
            )

            time.sleep(10)


if __name__ == "__main__":
    escuchar()