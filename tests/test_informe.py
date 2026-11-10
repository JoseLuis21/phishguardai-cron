import unittest
from unittest.mock import patch
from email.message import EmailMessage
# En este test no se ejecutan llamadas a IA; se permite un stub mínimo
# para comprobar el renderizado aun si la dependencia no está instalada aquí.
import sys
import types
try:
    from openai import OpenAI
except ImportError:
    stub = types.ModuleType('openai')
    stub.OpenAI = object
    sys.modules['openai'] = stub
from test_correo import desactivar_urls_informe, enviar_respuesta

class TestInformeSeguro(unittest.TestCase):
    def test_desactiva_dominio_y_protocolo(self):
        self.assertEqual(desactivar_urls_informe('https://login.ejemplo.com/ruta'),
                         'hxxps://login[.]ejemplo[.]com/ruta')
        self.assertEqual(desactivar_urls_informe('http://ejemplo.org'),
                         'hxxp://ejemplo[.]org')

    def test_construye_mensaje_sin_links_en_cuerpo_html(self):
        resultado = {'clasificacion':'SOSPECHOSO', 'riesgo':65,
                     'resumen':'Revisar https://fraude.ejemplo.com',
                     'indicadores':['enlace: www.ejemplo.com'],
                     'recomendacion':'No acceder a https://fraude.ejemplo.com'}
        original = EmailMessage()
        original['Message-ID'] = '<prueba@ejemplo.com>'
        with patch('test_correo.SMTP_USER', 'analisis@ejemplo.com'), \
             patch('test_correo.SMTP_PASSWORD', 'password-falsa'), \
             patch('test_correo.SMTP_HOST', 'smtp.ejemplo.com'), \
             patch('test_correo.SMTP_PORT', 465), \
             patch('test_correo.smtplib.SMTP_SSL') as mock_smtp:
            enviar_respuesta('usuario@ejemplo.com', 'Oferta en https://ejemplo.com', original, resultado)
            mail = mock_smtp.return_value.__enter__.return_value.send_message.call_args.args[0]
        html = mail.get_body(preferencelist=('html',)).get_content()
        plano = mail.get_body(preferencelist=('plain',)).get_content()
        self.assertNotIn('https://fraude.ejemplo.com', html)
        self.assertNotIn('<a ', html.lower())
        self.assertIn('hxxps://fraude[.]ejemplo[.]com', html)
        self.assertIn('hxxps://fraude[.]ejemplo[.]com', plano)

if __name__ == '__main__':
    unittest.main()
