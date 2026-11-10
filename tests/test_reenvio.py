import unittest
from evidencia_reenvio import analizar_reenvio

class TestEvidenciaReenvio(unittest.TestCase):
    def test_extrae_campos_sin_afirmar_autenticidad(self):
        cuerpo = ("Mensaje recibido\n\n---------- Forwarded message ---------\n"
                  "From: Soporte <soporte@ejemplo.com>\n"
                  "Date: lunes\nSubject: Aviso de seguridad\n"
                  "Authentication-Results: spf=pass\n")
        info = analizar_reenvio(cuerpo, "Fwd: Aviso")
        self.assertEqual(info['dominio'], 'ejemplo.com')
        self.assertTrue(info['auth_citada'])
        self.assertEqual(info['metodo'], 'CUERPO_REENVIADO_NO_CONFIABLE')
        self.assertEqual(info['tipo'], 'REENVIO_CON_AUTH_CITADA')

    def test_sin_marcador_no_trata_cabecera_como_original(self):
        info = analizar_reenvio('From: soporte@ejemplo.com\nmensaje cualquiera', 'saludos')
        self.assertIsNone(info['dominio'])
        self.assertEqual(info['metodo'], 'NINGUNO')

if __name__ == '__main__':
    unittest.main()
