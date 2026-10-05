import contextlib
import io
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml
from werkzeug.security import check_password_hash

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import reporte_auditoria as audit
from servicio import app


class SecurityRegressions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.reports = Path(self.temp.name) / 'reportes'
        self.reports.mkdir()
        self.report = self.reports / 'report-2026.html'
        self.report.write_text('<p>Report</p>', encoding='utf-8')
        reports_patch = patch.object(audit, 'RUTA_REPORTES', self.reports)
        reports_patch.start()
        self.addCleanup(reports_patch.stop)
        self.db = Path(self.temp.name) / 'reports.db'
        with sqlite3.connect(self.db) as connection:
            connection.execute('CREATE TABLE reportes (id INTEGER, cliente TEXT, monto REAL)')
            connection.executemany('INSERT INTO reportes VALUES (?, ?, ?)', [
                (1, "o'brien_ltd", 100), (2, 'another_client', 200)
            ])

    def test_apostrophe_is_a_literal_client_name(self):
        rows = audit.buscar_reportes_cliente("o'brien_ltd", str(self.db))
        self.assertEqual([row[0] for row in rows], [1])

    def test_sql_input_cannot_return_other_clients(self):
        self.assertEqual(audit.buscar_reportes_cliente("' OR 1=1 --", str(self.db)), [])

    def test_pdf_conversion_does_not_invoke_a_shell(self):
        with patch.object(audit.subprocess, 'run') as runner:
            self.assertEqual(audit.convertir_a_pdf('report-2026.html'), 'report-2026.html.pdf')
            args, kwargs = runner.call_args
            self.assertEqual(args[0], ['wkhtmltopdf', str(self.report), str(self.report) + '.pdf'])
            self.assertFalse(kwargs.get('shell', False))
            self.assertTrue(kwargs['check'])

    def test_unsafe_filenames_never_reach_converter(self):
        with patch.object(audit.subprocess, 'run') as runner:
            for filename in ['../private.html', '/etc/passwd', '-option.html', 'a.html;id', '$(id).html', '', 'https://example.com/a.html', '0' * 3000 + '.html']:
                with self.subTest(filename=filename), self.assertRaises(ValueError):
                    audit.convertir_a_pdf(filename)
            runner.assert_not_called()

    def test_missing_report_never_reaches_converter(self):
        with patch.object(audit.subprocess, 'run') as runner, self.assertRaises(ValueError):
            audit.convertir_a_pdf('missing.html')
        runner.assert_not_called()

    def test_symlink_cannot_escape_report_directory(self):
        outside = Path(self.temp.name) / 'private.html'
        outside.write_text('private', encoding='utf-8')
        (self.reports / 'linked.html').symlink_to(outside)
        with patch.object(audit.subprocess, 'run') as runner, self.assertRaises(ValueError):
            audit.convertir_a_pdf('linked.html')
        runner.assert_not_called()

    def test_homepage_and_report_endpoint(self):
        client = app.test_client()
        self.assertEqual(client.get('/').status_code, 200)
        with patch('servicio.buscar_reportes_cliente', return_value=[(1, 'client', 100)]):
            response = client.get('/reportes', query_string={'cliente': 'client'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['total_registros'], 1)

    def test_yaml_rejects_python_object_tags(self):
        config = Path(self.temp.name) / 'config.yaml'
        config.write_text('!!python/tuple [1, 2]', encoding='utf-8')
        with self.assertRaises(yaml.constructor.ConstructorError):
            audit.cargar_configuracion(config)

    def test_password_hash_has_random_salt_and_checks_password(self):
        first = audit.hash_password_legacy('test password')
        second = audit.hash_password_legacy('test password')
        self.assertNotEqual(first, second)
        self.assertTrue(check_password_hash(first, 'test password'))
        self.assertFalse(check_password_hash(first, 'wrong password'))

    def test_notification_does_not_print_credential_fragments(self):
        output = io.StringIO()
        with patch.object(audit, 'NOTIFICATION_API_KEY', 'testSecretForLogging'), contextlib.redirect_stdout(output):
            self.assertTrue(audit.notificar_cliente('test@example.invalid', 'test'))
        self.assertNotIn('testSe', output.getvalue())

    def test_http_api_rejects_unsafe_filename(self):
        response = app.test_client().get('/convertir', query_string={'archivo': '../private.html'})
        self.assertEqual(response.status_code, 400)


if __name__ == '__main__':
    unittest.main()
