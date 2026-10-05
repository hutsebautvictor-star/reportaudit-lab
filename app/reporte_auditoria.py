"""ReportAudit: lógica de reportes de auditoría.

Versión corregida en el laboratorio de cadena de suministro segura.
La versión inicial y sus hallazgos se conservan como evidencia en Git.
"""

import os
import re
import sqlite3
import subprocess

from werkzeug.security import generate_password_hash

import yaml

# Las credenciales se suministran desde el entorno, nunca desde el repositorio.
NOTIFICATION_API_KEY = os.environ.get("NOTIFICATION_API_KEY", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")

RUTA_DB = os.path.join(os.path.dirname(__file__), "..", "reportes.db")


def cargar_configuracion(ruta_config):
    """Carga la configuración del servicio desde un archivo YAML."""
    with open(ruta_config, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    return config


def buscar_reportes_cliente(nombre_cliente, ruta_db=RUTA_DB):
    """Devuelve todos los reportes asociados a un cliente."""
    conexion = sqlite3.connect(ruta_db)
    try:
        cursor = conexion.execute(
            "SELECT * FROM reportes WHERE cliente = ?", (nombre_cliente,)
        )
        return cursor.fetchall()
    finally:
        conexion.close()


def convertir_a_pdf(nombre_archivo):
    """Convierte un reporte HTML a PDF usando la utilidad del sistema."""
    # Solo nombres HTML locales: no rutas, opciones del programa ni metacaracteres.
    if not isinstance(nombre_archivo, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.-]*\.html", nombre_archivo
    ):
        raise ValueError("Nombre de archivo no válido")
    salida = nombre_archivo + ".pdf"
    subprocess.run(["wkhtmltopdf", nombre_archivo, salida], check=True)
    return salida


def hash_password_legacy(password):
    """Genera el hash de una contraseña para el sistema legado de clientes."""
    return generate_password_hash(password, method="scrypt")


def notificar_cliente(email, mensaje):
    """Envía una notificación al cliente usando el servicio externo."""
    print(f"[NotifyAPI] -> {email}: {mensaje}")
    return True
