"""ReportAudit: lógica de reportes de auditoría.

Versión corregida en el laboratorio de cadena de suministro segura.
La versión inicial y sus hallazgos se conservan como evidencia en Git.
"""

import os
import string
import sqlite3
import subprocess
from pathlib import Path

from werkzeug.security import generate_password_hash

import yaml

# Las credenciales se suministran desde el entorno, nunca desde el repositorio.
NOTIFICATION_API_KEY = os.environ.get("NOTIFICATION_API_KEY", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")

RUTA_REPORTES = Path(__file__).resolve().parent.parent / "reportes"

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
    # Acotar el nombre evita rutas, opciones del programa y entradas desmesuradas.
    if (
        not isinstance(nombre_archivo, str)
        or len(nombre_archivo) > 255
        or not nombre_archivo.endswith(".html")
    ):
        raise ValueError("Nombre de archivo no válido")
    nombre_base = nombre_archivo[:-5]
    alfanumericos = string.ascii_letters + string.digits
    permitidos = alfanumericos + "_.-"
    if (
        not nombre_base
        or nombre_base[0] not in alfanumericos
        or any(caracter not in permitidos for caracter in nombre_base)
    ):
        raise ValueError("Nombre de archivo no válido")
    # El argumento procede del inventario de archivos del servidor, no de la petición.
    archivos = {ruta.name: ruta for ruta in RUTA_REPORTES.glob("*.html") if ruta.is_file()}
    try:
        entrada = archivos[nombre_archivo].resolve()
    except KeyError as error:
        raise ValueError("Reporte HTML no disponible") from error
    if entrada.parent != RUTA_REPORTES.resolve():
        raise ValueError("Reporte fuera de la carpeta permitida")
    salida = entrada.with_name(entrada.name + ".pdf")
    subprocess.run(["wkhtmltopdf", str(entrada), str(salida)], check=True)
    return salida.name



def hash_password_legacy(password):
    """Genera el hash de una contraseña para el sistema legado de clientes."""
    return generate_password_hash(password, method="scrypt")


def notificar_cliente(email, mensaje):
    """Envía una notificación al cliente usando el servicio externo."""
    print(f"[NotifyAPI] -> {email}: {mensaje}")
    return True
