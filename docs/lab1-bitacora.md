# Laboratorio 1 — Bitácora de auditoría de la cadena de suministro

- **Autor/a:** ESCRIBE_AQUÍ_TU_NOMBRE_Y_APELLIDOS
- **Repositorio:** https://github.com/TU-USUARIO/reportaudit-lab
- **Sistema operativo y versión de Python usados:**

> Completa cada sección en el momento en que la guía te lo pide, no al final.
> Una bitácora escrita "de memoria" al terminar no sirve como evidencia.

---

## Parte B — Auditoría manual (antes de usar ninguna herramienta)

| # | Función | Línea | Qué sospechas | Dato de entrada (*source*) | Destino peligroso (*sink*) |
|---|---|---|---|---|---|
| 1 | `buscar_reportes_cliente` | 41–42 | Inyección SQL por concatenación del cliente en la consulta. | Parámetro HTTP `cliente` → `nombre_cliente`. | `cursor.execute(query)`. |
| 2 | `convertir_a_pdf` | 50–51 | Inyección de comandos: el nombre del archivo se concatena en un comando interpretado por el shell. | Parámetro HTTP `archivo` → `nombre_archivo`. | `os.system(comando)`. |
| 3 | `cargar_configuracion` | 33 | Deserialización insegura con `yaml.Loader`; requiere que alguien pueda alterar el YAML local que se carga al arrancar. | Contenido de `app/config.yaml`. | `yaml.load(f, Loader=yaml.Loader)`. |
| 4 | `hash_password_legacy` | 57 | MD5 es un hash rápido e inadecuado para almacenar contraseñas; no se observa una llamada desde los endpoints actuales. | Argumento `password`. | `hashlib.md5(...).hexdigest()`. |
| 5 | Configuración del módulo | 21–22 | Clave de API y contraseña SMTP incrustadas en el código; no se reproducen sus valores en la bitácora. | Constantes versionables en el módulo. | Código fuente y eventual historial público de Git. |

**Impacto en el negocio:** para cada sospecha, explica en una frase qué
consecuencia tendría para ReportAudit y sus clientes si fuera real (qué datos,
qué sistema o qué credencial quedarían expuestos).

Auditoría manual realizada el 2026-10-05, antes de ejecutar escáneres y sin modificar el código original.

1. SQL: podría permitir acceder a reportes de clientes distintos del solicitado.
2. Comandos: podría permitir ejecutar órdenes con los permisos del proceso del servicio.
3. YAML: un archivo de configuración manipulado podría ejecutar código al arrancar el servicio.
4. MD5: si esta función se usase para almacenar contraseñas, facilitaría su descifrado por fuerza bruta ante una filtración.
5. Credenciales: publicar el módulo expone las credenciales incluidas; si fueran reales, habría que revocarlas y reemplazarlas, además de retirarlas del código.

El síntoma del cliente con apóstrofo está pendiente de reproducir en el entorno del laboratorio. Estas observaciones proceden de lectura del código, no de resultados de herramientas.


---

## Matriz de detección (se completa a lo largo del laboratorio)

Marca ✓ (lo detectó, anota la regla) o ✗ (no lo detectó) en cada columna cuando
llegues a la parte correspondiente.

| Hallazgo | Manual (B) | SonarQube for IDE sin conexión (D) | SonarQube for IDE en Connected Mode (E) | SonarQube Cloud (F) | CodeQL (F) | Semgrep (G) | Trivy (K) |
|---|---|---|---|---|---|---|---|
| H1 Inyección SQL en `buscar_reportes_cliente` |  |  |  |  |  |  | n/a |
| H2 Inyección de comandos en `convertir_a_pdf` |  |  |  |  |  |  | n/a |
| H3 Deserialización YAML insegura en `cargar_configuracion` |  |  |  |  |  |  | n/a |
| H4 Hash MD5 en `hash_password_legacy` |  |  |  |  |  |  | n/a |
| H5 Clave de API escrita en el código |  |  |  |  |  |  |  |
| H6 Contraseña SMTP escrita en el código |  |  |  |  |  |  |  |

**Conclusión de la matriz** (Parte K): ¿alguna herramienta lo detectó todo? ¿Qué
te dice eso sobre depender de una sola herramienta?

---

## Parte J — SBOM: el iceberg medido

| Dato | Valor |
|---|---|
| Dependencias directas (`requirements.in`) |  |
| Componentes Python en el SBOM |  |
| Otros componentes que aparezcan en el SBOM (si los hay) y de dónde salen |  |
| Formato y versión de especificación del SBOM (`bomFormat`, `specVersion`) |  |

---

## Parte J — Triage de vulnerabilidades de dependencias (Grype)

| Paquete | Versión | ¿Directa o transitiva? (usa `# via`) | CVE / GHSA | Severidad | Corregida en | ¿Explotable en ReportAudit? ¿Por qué? | Decisión |
|---|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |  |

**Comparación con Dependabot** (Parte H): ¿las alertas coinciden con Grype? Explica
cualquier diferencia.

**Documento VEX:** copia `plantillas/reportaudit.openvex.json` a
`docs/evidencias/`, rellénalo, enlázalo aquí y resume en una frase la
justificación.

---

## Parte L y M — Antes y después

| Medida | Antes | Después |
|---|---|---|
| Hallazgos de Semgrep en `app/` |  |  |
| Alertas abiertas de CodeQL (Security → Code scanning) |  |  |
| Vulnerabilidades en SonarQube Cloud (rama main) |  |  |
| Security Hotspots por revisar en SonarQube Cloud |  |  |
| Vulnerabilidades de Grype sobre el SBOM |  |  |
| Alertas abiertas de Dependabot |  |  |

---

## Preguntas de comprobación (Sección 7 de la guía)

1.
2.
3.
4.
5.
6.
7.
8.
9.
10.
11.
12.
