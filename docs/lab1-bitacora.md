# Laboratorio 1 — Bitácora de auditoría de la cadena de suministro

- **Autor/a:** ESCRIBE_AQUÍ_TU_NOMBRE_Y_APELLIDOS
- **Repositorio:** https://github.com/hutsebautvictor-star/reportaudit-lab
- **Sistema operativo y versión de Python usados:** Ubuntu 24.04 LTS en WSL2; Python 3.12.3.

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

El cliente con apóstrofo reproduce OperationalError; salida exacta en docs/evidencias/inicio-antes.json. Estas observaciones proceden de lectura del código, no de resultados de herramientas.


---

## Matriz de detección (se completa a lo largo del laboratorio)

Marca ✓ (lo detectó, anota la regla) o ✗ (no lo detectó) en cada columna cuando
llegues a la parte correspondiente.

| Hallazgo | Manual (B) | SonarQube for IDE sin conexión (D) | SonarQube for IDE en Connected Mode (E) | SonarQube Cloud (F) | CodeQL (F) | Semgrep (G) | Trivy (K) |
|---|---|---|---|---|---|---|---|
| H1 Inyección SQL en `buscar_reportes_cliente` | ✓, lectura del código | Pendiente | Pendiente | ✓, S3649 | ✗, PR #21 | ✗ | n/a |
| H2 Inyección de comandos en `convertir_a_pdf` | ✓, lectura del código | Pendiente | Pendiente | ✓, S2076 | ✗, PR #21 | ✗ | n/a |
| H3 Deserialización YAML insegura en `cargar_configuracion` | ✓, lectura del código | Pendiente | Pendiente | ✗ | ✗, PR #21 | ✓, avoid-pyyaml-load | n/a |
| H4 Hash MD5 en `hash_password_legacy` | ✓, lectura del código | Pendiente | Pendiente | ✓, S4790 | ✗, PR #21 | ✓, insecure-hash-algorithm-md5 y md5-used-as-password | n/a |
| H5 Clave de API escrita en el código | ✓, lectura del código | Pendiente | Pendiente | ✗ | ✗, PR #21 | ✗ | ✗ |
| H6 Contraseña SMTP escrita en el código | ✓, lectura del código | Pendiente | Pendiente | ✓, S2068 y S7552 | ✗, PR #21 | ✗ | ✗ |

La columna Cloud corresponde al [análisis automático inicial](evidencias/sonar-automatico-antes-issues.json). La de CodeQL corresponde al [PR #21](evidencias/codeql-pr21-analyses.json).

**Conclusión de la matriz.** Semgrep señaló YAML y MD5. El análisis inicial de SonarQube Cloud señaló SQL, argumentos de comandos, hash y la contraseña SMTP, entre otros avisos. Trivy encontró avisos de dependencias pero no reconoció las dos credenciales del código con las reglas usadas. Las detecciones dependen de las reglas y del alcance de cada escáner. Las dos mediciones del editor siguen pendientes.

---

## Parte J — SBOM: el iceberg medido

| Dato | Valor |
|---|---|
| Dependencias directas (`requirements.in`) | 2: Flask y PyYAML |
| Componentes Python en el SBOM | 9 bibliotecas. Colorama figura en el manifiesto, pero su marcador de plataforma impide instalarlo en Linux. |
| Otros componentes que aparezcan en el SBOM (si los hay) y de dónde salen | 1 componente file: requirements.txt; los workflows aún no están activados. |
| Formato y versión de especificación del SBOM (`bomFormat`, `specVersion`) | CycloneDX 1.6 |

---

## Parte J — Triage de vulnerabilidades de dependencias (Grype)

| Paquete | Versión | ¿Directa o transitiva? (usa `# via`) | CVE / GHSA | Severidad | Corregida en | ¿Explotable en ReportAudit? ¿Por qué? | Decisión |
|---|---|---|---|---|---|---|---|
| werkzeug | 3.0.1 | Transitiva (# via flask) | [CVE-2024-34069 / GHSA-2g68-c3qc-8985](https://github.com/advisories/GHSA-2g68-c3qc-8985) | High | 3.0.3 | No en el arranque documentado: app/servicio.py usa debug=False. Revalidar si cambia el arranque. | Actualizar igualmente; además VEX |
| werkzeug | 3.0.1 | Transitiva (# via flask) | [CVE-2024-49767 / GHSA-q34m-jh98-gwm2](https://github.com/advisories/GHSA-q34m-jh98-gwm2) | Medium | 3.0.6 | No se observa lectura de request.form o request.files; las rutas actuales leen request.args. Revalidar si se añaden cargas multipart. | Actualizar igualmente; reevaluar ante cambios de código o entorno |
| jinja2 | 3.1.2 | Transitiva (# via flask) | [CVE-2024-34064 / GHSA-h75v-3vvj-5mfj](https://github.com/advisories/GHSA-h75v-3vvj-5mfj) | Medium | 3.1.4 | No en las rutas actuales: app/servicio.py responde con jsonify y no renderiza plantillas no confiables. | Actualizar igualmente; reevaluar ante cambios de código o entorno |
| jinja2 | 3.1.2 | Transitiva (# via flask) | [CVE-2024-22195 / GHSA-h5c8-rqwp-cp95](https://github.com/advisories/GHSA-h5c8-rqwp-cp95) | Medium | 3.1.3 | No en las rutas actuales: app/servicio.py responde con jsonify y no renderiza plantillas no confiables. | Actualizar igualmente; reevaluar ante cambios de código o entorno |
| werkzeug | 3.0.1 | Transitiva (# via flask) | [CVE-2024-49766 / GHSA-f9vj-2wh5-fj8j](https://github.com/advisories/GHSA-f9vj-2wh5-fj8j) | Medium | 3.0.6 | No en Linux con Python 3.12: exige Windows con Python inferior a 3.11. | Actualizar igualmente; reevaluar ante cambios de código o entorno |
| werkzeug | 3.0.1 | Transitiva (# via flask) | [CVE-2026-27199 / GHSA-29vq-49wr-vm6x](https://github.com/advisories/GHSA-29vq-49wr-vm6x) | Medium | 3.1.6 | No en este entorno Linux: afecta a nombres de dispositivos Windows al servir archivos. | Actualizar igualmente; reevaluar ante cambios de código o entorno |
| jinja2 | 3.1.2 | Transitiva (# via flask) | [CVE-2024-56326 / GHSA-q2x7-8rv6-6q7h](https://github.com/advisories/GHSA-q2x7-8rv6-6q7h) | Medium | 3.1.5 | No en las rutas actuales: app/servicio.py responde con jsonify y no renderiza plantillas no confiables. | Actualizar igualmente; reevaluar ante cambios de código o entorno |
| werkzeug | 3.0.1 | Transitiva (# via flask) | [CVE-2025-66221 / GHSA-hgf8-39gv-g3f2](https://github.com/advisories/GHSA-hgf8-39gv-g3f2) | Medium | 3.1.4 | No en este entorno Linux: afecta a nombres de dispositivos Windows al servir archivos. | Actualizar igualmente; reevaluar ante cambios de código o entorno |
| jinja2 | 3.1.2 | Transitiva (# via flask) | [CVE-2025-27516 / GHSA-cpwx-vrp4-4pq7](https://github.com/advisories/GHSA-cpwx-vrp4-4pq7) | Medium | 3.1.6 | No en las rutas actuales: app/servicio.py responde con jsonify y no renderiza plantillas no confiables. | Actualizar igualmente; reevaluar ante cambios de código o entorno |
| werkzeug | 3.0.1 | Transitiva (# via flask) | [CVE-2026-21860 / GHSA-87hc-h4r5-73f7](https://github.com/advisories/GHSA-87hc-h4r5-73f7) | Medium | 3.1.5 | No en este entorno Linux: afecta a nombres de dispositivos Windows con extensiones o espacios. | Actualizar igualmente; reevaluar ante cambios de código o entorno |
| jinja2 | 3.1.2 | Transitiva (# via flask) | [CVE-2024-56201 / GHSA-gmj6-6f8f-6699](https://github.com/advisories/GHSA-gmj6-6f8f-6699) | Medium | 3.1.5 | No en las rutas actuales: app/servicio.py responde con jsonify y no renderiza plantillas no confiables. | Actualizar igualmente; reevaluar ante cambios de código o entorno |
| flask | 3.0.0 | Directa (# via -r requirements.in) | [CVE-2026-27205 / GHSA-68rp-wp8r-4726](https://github.com/advisories/GHSA-68rp-wp8r-4726) | Low | 3.1.3 | No se observa acceso a session ni un proxy de caché en el arranque documentado; no se cumplen las condiciones del aviso. | Actualizar igualmente; reevaluar ante cambios de código o entorno |

**Comparación con Dependabot.** Los dos informes iniciales coinciden en 12 avisos tras comparar sus identificadores GHSA. Véanse [Dependabot](evidencias/dependabot-antes.json) y [Grype](evidencias/grype-antes.json).

**Documento VEX.** El [VEX de ReportAudit](evidencias/reportaudit.openvex.json) justifica que CVE-2024-34069 no afecta al arranque documentado porque este mantiene desactivado el depurador de Werkzeug. Se recomienda actualizar el paquete igualmente.

---

## Parte L y M — Antes y después

| Medida | Antes | Después |
|---|---|---|
| Hallazgos de Semgrep en `app/` | 3 | 0 en la rama de corrección |
| Alertas abiertas de CodeQL (Security → Code scanning) | 0 en el PR del pipeline #21 | 0 en el PR de corrección #22. Medición de `main` pendiente. |
| Vulnerabilidades en SonarQube Cloud (rama main) | 6 en el análisis automático inicial | Quality Gate del PR #22 en verde. Medición de `main` pendiente. |
| Security Hotspots por revisar en SonarQube Cloud | 0 en el análisis automático inicial | Pendiente de comprobar en `main` tras la fusión. |
| Vulnerabilidades de Grype sobre el SBOM | 12 | Medición de `main` pendiente. |
| Alertas abiertas de Dependabot | 12 | Pendiente de fusionar las actualizaciones y consultar GitHub. |
| Vulnerabilidades detectadas por Trivy | 12 | Medición de `main` pendiente. |

---

## Preguntas de comprobación (Sección 7 de la guía)

1. En Windows abro VS Code y el navegador. En Ubuntu se guardan la copia de trabajo y el entorno virtual, y se ejecutan Python, Git y los escáneres del laboratorio. GitHub guarda el historial remoto y ejecuta las comprobaciones de los PR. Usar Ubuntu mantiene el entorno local alineado con los runners Linux.
2. Flask aparece en `requirements.in` porque el proyecto lo usa directamente. Werkzeug llega a través de Flask. Lo indica el comentario `# via flask` del lockfile y ambos figuran en el [SBOM inicial](evidencias/sbom.cyclonedx.json).
3. El *source* es el punto de entrada de un dato y el *sink* es la operación sensible que lo consume. En el código original, `servicio.py` recibía el nombre del cliente y `reporte_auditoria.py` lo incorporaba a la consulta que ejecutaba SQLite.
4. El apóstrofo del nombre rompía la sintaxis porque el código concatenaba el dato en una cadena SQL. Eso indica que la entrada podía alterar la estructura de la consulta. La corrección pasa el nombre como parámetro, de modo que SQLite lo interpreta como un valor.
5. El hook de Semgrep puede bloquear un commit en la copia local y da feedback inmediato. SonarQube Cloud y CodeQL vuelven a analizar el PR en GitHub, donde los resultados pueden exigirse para fusionar. El hook local requiere instalación y se puede omitir.
6. Cada análisis tiene reglas y un alcance diferentes. En este caso Semgrep detectó la carga insegura de YAML, SonarQube Cloud señaló problemas de SQL y comandos, y Trivy encontró vulnerabilidades de paquetes. La matriz permite comparar qué vio cada uno.
7. El PR de código corrige operaciones inseguras de la aplicación, que son el objeto del análisis de CodeQL. Dependabot sigue los paquetes y sus versiones, así que sus alertas se cierran cuando se integran versiones corregidas.
8. Borrar un valor del código actual deja las copias antiguas en el historial de Git. Si corresponde a una credencial real, hay que revocarla en el proveedor y almacenar su sustituta fuera del repositorio.
9. VEX deja constancia del paquete, el aviso, el estado y la razón por la que una configuración concreta no está afectada. En este caso, el depurador vulnerable de Werkzeug queda fuera del arranque documentado. La decisión se revisaría si cambia ese arranque.
10. La comparación SHA-256 detecta discrepancias con el archivo de huellas publicado. Si se sustituyen a la vez el binario y las huellas en el origen, pueden seguir coincidiendo. Por eso importan también la procedencia y la seguridad del canal de distribución.
11. El escaneo de la carpeta actual revisa los archivos corregidos. El escaneo de Git incluye los commits que introdujeron los dos valores. Si alguno fuera real, la revocación en el proveedor es lo que invalida las copias existentes. Una exclusión de huella solo modifica el resultado del escáner.
12. En la fase inicial, el lockfile contiene avisos conocidos y exigir de inmediato el check bloquearía también los PR que preparan la corrección. Primero se corrige e integra esa línea base y, una vez limpia, se exige el check para evitar retrocesos.
13. Dependabot vigila las dependencias del repositorio y abre alertas o propuestas incluso si nadie cambia el código. El check de pip-audit revisa las versiones fijadas del PR cuando corre el pipeline y puede bloquear su fusión.
14. Las sumas verifican la coincidencia de los archivos con el listado descargado. Las atestaciones enlazan criptográficamente el archivo con el repositorio y el workflow, y vinculan el SBOM al mismo artefacto. Estas comprobaciones no sustituyen una revisión del contenido ni protegen frente a un workflow legítimo comprometido.
15. El canal privado permite investigar y preparar una corrección sin exponer el problema al público antes del parche. `SECURITY.md` indica qué versiones reciben soporte, cómo contactar y qué respuesta se puede esperar.
16. Un 0 en *Maintained* puede reflejar el poco historial o la baja frecuencia de cambios de un repositorio docente. Hay que leer la señal junto con su criterio y el contexto. La puntuación de ReportAudit está pendiente de medir con su propio workflow.
17. En B5 de la Práctica 2 (pág. 9) propuse un informe SCA con VEX, pruebas de configuración y un SBOM de cada versión ligado a la huella del paquete. Ya puedo enseñar los [resultados de Grype](evidencias/grype-antes.txt), el [VEX](evidencias/reportaudit.openvex.json), las [pruebas de corrección](evidencias/pruebas-correcciones.txt) y el [SBOM inicial](evidencias/sbom.cyclonedx.json). Quedan el SBOM atestado de la versión publicada, su firma y el registro de recepción del aviso privado, que también anticipé en B5.

## Backlog del laboratorio (Issues)

| Issue | Título | PR o evidencia de cierre |
|---|---|---|
| #1 | Adopt an international pull request template | Pendiente |
| #2 | Run SAST (SonarQube Cloud and CodeQL) on every pull request | Pendiente |
| #3 | Block insecure commits with a Semgrep pre-commit hook | Pendiente |
| #4 | Enable Dependabot alerts and security updates | Pendiente |
| #5 | Remediate the findings of the security audit | Pendiente |
| #6 | Upgrade the vulnerable dependencies | Pendiente |
| #7 | Publish the audit log and the before/after evidence | Pendiente |
| #8 | Detect ReportAudit credentials in the whole Git history | Pendiente |
| #9 | Make SCA and secret scanning required checks on main | Pendiente |
| #10 | Publish a security policy and a private vulnerability reporting channel | Pendiente |
| #11 | Release v1.0.0 with an SBOM and signed provenance | Pendiente |
| #12 | Measure supply-chain maturity with OpenSSF Scorecard | Pendiente |
| #13 | Build the CRA evidence index | Expediente preliminar preparado en la copia local |

## Estado al 2026-10-05

- main protegida: una aprobación obligatoria, administradores incluidos, sin force push ni eliminación.
- PR #14: plantilla; PR #15: Semgrep; PR #16: Dependabot. Pendientes de revisión y fusión; todavía no hay compañero.
- Dependabot alerts y automated security fixes activados. Configuración pendiente de fusionar; 12 alertas abiertas leídas; coinciden por identificador GHSA con Grype.
- Servicio comprobado mediante el cliente de pruebas de Flask: respuestas 200 en / y /reportes.
- Syft 1.52.0, Grype 0.119.0 y Trivy 0.74.0 instalados con verificación SHA-256 satisfactoria.
- Semgrep de desarrollo está en ~/.local/share/reportaudit-tools; el hook usa su entorno aislado y v1.172.0. Ambos detectan tres hallazgos de YAML/MD5.
- Commit inseguro bloqueado: docs/evidencias/commit-bloqueado.txt. El archivo de prueba se retiró sin confirmar.
- Trivy: 12 vulnerabilidades y 0 secretos reconocidos. Sus patrones no reconocen las dos credenciales de ejemplo visibles en el código.
- SonarQube for IDE, Connected Mode, SonarQube Cloud y CodeQL pendientes: las casillas pendientes no son resultados negativos.
- VEX: [reportaudit.openvex.json](evidencias/reportaudit.openvex.json), CVE-2024-34069; debug=False excluye el depurador vulnerable del arranque documentado. Se recomienda actualizar igualmente.
- Triage basado en los avisos enlazados y rutas actuales. Revalidar las conclusiones si cambian código, arranque o sistema operativo.
- Nombre completo del autor pendiente de confirmar. No se inventan respuestas a preguntas ausentes de la guía disponible.
- El PDF de 62 páginas termina en K.4; L-T solo están anunciadas en el índice. Entrega final todavía incompleta.

Dependabot y Grype coinciden en los doce identificadores GHSA. La alerta de Werkzeug CVE-2024-34069 es High y tiene versión corregida 3.0.3; el VEX limita la no afectación al arranque con debug=False. Dependabot ha abierto los PR #17 (Flask), #18 (Werkzeug) y #19 (Jinja2), pendientes de checks y revisión. No se han fusionado ni cerrado las alertas.

## Integración SAST: PR #21

- Organization Key: hutsebautvictor-star.
- Project Key: hutsebautvictor-star_reportaudit-lab.
- Automatic Analysis desactivado según la captura aportada por el estudiante.
- SONAR_TOKEN comprobado por nombre en Actions y Dependabot; nunca se registra su valor.
- PR: https://github.com/hutsebautvictor-star/reportaudit-lab/pull/21.
- Ejecución: https://github.com/hutsebautvictor-star/reportaudit-lab/actions/runs/37353921995.
- Checks SAST - SonarQube Cloud y SAST - CodeQL: success. Ambos son obligatorios en main y se exige que la rama esté actualizada.
- La aprobación de un compañero sigue siendo obligatoria; PR pendiente de revisión y fusión.
- CodeQL: análisis real del merge ref del PR #21, 50 reglas y 0 resultados; evidencia en codeql-pr21-analyses.json. No se generaliza como ausencia de riesgos: la auditoría manual y SonarQube encuentran fallos.
- Snapshot previo de análisis automático de main: 6 vulnerabilities y 0 security hotspots, 205 líneas. Es provisional y no sustituye la línea base de main mediante CI tras fusionar el PR.
- SonarQube for IDE 6.0.1 instalado y verificado en ~/.vscode-server/extensions dentro de Ubuntu. Connected Mode y su comparación con el análisis sin conexión pendientes.
- El plan Free todavía está pendiente de confirmar; la captura del estudiante muestra una prueba Team de 14 días.
- No se han corregido los problemas del código ni se declara completada la comparación final.

## Correcciones verificadas en el PR #22

- Connected Mode vinculado a hutsebautvictor-star_reportaudit-lab; evidencia sin credenciales en connected-mode-proyecto.json. No se inventan resultados de la comparación del editor antes y después de conectar.
- PR: https://github.com/hutsebautvictor-star/reportaudit-lab/pull/22; revisión analizada: 4614c5dcd1934207772ba363b2478ed18a491b4d.
- SQL parametrizado: el apóstrofo funciona como dato y la entrada de inyección no accede a otros clientes.
- PDF: nombres HTML acotados, archivos existentes en reportes/, rechazo de enlaces fuera de la carpeta y ejecución sin shell. wkhtmltopdf está simulado en las pruebas: el renderizado real sigue sin verificar.
- YAML seguro, hash de contraseñas scrypt con sal aleatoria y retirada de credenciales incrustadas y de sus fragmentos en logs.
- No se ha revocado ninguna credencial externa: el proyecto recibido incluye muestras docentes y no hay proveedor real configurado. Si los valores históricos fueran reales, su propietario debe revocarlos.
- 11 pruebas de regresión pasan. Cobertura local total de app/: 97%; módulo de negocio: 100%. SonarQube informa 100% de cobertura sobre código nuevo del PR.
- Semgrep: 3 hallazgos antes, 0 después. El hook con v1.172.0 también pasa sobre el código corregido.
- CodeQL: 0 alertas abiertas en el PR final; SonarQube Quality Gate: OK. Los cuatro checks publicados del PR final pasan.
- coverage==7.16.2 (Apache-2.0) es una herramienta de desarrollo, fijada en requirements-dev.txt; no se incorpora a las dependencias del servicio. CI ejecuta las pruebas y envía coverage.xml al análisis.
- La rama incluye el pipeline del PR #21, que debe fusionarse primero. Todos los PR siguen pendientes de aprobación del compañero; no se ha eludido la protección de main.
- Los resultados del PR no sustituyen una medición de main después de fusionar. En main siguen el código original y las doce alertas de dependencias, con actualizaciones pendientes en los PR #17-19.
- La entrega completa, las preguntas ausentes de la guía disponible y el bloque L-T siguen pendientes.

## Continuación del 25 de noviembre de 2026

La guía completa de 98 páginas incorpora el detalle de L–T. El estado de octubre se conserva arriba como registro histórico. Al consultar GitHub el 25 de noviembre, los PR #14 a #22 seguían abiertos con revisión obligatoria. Los archivos nuevos de esta sección se han preparado en una copia local basada en el PR #22.

### L–N. Trivy, corrección y medición

El [informe inicial de Trivy](evidencias/trivy-antes.json) registra 12 vulnerabilidades de dependencias y cero coincidencias de secretos con las reglas del escaneo. La auditoría manual sí encontró los dos valores incrustados. El PR #22 corrige el código. La medición final de dependencias y del código queda ligada a los resultados de `main` después de fusionar los PR.

En una copia temporal del PR #22 probé la combinación de los cambios de los PR #17 y #19. El [lockfile candidato](evidencias/candidato-requirements.txt) usa Flask 3.1.3, Jinja2 3.1.6 y el Werkzeug 3.1.9 que resolvía el PR de Flask. Conservé el marcador de Colorama para Windows. Pasaron las [11 pruebas y `pip check`](evidencias/candidato-pruebas.txt) y Syft generó el [SBOM del candidato](evidencias/candidato-sbom.cyclonedx.json). Grype y Trivy excedieron el tiempo de espera durante la actualización o consulta de sus bases, según el [registro local](evidencias/candidato-resumen.json).

### O. Secretos en el historial

| Escaneo | Hallazgos | Alcance |
|---|---:|---|
| `gitleaks dir app`, reglas por defecto | 0 | Código corregido del PR #22 |
| `gitleaks git . --log-opts=--all`, reglas por defecto | 7 | Historial de las referencias locales |
| `gitleaks git . --log-opts=--all --config .gitleaks.toml` | 8 | Dos asignaciones incrustadas en el commit de importación y seis identificadores de incidencias de SonarQube |
| `gitleaks dir app --config .gitleaks.toml` | 0 | Código corregido del PR #22 |
| Historial con exclusiones de huellas verificadas | 2 | Se excluyen las seis coincidencias de identificadores de SonarQube. Los dos valores de la aplicación siguen detectándose. |

La [evidencia local de Gitleaks](evidencias/gitleaks-verificacion-e-historial.json) recoge la versión 8.30.1, la comparación SHA-256 y los metadatos de cada hallazgo. Se comprobó que las seis coincidencias del JSON de SonarQube corresponden a campos `issues[].key`, identificadores de incidencias. `.gitleaksignore` contiene únicamente sus huellas, ligadas a la revisión y línea concretas. Los valores de la aplicación quedan fuera de las exclusiones hasta confirmar su naturaleza y, si procede, su revocación.

### P. Comprobaciones obligatorias

| Check | Estado |
|---|---|
| SAST - SonarQube Cloud | Configurado y verificado en el PR #21 |
| SAST - CodeQL | Configurado y verificado en el PR #21 |
| SCA - pip-audit | YAML preparado localmente. Pendiente de ejecución en GitHub y de exigirlo en `main`. |
| Secretos - Gitleaks | YAML y regla preparados. Pendiente de ejecución en GitHub y de exigirlo en `main`. |

El 26 de noviembre se comprobó en GitHub que *secret scanning* y *push protection* están activados y que `main` exige una revisión y los dos checks SAST. Queda registrar en GitHub la ejecución del control SCA y añadir los nuevos checks a la protección de `main` cuando se integren las actualizaciones.

La [prueba local de pip-audit](evidencias/pip-audit-prueba-local.json) revisó los dos lockfiles sin instalar sus paquetes para el escaneo. El original devolvió 25 avisos y código de salida 1. El candidato devolvió cero avisos y código 0. Estos recuentos corresponden a pip-audit y su base consultada en noviembre. Los 12 avisos de octubre corresponden a otros escáneres y a su consulta de entonces. Falta comprobar el check en GitHub.

### Q. Divulgación coordinada

Política y período de soporte preparados en [SECURITY.md](../SECURITY.md). Pendientes su revisión, habilitar el canal privado y el simulacro del compañero. El identificador del borrador de aviso, CVSS, CWE, versiones y créditos se registrarán cuando exista el aviso privado.

### R. Versión verificable

Workflow de publicación preparado en [publicar-version.yml](../.github/workflows/publicar-version.yml). Quedan la revisión, la publicación desde un commit integrado, los cinco archivos de la Release y las comprobaciones de huellas y atestaciones. La verificación de una copia alterada se documentará a partir del paquete realmente publicado.

### S. Scorecard

Workflow preparado en [scorecard.yml](../.github/workflows/scorecard.yml) para ejecutarse en `main`, semanalmente o de forma manual. Puntuación y análisis de resultados pendientes de la primera ejecución en GitHub.

### T. Expediente

El [expediente preliminar](cra/expediente-evidencias.md) recoge las doce comprobaciones. Quedan los enlaces de la Release, el aviso privado, las ejecuciones finales y la revisión por el compañero.

## Continuación del 26 de noviembre de 2026

Se publicaron y comprobaron los seis [PR del bloque final](evidencias/estado-pr-bloque-final.json):

| Parte | Borrador | Base provisional |
|---|---|---|
| O. Gitleaks | [#23](https://github.com/hutsebautvictor-star/reportaudit-lab/pull/23) | PR de corrección #22 |
| P. Controles SCA y secretos | [#24](https://github.com/hutsebautvictor-star/reportaudit-lab/pull/24) | PR de Gitleaks #23 |
| Q. Política de seguridad | [#25](https://github.com/hutsebautvictor-star/reportaudit-lab/pull/25) | `main` |
| R. Publicación firmada | [#26](https://github.com/hutsebautvictor-star/reportaudit-lab/pull/26) | `main` |
| S. Scorecard | [#27](https://github.com/hutsebautvictor-star/reportaudit-lab/pull/27) | `main` |
| T. Expediente | [#28](https://github.com/hutsebautvictor-star/reportaudit-lab/pull/28) | PR de evidencias #20 |

- GitHub confirmó que el canal privado de avisos está habilitado. Queda el simulacro con el compañero y la integración de la política.
- En el [PR de prueba #29](https://github.com/hutsebautvictor-star/reportaudit-lab/pull/29), se ejecutaron los cuatro controles sin cambiar las dependencias respecto de `main`. SCA - pip-audit falló según lo esperado con 25 avisos en tres paquetes. Gitleaks, CodeQL y SonarQube pasaron. El PR se cerró sin fusionar. Se conservan el [registro de GitHub Actions](evidencias/puerta-sca-pr29.json), la [captura del check fallido](evidencias/puerta-sca-pr29.jpg) y la [captura del cierre](evidencias/pr29-cerrado.jpg).
- En la [prueba local del empaquetado](evidencias/paquete-prueba-local.json), el paso de publicación generó un archivo con los 59 ficheros versionados del commit de prueba. Rechazó una etiqueta inválida y un commit ajeno a la referencia de `main` simulada. Las huellas de la copia original y la alterada difieren. No se creó una Release ni se emitieron atestaciones con esta prueba.
- El [PR #21](https://github.com/hutsebautvictor-star/reportaudit-lab/pull/21) seguía pendiente de aprobación con los checks en verde al comprobarlo. El compañero debe aceptar la invitación antes de revisar. Cambiar la base de cada borrador apilado cuando se integre su PR anterior y verificar los checks antes de fusionar.

## Continuación del 28 de noviembre de 2026

- Pedro (`pedromedinaps4-del`) ya figura como colaborador con permiso de escritura. Aprobó los PR #14 a #19 y #21 a #22, excepto el #20, que sigue en borrador. Las aprobaciones corresponden a las revisiones que vio en GitHub.
- Se fusionó el [PR #21](https://github.com/hutsebautvictor-star/reportaudit-lab/pull/21) con su aprobación y los checks obligatorios en verde. En la [primera ejecución del pipeline en main](https://github.com/hutsebautvictor-star/reportaudit-lab/actions/runs/46142741642), CodeQL y SonarQube terminaron correctamente. La [línea base de main](evidencias/linea-base-main-2026-11-28.json) registra cuatro alertas abiertas de CodeQL y seis de SonarQube antes de integrar las correcciones.
- Se actualizó el [PR #22](https://github.com/hutsebautvictor-star/reportaudit-lab/pull/22) con el nuevo `main`. Sus checks pasaron en la revisión `af975e8`. GitHub invalidó la aprobación de la revisión anterior, de acuerdo con la regla de descartar aprobaciones cuando cambia el PR. Queda la nueva revisión de Pedro.
- Se guardó una [captura del registro de Semgrep](evidencias/semgrep-commit-bloqueado.jpg) donde constan el bloqueo y el código de salida 1.
