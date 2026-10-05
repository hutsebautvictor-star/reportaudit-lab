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
| H1 Inyección SQL en `buscar_reportes_cliente` | ✓, lectura del código | Pendiente | Pendiente | Pendiente | Pendiente | ✗ | n/a |
| H2 Inyección de comandos en `convertir_a_pdf` | ✓, lectura del código | Pendiente | Pendiente | Pendiente | Pendiente | ✗ | n/a |
| H3 Deserialización YAML insegura en `cargar_configuracion` | ✓, lectura del código | Pendiente | Pendiente | Pendiente | Pendiente | ✓, avoid-pyyaml-load | n/a |
| H4 Hash MD5 en `hash_password_legacy` | ✓, lectura del código | Pendiente | Pendiente | Pendiente | Pendiente | ✓, insecure-hash-algorithm-md5 y md5-used-as-password | n/a |
| H5 Clave de API escrita en el código | ✓, lectura del código | Pendiente | Pendiente | Pendiente | Pendiente | ✗ | ✗ |
| H6 Contraseña SMTP escrita en el código | ✓, lectura del código | Pendiente | Pendiente | Pendiente | Pendiente | ✗ | ✗ |

**Conclusión de la matriz** (Parte K): ¿alguna herramienta lo detectó todo? ¿Qué
te dice eso sobre depender de una sola herramienta?

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

**Comparación con Dependabot** (Parte H): ¿las alertas coinciden con Grype? Explica
cualquier diferencia.

**Documento VEX:** copia `plantillas/reportaudit.openvex.json` a
`docs/evidencias/`, rellénalo, enlázalo aquí y resume en una frase la
justificación.

---

## Parte L y M — Antes y después

| Medida | Antes | Después |
|---|---|---|
| Hallazgos de Semgrep en `app/` | 3 | Pendiente |
| Alertas abiertas de CodeQL (Security → Code scanning) |  |  |
| Vulnerabilidades en SonarQube Cloud (rama main) |  |  |
| Security Hotspots por revisar en SonarQube Cloud |  |  |
| Vulnerabilidades de Grype sobre el SBOM | 12 | Pendiente |
| Alertas abiertas de Dependabot | 12 | Pendiente |

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
