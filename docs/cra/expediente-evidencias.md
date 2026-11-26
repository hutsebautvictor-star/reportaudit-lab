# Expediente preliminar de evidencias de ReportAudit

- Repositorio: https://github.com/hutsebautvictor-star/reportaudit-lab
- Versión prevista: `v1.0.0`
- Actualizado: 2026-11-25
- Responsable: `hutsebautvictor-star`

Índice de trabajo para la parte T del laboratorio. Registra lo que se puede comprobar ahora y qué evidencia falta para evaluar la versión.

| # | Requisito | Referencia de la guía | Evidencia disponible o pendiente | Cómo verificarla |
|---:|---|---|---|---|
| 1 | Vulnerabilidades conocidas antes de publicar | Anexo I, Parte I, 2.a | [Análisis de código del PR #22](https://github.com/hutsebautvictor-star/reportaudit-lab/pull/22/checks), [Grype inicial](../evidencias/grype-antes.txt) y [VEX](../evidencias/reportaudit.openvex.json). Faltan los análisis del commit que se publique. | Abrir los checks y comparar la revisión analizada con el commit de la futura etiqueta. Volver a escanear el SBOM de esa versión. |
| 2 | Configuración segura por defecto | Anexo I, Parte I, 2.b | [Cambios del PR #22](https://github.com/hutsebautvictor-star/reportaudit-lab/pull/22/files). Revisión de hotspots en `main` pendiente. | Inspeccionar la carga segura de YAML, la parametrización de SQL y la procedencia de las credenciales en el diff. Consultar Security Hotspots tras la fusión. |
| 3 | Protección frente a accesos no autorizados | Anexo I, Parte I, 2.d | [Detección de secretos en el historial](../evidencias/gitleaks-verificacion-e-historial.json) y [regla local](../../.gitleaks.toml). Falta verificar la protección del push. | Consultar revisiones, archivos y huellas en el informe, y comprobar el ajuste *Push protection* en GitHub. |
| 4 | Inventario de componentes | Anexo I, Parte II, 1 | [SBOM CycloneDX inicial](../evidencias/sbom.cyclonedx.json). Queda el SBOM atestado de la versión. | Abrir `components` y contrastar nombres y versiones con el lockfile de la misma revisión. |
| 5 | Corrección de vulnerabilidades de dependencias | Anexo I, Parte II, 2 | [PR de dependencias](https://github.com/hutsebautvictor-star/reportaudit-lab/pulls), [alertas iniciales](../evidencias/dependabot-antes.json) y [prueba local de pip-audit](../evidencias/pip-audit-prueba-local.json). Fusiones y cierre de alertas pendientes. | Comparar las versiones del diff y revisar Dependabot después de la fusión. |
| 6 | Pruebas y revisiones periódicas | Anexo I, Parte II, 3 | [Ejecución SAST y cobertura del PR #22](../evidencias/pipeline-pr22.json) y [workflow de Scorecard preparado](../../.github/workflows/scorecard.yml). Falta la ejecución de Scorecard. | Consultar *Actions*, el commit analizado y los checks de cada PR. Revisar el disparador semanal. |
| 7 | Información sobre vulnerabilidades corregidas | Anexo I, Parte II, 4 | Borrador de aviso del simulacro pendiente. Su acceso quedará limitado a colaboradores autorizados. | Revisar en *Security → Advisories* el borrador, la versión afectada y la corregida, con acceso autorizado. |
| 8 | Política de divulgación coordinada | Anexo I, Parte II, 5 | [Política de seguridad preparada](../../SECURITY.md). Pendientes la fusión y la activación del canal. | Tras la fusión, abrir *Security → Policy* y comprobar que la política coincide con el archivo de `main`. |
| 9 | Contacto para comunicar vulnerabilidades | Anexo I, Parte II, 6 | El borrador de [SECURITY.md](../../SECURITY.md) enlaza al formulario privado. | Comprobar desde una cuenta autorizada que aparece el botón *Report a vulnerability*. |
| 10 | Distribución segura de actualizaciones | Anexo I, Parte II, 7 | [Workflow de publicación](../../.github/workflows/publicar-version.yml). Release y atestaciones pendientes. | Descargar los activos de `v1.0.0` y ejecutar los comandos de suma y de verificación de las dos atestaciones que recoge `SECURITY.md`. |
| 11 | Período de soporte | Art. 13.8 | Fecha propuesta en [Supported versions](../../SECURITY.md#supported-versions). | Comprobar que el plazo cubre la fecha real de publicación y coincide con la política publicada. |
| 12 | Trazabilidad de cambios y revisión | Buena práctica del laboratorio | [Milestone del laboratorio](https://github.com/hutsebautvictor-star/reportaudit-lab/milestones) y [PR abiertos](https://github.com/hutsebautvictor-star/reportaudit-lab/pulls). Revisiones y cierres pendientes. | Seguir los enlaces Issue → PR, comprobar una aprobación del compañero y confirmar la fusión con los checks requeridos. |

La evaluación de riesgos, la documentación técnica para una eventual comercialización y la declaración UE de conformidad quedan fuera de este índice.
