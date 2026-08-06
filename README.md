# Ubuntu Security Triage

Script de triage local para Ubuntu. Reúne evidencias de seguridad sin modificar el sistema, sin descargar nada y sin abrir conexiones. Está pensado para dejar un informe ordenado que luego pueda revisar una persona.

## Qué hace

| Área | Qué revisa |
|---|---|
| Sistema | Fecha, kernel, red local, virtualización y contexto de ejecución |
| Usuarios | Cuentas, privilegios, `sudo`, `SSH` y accesos recientes |
| Red | Sockets, puertos en escucha, sesiones y reglas de firewall |
| Procesos | Ejecutables, rutas sospechosas, binarios borrados y uso alto |
| Persistencia | `cron`, `systemd`, perfiles, autostart y otros puntos comunes |
| Integridad | `dpkg`, `apt`, hashes y comandos básicos del sistema |
| Logs | `journalctl`, `auth.log`, `syslog`, `dpkg.log` y logs web |
| Kernel | Taint, `sysctl`, montajes, módulos y contenedores |

## Uso rápido

```bash
bash ubuntu_security_triage.sh
```

```bash
bash ubuntu_security_triage.sh --full --since-boot --output ./triage_resultado
```

## Opciones útiles

| Opción | Descripción |
|---|---|
| `--quick` | Modo rápido, es el valor por defecto |
| `--full` | Amplía el alcance y activa más comprobaciones |
| `--days N` | Revisa los últimos `N` días |
| `--since-boot` | Usa el último arranque como referencia temporal |
| `--include-home` | Incluye directorios personales |
| `--hash-files` | Calcula SHA-256 de candidatos dentro del límite |
| `--output DIR` | Guarda todo en un directorio nuevo |
| `--no-history` | Omite historiales de shell |
| `--no-package-verify` | Evita la verificación de paquetes más pesada |

También admite variables de entorno como `TRIAGE_DAYS`, `TRIAGE_INCLUDE_DIRS`, `TRIAGE_EXCLUDE_DIRS`, `TRIAGE_MAX_HASH_MB`, `TRIAGE_MAX_DEPTH` y `TRIAGE_COMMAND_TIMEOUT`.

## Salida

El script crea un directorio nuevo con varios informes. Los más importantes son:

| Archivo | Contenido |
|---|---|
| `resumen.txt` | Visión general, nivel de riesgo orientativo y pasos siguientes |
| `hallazgos.txt` | Hallazgos explicados en texto |
| `hallazgos.tsv` / `hallazgos.jsonl` | Los mismos hallazgos en formatos más fáciles de procesar |
| `sistema.txt`, `usuarios.txt`, `red.txt`, `procesos.txt` | Evidencia por área |
| `persistencia.txt`, `archivos_recientes.txt`, `integridad_paquetes.txt` | Zonas donde suele aparecer actividad sospechosa |
| `logs_relevantes.txt`, `kernel.txt`, `errores.txt` | Contexto, fallos y limitaciones |
| `manifest_sha256.txt` | Hashes de los informes generados |

## Notas

- Requiere Bash 4 o superior.
- Con root ve más información; sin root la cobertura es parcial.
- La redacción de secretos es heurística, no absoluta.
- El resumen sirve para priorizar revisión, no como veredicto final.
- No encontrar hallazgos no significa que el sistema esté limpio.