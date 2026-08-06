#!/usr/bin/env bash
# ubuntu_security_triage.sh
# Triage local, defensivo y no destructivo para sistemas Ubuntu.
# No confirma ni descarta por sí solo un compromiso: recopila evidencia,
# aplica heurísticas prudentes y correlaciona indicadores para revisión humana.

set -uo pipefail
umask 077
export LC_ALL=C

readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_NAME="${0##*/}"

# Variables configurables por entorno. Las listas usan ':' como separador.
TRIAGE_DAYS="${TRIAGE_DAYS:-7}"
TRIAGE_INCLUDE_DIRS="${TRIAGE_INCLUDE_DIRS:-/etc:/usr/local/bin:/usr/local/sbin:/opt:/boot:/lib:/usr/lib:/var/www:/srv/www}"
TRIAGE_EXCLUDE_DIRS="${TRIAGE_EXCLUDE_DIRS:-/proc:/sys:/dev:/run/user:/var/lib/docker/overlay2:/var/lib/containerd:/var/lib/snapd/snaps:/snap:/lost+found}"
TRIAGE_MAX_HASH_MB="${TRIAGE_MAX_HASH_MB:-50}"
TRIAGE_MAX_DEPTH="${TRIAGE_MAX_DEPTH:-8}"
TRIAGE_COMMAND_TIMEOUT="${TRIAGE_COMMAND_TIMEOUT:-120}"
TRIAGE_MAX_CAPTURE_MB="${TRIAGE_MAX_CAPTURE_MB:-20}"

MODE="quick"
DAYS="$TRIAGE_DAYS"
OUTPUT_DIR=""
OUTPUT_FIND_PATTERN=""
OUTPUT_EXPLICIT=0
INCLUDE_HOME=0
HASH_FILES=0
SINCE_BOOT=0
NO_HISTORY=0
NO_PACKAGE_VERIFY=0
MAX_HASH_MB="$TRIAGE_MAX_HASH_MB"
MAX_DEPTH="$TRIAGE_MAX_DEPTH"
COMMAND_TIMEOUT="$TRIAGE_COMMAND_TIMEOUT"
MAX_CAPTURE_MB="$TRIAGE_MAX_CAPTURE_MB"
MAX_FIND_RESULTS=2500
MAX_TOTAL_FILES=15000
MAX_LOG_LINES=800
ROOT_AVAILABLE=0
INTERRUPTED=0
TMP_DIR=""
START_EPOCH="$(date +%s 2>/dev/null || printf '0')"
BOOT_EPOCH=0
CUTOFF_EPOCH=0
CUTOFF_TEXT=""

declare -a INCLUDE_DIRS=()
declare -a EXCLUDE_DIRS=()
declare -a REPORT_FILES=(
  "resumen.txt" "hallazgos.txt" "hallazgos.tsv" "hallazgos.jsonl"
  "sistema.txt" "usuarios.txt" "red.txt" "procesos.txt"
  "persistencia.txt" "archivos_recientes.txt" "integridad_paquetes.txt"
  "logs_relevantes.txt" "kernel.txt" "errores.txt"
)
declare -a LIMITATIONS=()
declare -A SEVERITY_COUNT=(
  [INFORMATIVO]=0 [BAJO]=0 [MEDIO]=0 [ALTO]=0 [CRÍTICO]=0
)
declare -A SIGNALS=()
declare -A SIGNAL_EVIDENCE=()
declare -A SIGNAL_ENTITIES=()
declare -A FINDING_DEDUP=()
declare -A PACKAGE_CACHE=()
declare -A KEY_USERS=()
declare -A SEEN_RECENT=()

FINDING_SEQ=0
SCORE_RAW=0
AUTH_PREPARED=0
DPKG_PATH_QUERY_USABLE=-1
TOTAL_FILES_INSPECTED=0
FILE_LIMIT_REPORTED=0

show_help() {
  cat <<'EOF'
Uso:
  ubuntu_security_triage.sh [opciones]

Opciones principales:
  --days N                 Revisar los últimos N días (predeterminado: 7).
  --output DIRECTORIO      Directorio nuevo para los resultados.
  --quick                  Modo rápido (predeterminado).
  --full                   Modo completo; amplía archivos, paquetes y hogares.
  --include-home           Incluir persistencia y archivos de directorios personales.
  --hash-files             Calcular SHA-256 de candidatos dentro del límite de tamaño.
  --since-boot             Usar el último arranque como inicio temporal principal.
  --no-history             No analizar historiales de shells.
  --no-package-verify      Omitir dpkg --verify/debsums en modo completo.

Opciones de control adicionales:
  --include DIRECTORIO     Añadir una raíz de búsqueda (repetible).
  --exclude DIRECTORIO     Añadir una exclusión (repetible).
  --max-hash-mb N          Tamaño máximo por archivo para SHA-256.
  --max-depth N            Profundidad máxima en raíces de búsqueda dirigidas.
  --command-timeout N      Límite habitual por comando, en segundos.
  -h, --help               Mostrar esta ayuda.

Variables de entorno equivalentes:
  TRIAGE_DAYS, TRIAGE_INCLUDE_DIRS, TRIAGE_EXCLUDE_DIRS,
  TRIAGE_MAX_HASH_MB, TRIAGE_MAX_DEPTH, TRIAGE_COMMAND_TIMEOUT,
  TRIAGE_MAX_CAPTURE_MB.

El script no realiza conexiones de red, no descarga software y no modifica
la configuración, procesos, cuentas, archivos examinados ni reglas de red.
EOF
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 2
}

is_uint() {
  [[ "${1:-}" =~ ^[0-9]+$ ]]
}

redact_stream() {
  # Redacción heurística: evita los secretos con formato reconocible sin
  # convertir la salida en una falsa garantía de ausencia de datos sensibles.
  sed -E \
    -e 's#([A-Za-z][A-Za-z0-9+.-]*://)[^/@[:space:]]+:[^/@[:space:]]+@#\1[credenciales_redactadas]@#g' \
    -e 's#([?&][A-Za-z0-9_.-]+=)[^&[:space:]\"]+#\1[VALOR_REDACTADO]#g' \
    -e 's/((pass(word|wd)?|token|secret|api[_-]?key|client[_-]?secret|authorization|cookie|session|credential|private[_-]?key)[[:space:]]*[:=][[:space:]]*)[^[:space:],;]+/\1[REDACTADO]/Ig' \
    -e 's/((--?(password|passwd|token|secret|api-key|apikey|authorization|cookie))[=[:space:]]+)[^[:space:]]+/\1[REDACTADO]/Ig' \
    -e 's/((AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|GITLAB_TOKEN|PGPASSWORD|MYSQL_PWD|OPENAI_API_KEY)[=[:space:]]+)[^[:space:]]+/\1[REDACTADO]/Ig' \
    -e 's/((sshpass[[:space:]]+-p|curl[[:space:]].*(-u|--user))[=[:space:]]+)[^[:space:]]+/\1[REDACTADO]/Ig' \
    -e 's/((mysql|mariadb)[[:space:]].*)-p[^[:space:]]+/\1-p[REDACTADO]/Ig' \
    -e 's/(Bearer|Basic)[[:space:]]+[A-Za-z0-9+\/.=_-]+/\1 [REDACTADO]/Ig' \
    -e 's/[A-Za-z0-9+\/]{120,}={0,2}/[CADENA_LARGA_REDACTADA]/g'
}

sanitize_inline() {
  printf '%s' "${1:-}" \
    | redact_stream \
    | tr '\000-\010\013\014\016-\037\177' '?' \
    | tr '\t\r\n' '   ' \
    | cut -c1-1800
}

safe_path() {
  local p="${1:-}"
  printf '%q' "$p" | cut -c1-1000
}

json_escape() {
  local s
  s="$(sanitize_inline "${1:-}")"
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  printf '%s' "$s"
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

local_username_by_uid() {
  local uid="$1"
  awk -F: -v wanted="$uid" '$3==wanted {print $1; exit}' /etc/passwd 2>/dev/null
}

find_pattern_escape() {
  # Escapa metacaracteres que GNU find interpreta en -path.
  local s="$1"
  s=${s//\\/\\\\}
  s=${s//\*/\\*}
  s=${s//\?/\\?}
  s=${s//\[/\\[}
  printf '%s' "$s"
}

iso_now() {
  date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z'
}

add_limitation() {
  local text
  text="$(sanitize_inline "$1")"
  LIMITATIONS+=("$text")
}

cleanup() {
  # Solo elimina el directorio mktemp creado por este proceso dentro de OUTPUT_DIR.
  case "${TMP_DIR:-}" in
    "${OUTPUT_DIR:-}"/.tmp.*)
      [[ -d "$TMP_DIR" ]] && rm -rf -- "$TMP_DIR"
      ;;
  esac
}

on_signal() {
  INTERRUPTED=1
  printf '\nAnálisis interrumpido; se conservan los informes parciales.\n' >&2
  cleanup
  exit 130
}

trap cleanup EXIT
trap on_signal INT TERM HUP

parse_args() {
  local arg
  while (($#)); do
    arg="$1"
    case "$arg" in
      --days)
        (($# >= 2)) || die "Falta el valor de --days"
        DAYS="$2"; shift 2 ;;
      --output)
        (($# >= 2)) || die "Falta el valor de --output"
        OUTPUT_DIR="$2"; OUTPUT_EXPLICIT=1; shift 2 ;;
      --quick)
        MODE="quick"; shift ;;
      --full)
        MODE="full"; shift ;;
      --include-home)
        INCLUDE_HOME=1; shift ;;
      --hash-files)
        HASH_FILES=1; shift ;;
      --since-boot)
        SINCE_BOOT=1; shift ;;
      --no-history)
        NO_HISTORY=1; shift ;;
      --no-package-verify)
        NO_PACKAGE_VERIFY=1; shift ;;
      --include)
        (($# >= 2)) || die "Falta el valor de --include"
        INCLUDE_DIRS+=("$2"); shift 2 ;;
      --exclude)
        (($# >= 2)) || die "Falta el valor de --exclude"
        EXCLUDE_DIRS+=("$2"); shift 2 ;;
      --max-hash-mb)
        (($# >= 2)) || die "Falta el valor de --max-hash-mb"
        MAX_HASH_MB="$2"; shift 2 ;;
      --max-depth)
        (($# >= 2)) || die "Falta el valor de --max-depth"
        MAX_DEPTH="$2"; shift 2 ;;
      --command-timeout)
        (($# >= 2)) || die "Falta el valor de --command-timeout"
        COMMAND_TIMEOUT="$2"; shift 2 ;;
      -h|--help)
        show_help; exit 0 ;;
      --)
        shift
        (($# == 0)) || die "No se admiten argumentos posicionales"
        ;;
      *)
        die "Opción desconocida: $arg" ;;
    esac
  done
}

validate_configuration() {
  ((BASH_VERSINFO[0] >= 4)) || die "Se requiere Bash 4 o posterior"
  is_uint "$DAYS" && ((DAYS <= 3650)) || die "--days debe ser un entero entre 0 y 3650"
  is_uint "$MAX_HASH_MB" && ((MAX_HASH_MB <= 10240)) || die "--max-hash-mb debe ser un entero entre 0 y 10240"
  is_uint "$MAX_DEPTH" && ((MAX_DEPTH >= 1 && MAX_DEPTH <= 64)) || die "--max-depth debe estar entre 1 y 64"
  is_uint "$COMMAND_TIMEOUT" && ((COMMAND_TIMEOUT >= 5 && COMMAND_TIMEOUT <= 3600)) || die "--command-timeout debe estar entre 5 y 3600"
  is_uint "$MAX_CAPTURE_MB" && ((MAX_CAPTURE_MB >= 1 && MAX_CAPTURE_MB <= 500)) || die "TRIAGE_MAX_CAPTURE_MB debe estar entre 1 y 500"

  local -a env_includes=() env_excludes=()
  IFS=':' read -r -a env_includes <<< "$TRIAGE_INCLUDE_DIRS"
  IFS=':' read -r -a env_excludes <<< "$TRIAGE_EXCLUDE_DIRS"
  INCLUDE_DIRS=("${env_includes[@]}" "${INCLUDE_DIRS[@]}")
  EXCLUDE_DIRS=("${env_excludes[@]}" "${EXCLUDE_DIRS[@]}")

  if [[ "$MODE" == "full" ]]; then
    INCLUDE_HOME=1
    HASH_FILES=1
    MAX_FIND_RESULTS=12000
    MAX_TOTAL_FILES=100000
    MAX_LOG_LINES=4000
  fi

  local p
  for p in "${INCLUDE_DIRS[@]}" "${EXCLUDE_DIRS[@]}"; do
    [[ -z "$p" || "$p" == /* ]] || die "Las rutas incluidas/excluidas deben ser absolutas: $p"
  done
  [[ "$OUTPUT_DIR" != *$'\n'* && "$OUTPUT_DIR" != *$'\r'* ]] || die "El directorio de salida no puede contener saltos de línea"
}

initialize_output() {
  local host_raw host_safe stamp parent free_kb min_kb base
  host_raw="$(hostname 2>/dev/null || printf 'desconocido')"
  host_safe="$(printf '%s' "$host_raw" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-80)"
  stamp="$(date '+%Y%m%d_%H%M%S' 2>/dev/null || printf '%s' "$START_EPOCH")"

  if ((OUTPUT_EXPLICIT == 0)); then
    OUTPUT_DIR="ubuntu_security_triage_${stamp}_${host_safe}"
    if [[ -e "$OUTPUT_DIR" ]]; then
      OUTPUT_DIR="${OUTPUT_DIR}_$$"
    fi
  fi

  [[ -n "$OUTPUT_DIR" ]] || die "Directorio de salida vacío"
  [[ ! -e "$OUTPUT_DIR" ]] || die "El directorio de salida ya existe; no se sobrescribirá: $OUTPUT_DIR"
  parent="$(dirname -- "$OUTPUT_DIR")"
  base="$(basename -- "$OUTPUT_DIR")"
  mkdir -p -- "$parent" || die "No se puede crear el directorio padre: $parent"

  free_kb="$(df -Pk -- "$parent" 2>/dev/null | awk 'NR==2 {print $4}')"
  min_kb=51200
  [[ "$MODE" == "full" ]] && min_kb=204800
  if is_uint "$free_kb"; then
    ((free_kb >= 10240)) || die "Menos de 10 MiB libres; se cancela para no agotar el disco"
  fi

  mkdir -m 700 -- "$OUTPUT_DIR" || die "No se puede crear: $OUTPUT_DIR"
  OUTPUT_DIR="$(cd -- "$parent" 2>/dev/null && printf '%s/%s' "$(pwd -P)" "$base")"
  OUTPUT_FIND_PATTERN="$(find_pattern_escape "$OUTPUT_DIR")"
  chmod 700 -- "$OUTPUT_DIR" 2>/dev/null || true
  TMP_DIR="$(mktemp -d "$OUTPUT_DIR/.tmp.XXXXXX")" || die "mktemp falló"
  chmod 700 -- "$TMP_DIR" 2>/dev/null || true

  local report
  for report in "${REPORT_FILES[@]}"; do
    : > "$OUTPUT_DIR/$report" || die "No se puede crear $report"
    chmod 600 -- "$OUTPUT_DIR/$report" 2>/dev/null || true
  done

  if is_uint "$free_kb" && ((free_kb < min_kb)); then
    printf '%s\tESPACIO\tEspacio libre inferior al umbral recomendado: %s KiB\n' "$(iso_now)" "$free_kb" >> "$OUTPUT_DIR/errores.txt"
    add_limitation "Espacio libre inferior al umbral recomendado; algunas capturas podrían truncarse."
  elif ! is_uint "$free_kb"; then
    printf '%s\tESPACIO\tNo se pudo determinar el espacio libre.\n' "$(iso_now)" >> "$OUTPUT_DIR/errores.txt"
  fi

  printf 'id\tcategoria\tseveridad\tfecha_hora\tdescripcion\tevidencia\trelevancia\texplicaciones_legitimas\trecomendacion\tconfianza\n' > "$OUTPUT_DIR/hallazgos.tsv"
  printf 'HALLAZGOS DE SEGURIDAD - Ubuntu Security Triage %s\n' "$SCRIPT_VERSION" > "$OUTPUT_DIR/hallazgos.txt"
  printf 'La ausencia de hallazgos no demuestra ausencia de compromiso.\n\n' >> "$OUTPUT_DIR/hallazgos.txt"

  printf 'Ubuntu Security Triage %s\n' "$SCRIPT_VERSION" > "$OUTPUT_DIR/sistema.txt"
  printf 'Modo: %s | inicio: %s | cutoff: pendiente\n\n' "$MODE" "$(iso_now)" >> "$OUTPUT_DIR/sistema.txt"
  printf 'Evidencia de usuarios, grupos y acceso\n\n' > "$OUTPUT_DIR/usuarios.txt"
  printf 'Evidencia de red y SSH\n\n' > "$OUTPUT_DIR/red.txt"
  printf 'Evidencia de procesos\n\n' > "$OUTPUT_DIR/procesos.txt"
  printf 'Evidencia de persistencia\n\n' > "$OUTPUT_DIR/persistencia.txt"
  printf 'Evidencia de archivos recientes y candidatos\n\n' > "$OUTPUT_DIR/archivos_recientes.txt"
  printf 'Integridad local y paquetes\n\n' > "$OUTPUT_DIR/integridad_paquetes.txt"
  printf 'Fragmentos relevantes de logs (volumen limitado)\n\n' > "$OUTPUT_DIR/logs_relevantes.txt"
  printf 'Kernel, módulos, montajes y contenedores\n\n' > "$OUTPUT_DIR/kernel.txt"

  ROOT_AVAILABLE=0
  [[ "$(id -u 2>/dev/null || printf '1')" == "0" ]] && ROOT_AVAILABLE=1

  BOOT_EPOCH="$(awk '$1=="btime" {print $2}' /proc/stat 2>/dev/null | head -n 1)"
  is_uint "$BOOT_EPOCH" || BOOT_EPOCH=0
  if ((SINCE_BOOT == 1 && BOOT_EPOCH > 0)); then
    CUTOFF_EPOCH="$BOOT_EPOCH"
  else
    CUTOFF_EPOCH="$(date -d "$DAYS days ago" +%s 2>/dev/null || printf '0')"
  fi
  is_uint "$CUTOFF_EPOCH" || CUTOFF_EPOCH=0
  CUTOFF_TEXT="$(date -d "@$CUTOFF_EPOCH" '+%Y-%m-%d %H:%M:%S %z' 2>/dev/null || printf 'desconocido')"
  printf 'Ventana temporal principal desde: %s\n' "$CUTOFF_TEXT" >> "$OUTPUT_DIR/sistema.txt"

  # Inicializar esta capacidad en el shell principal. package_owner suele
  # invocarse en sustituciones de comando, cuyos cambios globales no persisten.
  package_owner /bin/sh >/dev/null 2>&1 || true
  if ((DPKG_PATH_QUERY_USABLE == 0)); then
    add_limitation "La base dpkg no permite atribuir rutas en este entorno; se evita clasificar binarios como 'sin paquete' por esa sola razón."
  fi
}

log_error() {
  local context="$(sanitize_inline "${1:-sin_contexto}")"
  local rc="${2:-1}"
  local detail="$(sanitize_inline "${3:-sin_detalle}")"
  printf '%s\t%s\trc=%s\t%s\n' "$(iso_now)" "$context" "$rc" "$detail" >> "$OUTPUT_DIR/errores.txt"
}

run_limited() {
  # run_limited DESTINO ETIQUETA MAX_LINEAS SEGUNDOS COMANDO [ARGS...]
  local dest="$1" label="$2" max_lines="$3" seconds="$4"
  shift 4
  local errfile rc errtext
  errfile="$(mktemp "$TMP_DIR/cmd_err.XXXXXX")" || return 0
  printf '\n===== %s =====\n' "$label" >> "$dest"

  if have_cmd timeout; then
    timeout --signal=TERM --kill-after=5s "${seconds}s" "$@" 2>"$errfile" \
      | redact_stream \
      | awk -v max="$max_lines" 'NR<=max {print} END {if (NR>max) print "[salida truncada: " NR " líneas totales]"}' \
      >> "$dest"
    rc=${PIPESTATUS[0]}
  else
    "$@" 2>"$errfile" \
      | redact_stream \
      | awk -v max="$max_lines" 'NR<=max {print} END {if (NR>max) print "[salida truncada: " NR " líneas totales]"}' \
      >> "$dest"
    rc=${PIPESTATUS[0]}
  fi
  if ((rc != 0)); then
    errtext="$(redact_stream < "$errfile" | head -n 5 | tr '\n' ' ')"
    log_error "$label" "$rc" "${errtext:-comando sin detalle de error}"
    printf '[comando no completado: rc=%s; consulte errores.txt]\n' "$rc" >> "$dest"
  fi
  rm -f -- "$errfile"
  return 0
}

run_optional() {
  # run_optional DESTINO ETIQUETA MAX_LINEAS SEGUNDOS COMANDO [ARGS...]
  local dest="$1" label="$2" lines="$3" seconds="$4" cmd="$5"
  shift 5
  if have_cmd "$cmd"; then
    run_limited "$dest" "$label" "$lines" "$seconds" "$cmd" "$@"
  else
    printf '\n===== %s =====\n[comando no instalado: %s]\n' "$label" "$cmd" >> "$dest"
    add_limitation "$label: el comando opcional '$cmd' no está instalado."
  fi
}

capture_bounded() {
  # capture_bounded SALIDA CONTEXTO SEGUNDOS COMANDO [ARGS...]
  local outfile="$1" context="$2" seconds="$3"
  shift 3
  local errfile rc max_bytes errtext actual_bytes
  errfile="$(mktemp "$TMP_DIR/capture_err.XXXXXX")" || return 1
  max_bytes=$((MAX_CAPTURE_MB * 1024 * 1024))
  : > "$outfile"
  if have_cmd timeout; then
    timeout --signal=TERM --kill-after=5s "${seconds}s" "$@" 2>"$errfile" | head -c "$max_bytes" > "$outfile"
    rc=${PIPESTATUS[0]}
  else
    "$@" 2>"$errfile" | head -c "$max_bytes" > "$outfile"
    rc=${PIPESTATUS[0]}
  fi
  if ((rc != 0 && rc != 141)); then
    errtext="$(redact_stream < "$errfile" | head -n 5 | tr '\n' ' ')"
    log_error "$context" "$rc" "${errtext:-captura incompleta}"
  fi
  actual_bytes="$(stat -c '%s' -- "$outfile" 2>/dev/null || printf '0')"
  if is_uint "$actual_bytes" && ((actual_bytes >= max_bytes)); then
    log_error "$context" "TRUNCADA" "Captura limitada a ${MAX_CAPTURE_MB} MiB"
    add_limitation "$context: captura truncada al límite de ${MAX_CAPTURE_MB} MiB."
  fi
  rm -f -- "$errfile"
  chmod 600 -- "$outfile" 2>/dev/null || true
  return 0
}

severity_weight() {
  case "$1" in
    INFORMATIVO) printf '0' ;;
    BAJO) printf '1' ;;
    MEDIO) printf '3' ;;
    ALTO) printf '10' ;;
    CRÍTICO) printf '25' ;;
    *) printf '0' ;;
  esac
}

add_finding() {
  # PREFIJO CATEGORIA SEVERIDAD DESCRIPCION EVIDENCIA RELEVANCIA LEGITIMO RECOMENDACION CONFIANZA
  local prefix="$1" category="$2" severity="$3" description="$4" evidence="$5"
  local relevance="$6" legitimate="$7" recommendation="$8" confidence="$9"
  local finding_id timestamp weight
  case "$severity" in
    INFORMATIVO|BAJO|MEDIO|ALTO|CRÍTICO) ;;
    *) severity="INFORMATIVO" ;;
  esac
  case "$confidence" in
    baja|media|alta) ;;
    *) confidence="baja" ;;
  esac

  FINDING_SEQ=$((FINDING_SEQ + 1))
  finding_id="$(sanitize_inline "$prefix")-$(printf '%04d' "$FINDING_SEQ")"
  timestamp="$(iso_now)"
  description="$(sanitize_inline "$description")"
  evidence="$(sanitize_inline "$evidence")"
  relevance="$(sanitize_inline "$relevance")"
  legitimate="$(sanitize_inline "$legitimate")"
  recommendation="$(sanitize_inline "$recommendation")"
  category="$(sanitize_inline "$category")"

  SEVERITY_COUNT[$severity]=$(( ${SEVERITY_COUNT[$severity]:-0} + 1 ))
  weight="$(severity_weight "$severity")"
  SCORE_RAW=$((SCORE_RAW + weight))

  {
    printf '[%s] %s | %s | %s | confianza=%s\n' "$finding_id" "$severity" "$category" "$timestamp" "$confidence"
    printf 'Descripción: %s\n' "$description"
    printf 'Evidencia: %s\n' "$evidence"
    printf 'Relevancia: %s\n' "$relevance"
    printf 'Explicaciones legítimas: %s\n' "$legitimate"
    printf 'Verificación recomendada: %s\n\n' "$recommendation"
  } >> "$OUTPUT_DIR/hallazgos.txt"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$finding_id" "$category" "$severity" "$timestamp" "$description" "$evidence" \
    "$relevance" "$legitimate" "$recommendation" "$confidence" \
    >> "$OUTPUT_DIR/hallazgos.tsv"

  printf '{"id":"%s","categoria":"%s","severidad":"%s","fecha_hora":"%s","descripcion":"%s","evidencia":"%s","relevancia":"%s","explicaciones_legitimas":"%s","recomendacion":"%s","confianza":"%s"}\n' \
    "$(json_escape "$finding_id")" "$(json_escape "$category")" "$(json_escape "$severity")" \
    "$(json_escape "$timestamp")" "$(json_escape "$description")" "$(json_escape "$evidence")" \
    "$(json_escape "$relevance")" "$(json_escape "$legitimate")" \
    "$(json_escape "$recommendation")" "$(json_escape "$confidence")" \
    >> "$OUTPUT_DIR/hallazgos.jsonl"
}

add_finding_once() {
  local key="$1"
  shift
  [[ -z "${FINDING_DEDUP[$key]:-}" ]] || return 0
  FINDING_DEDUP[$key]=1
  add_finding "$@"
}

record_signal() {
  local entity="$(sanitize_inline "${1:-}")" signal="$(sanitize_inline "${2:-}")" evidence
  local key
  evidence="$(sanitize_inline "${3:-}")"
  [[ -n "$entity" && -n "$signal" ]] || return 0
  key="${entity}"$'\037'"${signal}"
  SIGNALS[$key]=1
  SIGNAL_EVIDENCE[$key]="$evidence"
  SIGNAL_ENTITIES[$entity]=1
}

has_signal() {
  local key="${1}"$'\037'"${2}"
  [[ "${SIGNALS[$key]:-0}" == "1" ]]
}

signal_evidence() {
  local key="${1}"$'\037'"${2}"
  printf '%s' "${SIGNAL_EVIDENCE[$key]:-}"
}

file_is_recent() {
  local epoch
  epoch="$(stat -c '%Y' -- "$1" 2>/dev/null || printf '0')"
  is_uint "$epoch" && ((epoch >= CUTOFF_EPOCH))
}

file_metadata() {
  local p="$1"
  stat -c 'ruta=%n tipo=%F modo=%A(%a) uid=%u usuario=%U gid=%g grupo=%G tamano=%s mtime=%y ctime=%z' -- "$p" 2>/dev/null \
    | redact_stream \
    | cut -c1-1600
}

describe_file() {
  if have_cmd file; then
    file -b -- "$1" 2>/dev/null | head -c "${2:-500}"
  else
    printf 'tipo no disponible (comando file ausente)'
  fi
}

package_owner() {
  local path="$1" result=""
  if [[ -n "${PACKAGE_CACHE[$path]+x}" ]]; then
    printf '%s' "${PACKAGE_CACHE[$path]}"
    return 0
  fi
  if ((DPKG_PATH_QUERY_USABLE < 0)); then
    DPKG_PATH_QUERY_USABLE=0
    if have_cmd dpkg-query; then
      local sample
      sample="$(dpkg-query -L dpkg 2>/dev/null | while IFS= read -r p; do [[ -f "$p" ]] && { printf '%s' "$p"; break; }; done)"
      if [[ -n "$sample" ]] && dpkg-query -S "$sample" >/dev/null 2>&1; then
        DPKG_PATH_QUERY_USABLE=1
      fi
    fi
  fi
  if ((DPKG_PATH_QUERY_USABLE == 1)); then
    local query_path alt=""
    query_path="$path"
    result="$(dpkg-query -S "$query_path" 2>/dev/null | head -n 1)"
    if [[ -z "$result" ]]; then
      case "$query_path" in
        /usr/bin/*) alt="/${query_path#/usr/}" ;;
        /usr/sbin/*) alt="/${query_path#/usr/}" ;;
        /usr/lib/*) alt="/${query_path#/usr/}" ;;
        /bin/*|/sbin/*|/lib/*) alt="/usr$query_path" ;;
      esac
      [[ -n "$alt" ]] && result="$(dpkg-query -S "$alt" 2>/dev/null | head -n 1)"
    fi
    result="${result%%:*}"
  fi
  if [[ -z "$result" ]]; then
    case "$path" in
      /snap/*) result="snap" ;;
      /var/lib/flatpak/*|/home/*/.local/share/flatpak/*) result="flatpak" ;;
      *)
        if ((DPKG_PATH_QUERY_USABLE == 1)); then result="sin-paquete-dpkg"; else result="dpkg-no-verificable"; fi
        ;;
    esac
  fi
  PACKAGE_CACHE[$path]="$result"
  printf '%s' "$result"
}

is_public_ip() {
  local ip="${1#[}" a b
  ip="${ip%]}"
  ip="${ip%%%*}"
  [[ -n "$ip" ]] || return 1
  if [[ "$ip" == *:* ]]; then
    local low="${ip,,}"
    [[ "$low" == "::1" || "$low" == "::" || "$low" == fe8* || "$low" == fe9* || "$low" == fea* || "$low" == feb* || "$low" == fc* || "$low" == fd* ]] && return 1
    return 0
  fi
  [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  a="${BASH_REMATCH[1]}"; b="${BASH_REMATCH[2]}"
  ((a <= 255 && b <= 255 && BASH_REMATCH[3] <= 255 && BASH_REMATCH[4] <= 255)) || return 1
  ((a == 10 || a == 127 || a == 0 || (a == 169 && b == 254) || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) || (a == 100 && b >= 64 && b <= 127) || a >= 224)) && return 1
  return 0
}

endpoint_host() {
  local ep="$1" host
  host="${ep%:*}"
  host="${host#[}"
  host="${host%]}"
  host="${host%%%*}"
  printf '%s' "$host"
}

endpoint_port() {
  local ep="$1"
  printf '%s' "${ep##*:}"
}

pid_from_ss_line() {
  sed -nE 's/.*pid=([0-9]+).*/\1/p' <<< "$1" | head -n 1
}

proc_name_from_ss_line() {
  sed -nE 's/.*users:\(\(\"([^\"]+)\".*/\1/p' <<< "$1" | head -n 1
}

known_service_port() {
  case "$1" in
    22|25|53|67|68|80|110|111|123|137|138|139|143|161|389|443|445|465|514|587|631|636|853|993|995|2049|2375|2376|3000|3128|3306|3389|5000|5432|5672|5900|6379|6443|8000|8080|8081|8443|8888|9000|9090|9100|9200|9300|9418|27017) return 0 ;;
    *) return 1 ;;
  esac
}

parse_args "$@"
validate_configuration
initialize_output

collect_system_info() {
  local out="$OUTPUT_DIR/sistema.txt" sb_state="desconocido" aa_state="desconocido" fw_state="desconocido"
  local os_id=""
  os_id="$(sed -nE 's/^ID=\"?([^\"]+)\"?$/\1/p' /etc/os-release 2>/dev/null | head -n 1)"
  if [[ -n "$os_id" && "$os_id" != "ubuntu" ]]; then
    add_limitation "El sistema declara ID=$os_id; el script está diseñado y validado para Ubuntu y derivados systemd/dpkg."
  fi
  {
    printf '\n===== IDENTIDAD Y TIEMPO =====\n'
    printf 'Fecha local: '; date '+%Y-%m-%d %H:%M:%S %z (%Z)' 2>/dev/null || true
    printf 'Fecha UTC: '; date -u '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null || true
    printf 'Zona horaria: '
    if have_cmd timedatectl; then
      timedatectl show -p Timezone --value 2>/dev/null || true
    else
      readlink /etc/localtime 2>/dev/null || printf 'no disponible\n'
    fi
    printf 'Hostname: '; hostname 2>/dev/null || true
    local invoking_uid
    invoking_uid="$(id -ru 2>/dev/null || printf '?')"
    printf 'Usuario invocador: uid=%s nombre_local=%s euid=%s\n' "$invoking_uid" "$(local_username_by_uid "$invoking_uid")" "$(id -u 2>/dev/null || printf '?')"
    printf 'Privilegios root: %s\n' "$([[ "$ROOT_AVAILABLE" == 1 ]] && printf 'sí' || printf 'no')"
    printf 'Kernel: '; uname -a 2>/dev/null || true
    printf 'Uptime: '; uptime -p 2>/dev/null || uptime 2>/dev/null || true
    printf 'Inicio estimado: '; uptime -s 2>/dev/null || true
    printf 'Último arranque (who): '; who -b 2>/dev/null || true
    printf '\n/etc/os-release:\n'
    if [[ -r /etc/os-release ]]; then
      grep -E '^(NAME|VERSION|VERSION_ID|VERSION_CODENAME|UBUNTU_CODENAME|PRETTY_NAME)=' /etc/os-release 2>/dev/null || true
    fi
  } | redact_stream >> "$out"

  run_optional "$out" "hostnamectl" 120 20 hostnamectl
  run_optional "$out" "Virtualización" 80 20 systemd-detect-virt

  {
    printf '\n===== RED LOCAL BÁSICA =====\n'
    printf 'Direcciones locales (hostname -I): '
    hostname -I 2>/dev/null || printf 'no disponible\n'
  } | redact_stream >> "$out"
  run_optional "$out" "Interfaces (ip -brief address)" 300 30 ip -brief address show
  run_optional "$out" "Rutas principales" 300 30 ip route show table all

  if have_cmd resolvectl; then
    run_limited "$out" "DNS mediante resolvectl" 350 30 resolvectl status
  elif have_cmd systemd-resolve; then
    run_limited "$out" "DNS mediante systemd-resolve" 350 30 systemd-resolve --status
  fi
  {
    printf '\n===== /etc/resolv.conf (solo directivas no secretas) =====\n'
    ls -l -- /etc/resolv.conf 2>/dev/null || true
    if [[ -r /etc/resolv.conf ]]; then
      grep -E '^[[:space:]]*(nameserver|search|domain|options)[[:space:]]' /etc/resolv.conf 2>/dev/null | head -n 100 || true
    fi
  } | redact_stream >> "$out"

  if have_cmd mokutil; then
    sb_state="$(mokutil --sb-state 2>/dev/null | head -n 1)"
    printf '\n===== SECURE BOOT =====\n%s\n' "$(sanitize_inline "$sb_state")" >> "$out"
  elif [[ -d /sys/firmware/efi/efivars ]] && have_cmd od; then
    local sb_file=""
    sb_file="$(find /sys/firmware/efi/efivars -maxdepth 1 -type f -name 'SecureBoot-*' -print -quit 2>/dev/null)"
    if [[ -n "$sb_file" && -r "$sb_file" ]]; then
      local sb_byte
      sb_byte="$(od -An -t u1 -j 4 -N 1 -- "$sb_file" 2>/dev/null | tr -d ' ')"
      [[ "$sb_byte" == "1" ]] && sb_state="enabled (efivar)" || sb_state="disabled/unknown (efivar=$sb_byte)"
    fi
    printf '\n===== SECURE BOOT =====\n%s\n' "$sb_state" >> "$out"
  else
    printf '\n===== SECURE BOOT =====\nNo determinable sin mokutil/EFI.\n' >> "$out"
    add_limitation "Secure Boot no se pudo determinar (mokutil no disponible o sistema sin EFI visible)."
  fi

  if have_cmd aa-status; then
    aa_state="$(aa-status --enabled >/dev/null 2>&1 && printf 'enabled' || printf 'disabled-or-unavailable')"
    run_limited "$out" "Estado de AppArmor" 250 30 aa-status
  elif have_cmd apparmor_status; then
    aa_state="$(apparmor_status --enabled >/dev/null 2>&1 && printf 'enabled' || printf 'disabled-or-unavailable')"
    run_limited "$out" "Estado de AppArmor" 250 30 apparmor_status
  else
    printf '\n===== APPARMOR =====\nHerramienta de estado no instalada.\n' >> "$out"
    add_limitation "No se pudo obtener el detalle de perfiles AppArmor."
  fi

  if have_cmd ufw; then
    fw_state="$(ufw status 2>/dev/null | head -n 1)"
    run_limited "$out" "Estado de UFW" 350 40 ufw status verbose
  elif have_cmd nft; then
    fw_state="nftables disponible"
    run_limited "$out" "Resumen nftables" 500 40 nft list ruleset
  elif have_cmd iptables; then
    fw_state="iptables disponible"
    run_limited "$out" "Reglas iptables" 500 40 iptables -S
  else
    fw_state="no se detectó utilidad de firewall"
    add_limitation "No se encontró ufw, nft ni iptables para revisar el cortafuegos."
  fi

  add_finding "SYS" "Sistema" "INFORMATIVO" \
    "Contexto de ejecución registrado" \
    "modo=$MODE; root=$ROOT_AVAILABLE; ventana_desde=$CUTOFF_TEXT; secure_boot=$(sanitize_inline "$sb_state"); apparmor=$(sanitize_inline "$aa_state"); firewall=$(sanitize_inline "$fw_state")" \
    "Define el alcance y las protecciones observables del análisis." \
    "La ausencia de una utilidad de consulta no implica que la protección esté desactivada." \
    "Interpretar todos los hallazgos teniendo en cuenta este contexto y los errores de permisos." "alta"

  if ((ROOT_AVAILABLE == 0)); then
    add_finding "SYS" "Cobertura" "BAJO" \
      "Análisis ejecutado sin privilegios root" \
      "euid=$(id -u 2>/dev/null || printf '?')" \
      "Sin root no se ven todos los argumentos, sockets, crontabs, shadow, logs ni metadatos." \
      "Puede ser una decisión deliberada de mínimo privilegio." \
      "Repetir con sudo desde una cuenta administrativa confiable y comparar los informes." "alta"
    add_limitation "Ejecución sin root: visibilidad incompleta de procesos, sockets, cuentas, logs y persistencia."
  fi

  case "${aa_state,,}" in
    disabled*|*not*enabled*)
      add_finding_once "apparmor-disabled" "SYS" "Protecciones" "BAJO" \
        "AppArmor no aparece habilitado" "$aa_state" \
        "Reduce una capa de confinamiento; no es por sí mismo evidencia de intrusión." \
        "Puede estar desactivado por compatibilidad, contenedor o política del administrador." \
        "Confirmar el estado esperado con systemctl y la política de endurecimiento." "media" ;;
  esac
  if [[ "${fw_state,,}" == *inactive* || "${fw_state,,}" == *"no se detectó"* ]]; then
    add_finding_once "firewall-inactive" "SYS" "Protecciones" "BAJO" \
      "No se confirmó un cortafuegos de host activo" "$fw_state" \
      "Un servicio expuesto puede quedar accesible según la red y controles perimetrales." \
      "Puede existir filtrado en un router, hipervisor, proveedor cloud u otra herramienta." \
      "Verificar nftables/iptables, controles de red externos y la exposición real de cada servicio." "media"
  fi
}

prepare_auth_events() {
  ((AUTH_PREPARED == 0)) || return 0
  AUTH_PREPARED=1
  local raw="$TMP_DIR/auth_events.raw"
  : > "$raw"

  if [[ -r /var/log/auth.log ]]; then
    tail -n 12000 /var/log/auth.log 2>/dev/null \
      | grep -Eai 'sshd|sudo|su:|useradd|new user|authentication failure|session opened|session closed' \
      | tail -n 7000 >> "$raw" || true
  fi
  if [[ "$MODE" == "full" ]] && have_cmd zgrep; then
    local f
    for f in /var/log/auth.log.*.gz; do
      [[ -r "$f" ]] || continue
      zgrep -Eai 'sshd|sudo|su:|useradd|new user|authentication failure' "$f" 2>/dev/null | tail -n 1000 >> "$raw" || true
    done
  fi
  if have_cmd journalctl; then
    if ((SINCE_BOOT == 1)); then
      journalctl -b --no-pager -o short-iso 2>/dev/null \
        | grep -Eai 'sshd|sudo|su:|useradd|new user|authentication failure' \
        | tail -n 7000 >> "$raw" || true
    else
      journalctl --since "$DAYS days ago" --no-pager -o short-iso 2>/dev/null \
        | grep -Eai 'sshd|sudo|su:|useradd|new user|authentication failure' \
        | tail -n 7000 >> "$raw" || true
    fi
  fi
  chmod 600 -- "$raw" 2>/dev/null || true

  local ip kind
  : > "$TMP_DIR/auth_ips.tsv"
  while IFS= read -r ip; do
    ip="${ip%,}"
    [[ "$ip" =~ ^[0-9A-Fa-f:.%]+$ ]] || continue
    is_public_ip "$ip" || continue
    printf '%s\t%s\n' "$ip" "observada" >> "$TMP_DIR/auth_ips.tsv"
  done < <(sed -nE 's/.*[[:space:]]from[[:space:]]+([0-9A-Fa-f:.%]+).*/\1/p' "$raw" 2>/dev/null)

  while IFS=$'\t' read -r ip kind; do
    [[ -n "$ip" ]] || continue
    if grep -F "$ip" "$raw" 2>/dev/null | grep -Eqi 'Accepted (password|publickey|keyboard-interactive)'; then
      record_signal "ip:$ip" "auth_success" "Autenticación aceptada desde $ip"
    fi
    if grep -F "$ip" "$raw" 2>/dev/null | grep -Eqi 'Failed password|Invalid user|authentication failure|PAM.*failure'; then
      record_signal "ip:$ip" "auth_fail" "Fallos de autenticación desde $ip"
    fi
  done < <(sort -u "$TMP_DIR/auth_ips.tsv" 2>/dev/null)
}

collect_users() {
  local out="$OUTPUT_DIR/usuarios.txt" uid0 interactive empty_pass recent_accounts privileged_evidence=""
  {
    printf '===== USUARIOS LOCALES (/etc/passwd; sin hashes) =====\n'
    if [[ -r /etc/passwd ]]; then
      awk -F: '{printf "usuario=%s uid=%s gid=%s home=%s shell=%s\n",$1,$3,$4,$6,$7}' /etc/passwd
    else
      printf '[sin acceso a /etc/passwd]\n'
    fi
  } | redact_stream >> "$out"

  uid0="$(awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null | paste -sd, -)"
  printf '\nUsuarios con UID 0: %s\n' "${uid0:-ninguno_visible}" >> "$out"
  if [[ -n "$uid0" && "$uid0" != "root" ]]; then
    add_finding "USR" "Usuarios y privilegios" "ALTO" \
      "Existe más de una cuenta local con UID 0" "$uid0" \
      "Cualquier UID 0 dispone de privilegios equivalentes a root y puede constituir persistencia." \
      "Algunos entornos heredados crean cuentas administrativas UID 0 deliberadamente." \
      "Validar cada cuenta contra inventario, fecha de alta, propietario y logs de autenticación." "alta"
    record_signal "account:uid0" "privileged_account" "$uid0"
  fi

  interactive="$(awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1":"$3":"$6":"$7}' /etc/passwd 2>/dev/null)"
  printf '\n===== CUENTAS CON SHELL INTERACTIVA =====\n%s\n' "$(sanitize_inline "$interactive")" >> "$out"

  if ((ROOT_AVAILABLE == 1)) && [[ -r /etc/shadow ]]; then
    empty_pass="$(awk -F: '$2=="" {print $1}' /etc/shadow 2>/dev/null | paste -sd, -)"
    printf '\nCuentas con campo de contraseña vacío (solo nombres): %s\n' "${empty_pass:-ninguna}" >> "$out"
    if [[ -n "$empty_pass" ]]; then
      add_finding "USR" "Usuarios y privilegios" "CRÍTICO" \
        "Cuenta local con campo de contraseña vacío" "$empty_pass" \
        "Según PAM y servicios habilitados, podría permitir autenticación sin contraseña." \
        "Cuentas técnicas pueden depender de bloqueo por shell o de una política PAM que prohíba contraseñas vacías." \
        "Comprobar passwd -S, shell, PAM, servicios expuestos y razón documentada; no alterar la cuenta durante el triage." "alta"
      record_signal "account:empty_password" "weak_auth" "$empty_pass"
    fi
    printf '\n===== ESTADO passwd -S (sin hashes) =====\n' >> "$out"
    if have_cmd passwd; then
      local u passwd_status_count=0
      while IFS=: read -r u _; do
        passwd_status_count=$((passwd_status_count + 1))
        ((passwd_status_count <= 5000)) || { add_limitation "Estado passwd -S limitado a 5000 cuentas locales."; break; }
        passwd -S "$u" 2>/dev/null | redact_stream >> "$out" || true
      done < /etc/passwd
    else
      printf '[comando passwd no disponible]\n' >> "$out"
      add_limitation "passwd no disponible; no se consultó el estado resumido de las cuentas."
    fi
  else
    printf '\n[Estado de contraseñas no disponible sin acceso a /etc/shadow]\n' >> "$out"
  fi

  recent_accounts=""
  local user home birth mtime
  local account_shell
  while IFS=: read -r user _ _ _ _ home account_shell; do
    [[ -d "$home" ]] || continue
    [[ "$home" == "/root" || "$home" == /home/* ]] || continue
    [[ ! "$account_shell" =~ (nologin|false|sync|shutdown|halt)$ ]] || continue
    birth="$(stat -c '%W' -- "$home" 2>/dev/null || printf '0')"
    if is_uint "$birth" && ((birth > 0 && birth >= CUTOFF_EPOCH)); then
      recent_accounts+="$user(home=$(safe_path "$home"),birth=$birth); "
    fi
  done < /etc/passwd
  printf '\n===== INDICIOS TEMPORALES DE CUENTAS =====\n%s\n' "${recent_accounts:-Sin homes recientes según metadatos disponibles.}" >> "$out"
  if [[ -n "$recent_accounts" ]]; then
    add_finding "USR" "Usuarios y privilegios" "BAJO" \
      "Metadatos recientes en directorios personales de cuentas" "$recent_accounts" \
      "Puede orientar hacia altas o actividad reciente, pero passwd no conserva una fecha de creación fiable." \
      "Actualizaciones, restauraciones, migraciones o actividad normal cambian estos metadatos." \
      "Correlacionar con useradd/adduser en auth.log/journal, gestión de identidades e inventario." "baja"
  fi

  printf '\n===== GRUPOS PRIVILEGIADOS =====\n' >> "$out"
  local group members group_gid direct_members primary_members
  for group in sudo adm docker lxd libvirt kvm systemd-journal disk shadow root; do
    if awk -F: -v wanted="$group" '$1==wanted {found=1} END{exit !found}' /etc/group 2>/dev/null; then
      group_gid="$(awk -F: -v wanted="$group" '$1==wanted {print $3; exit}' /etc/group 2>/dev/null)"
      direct_members="$(awk -F: -v wanted="$group" '$1==wanted {print $4; exit}' /etc/group 2>/dev/null)"
      primary_members="$(awk -F: -v wanted="$group_gid" '$4==wanted {print $1}' /etc/passwd 2>/dev/null | paste -sd, -)"
      members="$(printf '%s\n%s\n' "$direct_members" "$primary_members" | tr ',' '\n' | sed '/^$/d' | sort -u | paste -sd, -)"
      printf '%s: %s\n' "$group" "${members:-sin miembros suplementarios}" >> "$out"
      [[ -n "$members" ]] && privileged_evidence+="$group=$members; "
      if [[ "$group" == "docker" || "$group" == "lxd" ]] && [[ -n "$members" ]]; then
        add_finding_once "priv-group-$group" "USR" "Usuarios y privilegios" "MEDIO" \
          "Usuarios pertenecen al grupo $group" "$group=$members" \
          "El control del daemon o de contenedores puede equivaler a privilegios root sobre el host." \
          "Es habitual para administradores y plataformas de desarrollo autorizadas." \
          "Confirmar necesidad, propietarios de las cuentas y actividad del daemon; tratar el grupo como acceso privilegiado." "alta"
      fi
    fi
  done

  printf '\n===== METADATOS DE ARCHIVOS DE CUENTAS Y SUDO =====\n' >> "$out"
  local cfg
  for cfg in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers; do
    [[ -e "$cfg" ]] || continue
    file_metadata "$cfg" >> "$out"
    if file_is_recent "$cfg"; then
      add_finding_once "recent-$cfg" "USR" "Usuarios y privilegios" "MEDIO" \
        "Archivo crítico de cuentas o privilegios modificado recientemente" "$(file_metadata "$cfg")" \
        "Cambios en estas bases pueden crear acceso o elevar privilegios." \
        "Altas legítimas, cambios de contraseña, actualizaciones o gestión de configuración también los modifican." \
        "Comparar con logs, copias aprobadas, gestor de configuración y cambios administrativos." "media"
      record_signal "path:$cfg" "recent_file" "$cfg"
    fi
  done

  printf '\n===== /etc/sudoers.d =====\n' >> "$out"
  if [[ -d /etc/sudoers.d ]]; then
    find /etc/sudoers.d -xdev -maxdepth 1 -type f -printf '%M %u:%g %TY-%Tm-%Td %TH:%TM:%TS %p\n' 2>/dev/null \
      | redact_stream | head -n 500 >> "$out" || true
  fi
  if have_cmd visudo; then
    run_limited "$out" "Validación sintáctica sudoers" 120 30 visudo -c
  fi

  local sudo_matches="$TMP_DIR/sudo_nopasswd.txt"
  : > "$sudo_matches"
  for cfg in /etc/sudoers /etc/sudoers.d/*; do
    [[ -f "$cfg" && -r "$cfg" ]] || continue
    grep -HnE '^[[:space:]]*[^#].*NOPASSWD' "$cfg" 2>/dev/null | head -n 100 >> "$sudo_matches" || true
  done
  if [[ -s "$sudo_matches" ]]; then
    printf '\n===== REGLAS NOPASSWD (redactadas) =====\n' >> "$out"
    redact_stream < "$sudo_matches" | head -n 300 >> "$out"
    add_finding "USR" "Sudo" "MEDIO" \
      "Se detectaron reglas sudo NOPASSWD" "$(redact_stream < "$sudo_matches" | head -n 8 | tr '\n' '; ')" \
      "Una regla amplia puede facilitar elevación o persistencia si la cuenta es comprometida." \
      "Automatización y administración gestionada suelen necesitar reglas acotadas sin contraseña." \
      "Revisar alcance de comandos, usuarios/grupos, origen del archivo y aprobación del cambio." "alta"
    record_signal "sudo:nopasswd" "privilege_rule" "NOPASSWD"
  fi

  run_optional "$out" "Sesiones abiertas (who)" 200 20 who -a
  run_optional "$out" "Sesiones y actividad (w)" 200 20 w -h
  run_optional "$out" "Últimos inicios de sesión" 350 30 last -F -n 100
  if have_cmd lastb; then
    run_limited "$out" "Últimos inicios fallidos" 350 30 lastb -F -n 100
  fi

  prepare_auth_events
  printf '\n===== USO RECIENTE DE sudo/su Y CREACIÓN DE USUARIOS =====\n' >> "$out"
  grep -Eai 'sudo|su:|useradd|new user|adduser' "$TMP_DIR/auth_events.raw" 2>/dev/null \
    | tail -n "$MAX_LOG_LINES" | redact_stream >> "$out" || true

  printf '\n===== IP EXTERNAS OBSERVADAS EN AUTENTICACIÓN =====\n' >> "$out"
  cut -f1 "$TMP_DIR/auth_ips.tsv" 2>/dev/null | sort -u | head -n 300 >> "$out" || true
}

collect_ssh() {
  local out="$OUTPUT_DIR/red.txt" ssh_active="desconocido" sshd_effective="$TMP_DIR/sshd_effective.txt"
  printf '\n########## SSH Y ACCESO REMOTO ##########\n' >> "$out"
  if have_cmd systemctl; then
    ssh_active="$(systemctl is-active ssh 2>/dev/null || systemctl is-active sshd 2>/dev/null || printf 'inactivo/no-encontrado')"
    printf 'Estado systemd de SSH: %s\n' "$(sanitize_inline "$ssh_active")" >> "$out"
    run_limited "$out" "Detalle del servicio SSH" 250 30 systemctl status ssh --no-pager -l
  fi

  if have_cmd sshd; then
    capture_bounded "$sshd_effective" "sshd -T" 40 sshd -T -C user=root,host=localhost,addr=127.0.0.1
    printf '\n===== CONFIGURACIÓN EFECTIVA SSHD (directivas seleccionadas) =====\n' >> "$out"
    grep -Ei '^(port|listenaddress|addressfamily|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|challengeresponseauthentication|pubkeyauthentication|authenticationmethods|maxauthtries|allowusers|allowgroups|denyusers|denygroups|authorizedkeysfile|authorizedkeyscommand|authorizedkeyscommanduser|forcecommand|gatewayports|permittunnel|allowtcpforwarding|x11forwarding|loglevel)[[:space:]]' "$sshd_effective" 2>/dev/null \
      | redact_stream | head -n 300 >> "$out" || true

    local root_login pass_auth gateway forward
    root_login="$(awk 'tolower($1)=="permitrootlogin" {print tolower($2); exit}' "$sshd_effective")"
    pass_auth="$(awk 'tolower($1)=="passwordauthentication" {print tolower($2); exit}' "$sshd_effective")"
    gateway="$(awk 'tolower($1)=="gatewayports" {print tolower($2); exit}' "$sshd_effective")"
    forward="$(awk 'tolower($1)=="allowtcpforwarding" {print tolower($2); exit}' "$sshd_effective")"
    if [[ "$root_login" == "yes" ]]; then
      add_finding "SSH" "SSH" "MEDIO" \
        "sshd permite inicio de sesión directo de root" "PermitRootLogin yes" \
        "Aumenta el impacto de credenciales o claves comprometidas, aunque no demuestra abuso." \
        "Puede responder a una política administrativa controlada, especialmente con claves y restricciones." \
        "Revisar necesidad, AuthenticationMethods, AllowUsers/Groups y logs de accesos root." "alta"
    fi
    if [[ "$pass_auth" == "yes" ]]; then
      add_finding "SSH" "SSH" "BAJO" \
        "sshd permite autenticación por contraseña" "PasswordAuthentication yes" \
        "Amplía la superficie frente a fuerza bruta y reutilización de contraseñas." \
        "Puede ser necesario para usuarios autorizados con MFA/PAM y controles adicionales." \
        "Confirmar política, MFA, límites de intentos y exposición del puerto." "alta"
    fi
    if [[ "$gateway" == "yes" ]]; then
      add_finding "SSH" "SSH" "MEDIO" \
        "GatewayPorts está habilitado" "GatewayPorts yes; AllowTcpForwarding=${forward:-desconocido}" \
        "Los reenvíos remotos pueden exponerse más allá de loopback y actuar como túneles." \
        "Puede ser una función autorizada para bastiones o publicación controlada de servicios." \
        "Revisar sesiones, claves con permitopen/permitlisten y necesidad de reenvío." "alta"
    fi
  else
    printf '\n[sshd no instalado; no se obtuvo configuración efectiva]\n' >> "$out"
    add_limitation "No existe el binario sshd o no está en PATH; no se validó la configuración efectiva de SSH."
  fi

  if have_cmd ss; then
    run_limited "$out" "Sockets SSH en escucha" 200 30 ss -H -lntp
    run_limited "$out" "Sesiones SSH establecidas" 250 30 ss -H -tnp state established
  fi

  printf '\n===== ARCHIVOS DE CONFIGURACIÓN SSH =====\n' >> "$out"
  local cfg
  for cfg in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*; do
    [[ -e "$cfg" ]] || continue
    file_metadata "$cfg" >> "$out"
    if file_is_recent "$cfg"; then
      add_finding_once "recent-$cfg" "SSH" "SSH" "MEDIO" \
        "Configuración SSH modificada recientemente" "$(file_metadata "$cfg")" \
        "Cambios pueden habilitar métodos de acceso, usuarios, puertos o reenvíos." \
        "Actualizaciones y cambios administrativos autorizados son frecuentes." \
        "Comparar con control de cambios, paquete openssh-server y logs de reinicio del servicio." "media"
      record_signal "path:$cfg" "recent_file" "$cfg"
    fi
  done

  printf '\n===== AUTHORIZED_KEYS Y PERMISOS .ssh =====\n' >> "$out"
  local user uid home shell sshdir ak mode owner key_type key_blob key_digest fp key_count options_present
  local ssh_user_count=0
  while IFS=: read -r user _ uid _ _ home shell; do
    ssh_user_count=$((ssh_user_count + 1))
    ((ssh_user_count <= 5000)) || { add_limitation "Revisión SSH limitada a 5000 cuentas locales."; break; }
    [[ -n "$home" && "$home" == /* && -d "$home" ]] || continue
    sshdir="$home/.ssh"
    [[ -e "$sshdir" ]] || continue
    file_metadata "$sshdir" >> "$out"
    mode="$(stat -c '%a' -- "$sshdir" 2>/dev/null || printf '0')"
    owner="$(stat -c '%u' -- "$sshdir" 2>/dev/null || printf '?')"
    if is_uint "$mode" && (( (8#$mode & 022) != 0 )); then
      add_finding "SSH" "SSH" "MEDIO" \
        "Directorio .ssh escribible por grupo u otros" "usuario=$user; $(file_metadata "$sshdir")" \
        "Otro principal local podría alterar claves o configuración de acceso." \
        "ACL, grupos privados o directorios gestionados pueden explicar permisos no estándar." \
        "Revisar permisos, ACL con getfacl y propiedad esperada sin corregir durante la adquisición." "alta"
    fi
    if [[ "$owner" != "$uid" ]]; then
      add_finding "SSH" "SSH" "MEDIO" \
        "Propietario inesperado en directorio .ssh" "usuario=$user uid_esperado=$uid; $(file_metadata "$sshdir")" \
        "La propiedad incorrecta puede permitir manipulación o impedir StrictModes." \
        "Homes compartidos, root o aprovisionamiento centralizado pueden ser legítimos." \
        "Confirmar diseño de cuentas, ACL y configuración StrictModes." "media"
    fi

    for ak in "$sshdir/authorized_keys" "$sshdir/authorized_keys2"; do
      [[ -f "$ak" && -r "$ak" ]] || continue
      file_metadata "$ak" >> "$out"
      mode="$(stat -c '%a' -- "$ak" 2>/dev/null || printf '0')"
      owner="$(stat -c '%u' -- "$ak" 2>/dev/null || printf '?')"
      if is_uint "$mode" && (( (8#$mode & 022) != 0 )); then
        add_finding "SSH" "SSH" "ALTO" \
          "authorized_keys escribible por grupo u otros" "usuario=$user; $(file_metadata "$ak")" \
          "Permite a otro principal añadir una clave persistente si los permisos son efectivos." \
          "ACL o grupos estrictamente administrados podrían formar parte del diseño." \
          "Revisar ACL, propietario, grupo y quién modificó el archivo; preservar una copia antes de cambios." "alta"
      fi
      if [[ "$owner" != "$uid" && "$owner" != "0" ]]; then
        add_finding "SSH" "SSH" "MEDIO" \
          "authorized_keys con propietario inesperado" "usuario=$user uid_esperado=$uid; $(file_metadata "$ak")" \
          "Un propietario ajeno puede controlar el acceso por clave de la cuenta." \
          "Gestión centralizada puede crear archivos propiedad de root u otra cuenta de servicio." \
          "Verificar ACL, mecanismo de aprovisionamiento y trazabilidad del archivo." "media"
      fi
      if file_is_recent "$ak"; then
        add_finding "SSH" "SSH" "MEDIO" \
          "authorized_keys modificado recientemente" "usuario=$user; $(file_metadata "$ak")" \
          "La adición de claves es una técnica común de persistencia, pero el tiempo por sí solo no prueba abuso." \
          "Rotación de claves, alta de administradores y automatización son explicaciones comunes." \
          "Comparar huellas con inventario autorizado, backups y logs de acceso/gestión." "media"
        record_signal "path:$ak" "persistence" "authorized_keys de $user"
        record_signal "path:$ak" "recent_file" "$ak"
      fi
      key_count=0
      while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^[[:space:]]*$ || "$line" =~ ^[[:space:]]*# ]] && continue
        key_type="$(awk '{for(i=1;i<=NF;i++) if($i ~ /^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-|sk-ssh-|sk-ecdsa-)/){print $i; exit}}' <<< "$line")"
        key_blob="$(awk '{for(i=1;i<NF;i++) if($i ~ /^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-|sk-ssh-|sk-ecdsa-)/){print $(i+1); exit}}' <<< "$line")"
        [[ -n "$key_type" && -n "$key_blob" ]] || continue
        key_count=$((key_count + 1))
        key_digest=""
        if have_cmd sha256sum; then
          key_digest="$(printf '%s %s' "$key_type" "$key_blob" | sha256sum 2>/dev/null | awk '{print $1}')"
        fi
        fp=""
        if have_cmd ssh-keygen; then
          fp="$(printf '%s %s\n' "$key_type" "$key_blob" | ssh-keygen -lf - 2>/dev/null | awk '{print $1" "$2" "$NF}' | head -n 1)"
        fi
        printf 'usuario=%s archivo=%s clave=%s tipo=%s huella=%s digest_local=%s\n' \
          "$user" "$(safe_path "$ak")" "$key_count" "$key_type" "${fp:-no_disponible}" "$key_digest" >> "$out"
        if [[ -n "$key_digest" ]]; then
          if [[ -n "${KEY_USERS[$key_digest]:-}" && "${KEY_USERS[$key_digest]}" != *",$user,"* ]]; then
            KEY_USERS[$key_digest]="${KEY_USERS[$key_digest]}$user,"
          elif [[ -z "${KEY_USERS[$key_digest]:-}" ]]; then
            KEY_USERS[$key_digest]=",$user,"
          fi
        fi
        options_present=""
        [[ "$line" == "$key_type "* ]] || options_present="sí"
        if [[ -n "$options_present" ]]; then
          local option_names
          option_names="$(sed -E "s/[[:space:]]+$key_type[[:space:]].*//" <<< "$line" | grep -Eo '(^|,)(command|from|permitopen|permitlisten|environment|principals|restrict|no-[a-z-]+)' | tr '\n' ',' | cut -c1-300)"
          printf '  opciones_previas_a_clave=%s (valores no mostrados)\n' "${option_names:-presentes}" >> "$out"
          if [[ "$line" =~ /(\/tmp\/|\/var\/tmp\/|\/dev\/shm\/|curl[[:space:]]|wget[[:space:]]|nc[[:space:]]|socat[[:space:]]) ]]; then
            add_finding "SSH" "SSH" "ALTO" \
              "Opción de authorized_keys referencia una ruta o utilidad sensible" "usuario=$user archivo=$(safe_path "$ak") clave=$key_count opciones=$(sanitize_inline "$option_names")" \
              "Un command= forzado puede utilizarse como persistencia o ejecución automática." \
              "Las claves de respaldo, Git o automatización suelen usar command= y restricciones legítimas." \
              "Inspeccionar el valor completo de forma controlada, verificar el binario y el propietario de la clave." "media"
          fi
        fi
      done < "$ak"
    done

    local kh="$sshdir/known_hosts"
    if [[ -f "$kh" && -r "$kh" ]]; then
      local kh_total kh_hashed kh_marked kh_bad
      kh_total="$(grep -cvE '^[[:space:]]*(#|$)' "$kh" 2>/dev/null || printf '0')"
      kh_hashed="$(awk '$1 ~ /^\|1\|/ {n++} END{print n+0}' "$kh" 2>/dev/null)"
      kh_marked="$(awk '$1 ~ /^@(cert-authority|revoked)$/ {n++} END{print n+0}' "$kh" 2>/dev/null)"
      kh_bad="$(awk 'BEGIN{n=0} /^[[:space:]]*(#|$)/{next} {ok=0; for(i=1;i<=NF;i++) if($i ~ /^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-|sk-ssh-|sk-ecdsa-)/) ok=1; if(!ok)n++} END{print n+0}' "$kh" 2>/dev/null)"
      printf 'known_hosts usuario=%s archivo=%s entradas=%s hashed=%s marcadas=%s malformadas=%s\n' \
        "$user" "$(safe_path "$kh")" "$kh_total" "$kh_hashed" "$kh_marked" "$kh_bad" >> "$out"
      file_metadata "$kh" >> "$out"
      mode="$(stat -c '%a' -- "$kh" 2>/dev/null || printf '0')"
      if is_uint "$mode" && (( (8#$mode & 022) != 0 )); then
        add_finding "SSH" "SSH" "MEDIO" \
          "known_hosts escribible por grupo u otros" "usuario=$user; $(file_metadata "$kh")" \
          "Puede facilitar manipulación de confianza de hosts para esa cuenta, aunque no concede acceso entrante." \
          "ACL o grupos privados pueden justificarlo." \
          "Revisar ACL, propiedad y cambios recientes; contrastar huellas con fuentes confiables." "media"
      fi
      if is_uint "$kh_bad" && ((kh_bad > 0)); then
        add_finding "SSH" "SSH" "BAJO" \
          "known_hosts contiene entradas no reconocidas por la heurística" "usuario=$user entradas_malformadas=$kh_bad; no se muestran hosts" \
          "Una entrada alterada puede ocultar cambios de clave, pero el formato admite variantes." \
          "Certificados, claves futuras u opciones no comprendidas por la heurística pueden ser válidos." \
          "Validar con ssh-keygen -F/-H y documentación de OpenSSH sin reemplazar el archivo." "baja"
      fi
    fi
  done < /etc/passwd

  local digest users
  for digest in "${!KEY_USERS[@]}"; do
    users="${KEY_USERS[$digest]}"
    users="${users#,}"; users="${users%,}"
    if [[ "$users" == *,* ]]; then
      add_finding "SSH" "SSH" "MEDIO" \
        "La misma clave autorizada aparece en varias cuentas" "digest_sha256=$digest usuarios=$users" \
        "Una única credencial podría facilitar movimiento entre cuentas y ampliar el impacto." \
        "Claves de automatización o administración centralizada pueden compartirse deliberadamente." \
        "Confirmar propietario, propósito, restricciones y vigencia de la clave en cada cuenta." "alta"
    fi
  done

  prepare_auth_events
  printf '\n===== EVENTOS SSH RELEVANTES =====\n' >> "$out"
  grep -Eai 'sshd.*(Accepted|Failed|Invalid user|authentication failure|session opened|session closed|Disconnected|Connection closed)' "$TMP_DIR/auth_events.raw" 2>/dev/null \
    | tail -n "$MAX_LOG_LINES" | redact_stream >> "$out" || true

  local ip fails successes
  while IFS= read -r ip; do
    [[ -n "$ip" ]] || continue
    fails="$(grep -F "$ip" "$TMP_DIR/auth_events.raw" 2>/dev/null | grep -Eic 'Failed password|Invalid user|authentication failure|PAM.*failure' || true)"
    successes="$(grep -F "$ip" "$TMP_DIR/auth_events.raw" 2>/dev/null | grep -Eic 'Accepted (password|publickey|keyboard-interactive)' || true)"
    printf 'ip=%s fallos=%s éxitos=%s\n' "$ip" "$fails" "$successes" >> "$out"
    if is_uint "$fails" && ((fails >= 20)); then
      add_finding_once "ssh-fail-$ip" "SSH" "Autenticación" "MEDIO" \
        "Fallos SSH repetidos desde una dirección externa" "ip=$ip fallos_observados=$fails éxitos_observados=$successes" \
        "Puede indicar fuerza bruta o reconocimiento; en servidores expuestos es frecuente y no implica acceso." \
        "Errores de usuarios legítimos, sistemas desactualizados o escaneo indiscriminado de Internet." \
        "Correlacionar intervalo, usuarios, éxitos posteriores, geografía autorizada y controles perimetrales." "alta"
    fi
    if is_uint "$fails" && is_uint "$successes" && ((fails > 0 && successes > 0)); then
      add_finding_once "ssh-fail-success-$ip" "SSH" "Autenticación" "ALTO" \
        "La misma IP externa presenta fallos y autenticaciones SSH aceptadas" "ip=$ip fallos=$fails éxitos=$successes" \
        "La secuencia puede representar tanteo seguido de acceso, aunque requiere ordenar los eventos." \
        "Un administrador puede equivocarse antes de autenticarse correctamente." \
        "Construir una línea temporal exacta y validar usuario, método, clave, origen y actividad de la sesión." "media"
      record_signal "ip:$ip" "auth_fail_success" "fallos=$fails éxitos=$successes"
    fi
  done < <(cut -f1 "$TMP_DIR/auth_ips.tsv" 2>/dev/null | sort -u)
}

collect_network() {
  local out="$OUTPUT_DIR/red.txt"
  local ss_listen="$TMP_DIR/ss_listen.raw" ss_estab="$TMP_DIR/ss_established.raw"
  local listeners="$TMP_DIR/listeners.tsv" remote_ips="$TMP_DIR/remote_ips.txt"
  : > "$listeners"; : > "$remote_ips"
  printf '\n########## CONEXIONES Y EXPOSICIÓN DE RED ##########\n' >> "$out"

  if have_cmd ip; then
    run_limited "$out" "Interfaces y direcciones" 500 30 ip -details -statistics address show
    run_limited "$out" "Rutas IPv4/IPv6" 500 30 ip route show table all
    run_limited "$out" "Vecinos ARP/NDP" 500 30 ip neigh show
    run_limited "$out" "Reglas de política de rutas" 300 30 ip rule show
  elif have_cmd ifconfig; then
    run_limited "$out" "Interfaces (ifconfig)" 500 30 ifconfig -a
    add_limitation "iproute2 no está disponible; la evidencia de red es menos completa."
  fi

  if have_cmd ss; then
    capture_bounded "$ss_listen" "ss sockets en escucha" 45 ss -H -lntup
    capture_bounded "$ss_estab" "ss conexiones establecidas" 45 ss -H -tunap state established
    printf '\n===== TCP/UDP EN ESCUCHA =====\n' >> "$out"
    redact_stream < "$ss_listen" | head -n 2500 >> "$out"
    printf '\n===== CONEXIONES ESTABLECIDAS =====\n' >> "$out"
    redact_stream < "$ss_estab" | head -n 2500 >> "$out"
  elif have_cmd netstat; then
    capture_bounded "$ss_listen" "netstat escucha" 45 netstat -lntup
    capture_bounded "$ss_estab" "netstat conexiones" 45 netstat -antup
    redact_stream < "$ss_listen" | head -n 2500 >> "$out"
    redact_stream < "$ss_estab" | head -n 2500 >> "$out"
    add_limitation "Se usó netstat como alternativa; el análisis automático de sockets puede ser incompleto."
  else
    : > "$ss_listen"; : > "$ss_estab"
    add_limitation "No se encontró ss ni netstat; no se enumeraron sockets de forma fiable."
  fi

  local line netid state recvq sendq local_ep peer_ep pid proc exe uid package host port wildcard unusual entity
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    read -r netid state recvq sendq local_ep peer_ep _ <<< "$line"
    [[ "$state" == "LISTEN" || "$state" == "UNCONN" ]] || continue
    host="$(endpoint_host "${local_ep:-}")"
    port="$(endpoint_port "${local_ep:-}")"
    pid="$(pid_from_ss_line "$line")"
    proc="$(proc_name_from_ss_line "$line")"
    exe=""; uid="?"; package="desconocido"
    if [[ -n "$pid" && -d "/proc/$pid" ]]; then
      exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || readlink "/proc/$pid/exe" 2>/dev/null || true)"
      uid="$(awk '/^Uid:/ {print $2; exit}' "/proc/$pid/status" 2>/dev/null || printf '?')"
      [[ -n "$exe" ]] && package="$(package_owner "${exe% (deleted)}")"
    fi
    wildcard=0
    [[ "$host" == "0.0.0.0" || "$host" == "::" || "$host" == "*" || -z "$host" ]] && wildcard=1
    unusual=0
    [[ "$port" =~ ^[0-9]+$ ]] && ! known_service_port "$port" && unusual=1
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$netid" "$host" "$port" "${pid:-?}" "${proc:-?}" "$(sanitize_inline "$exe")" "$uid" "$package" "$wildcard" >> "$listeners"
    entity="pid:${pid:-sin_pid}:$proc"
    [[ -n "$pid" ]] && entity="pid:$pid"
    ((wildcard == 1)) && record_signal "$entity" "wildcard_listener" "$netid $host:$port proc=$proc"
    ((unusual == 1)) && record_signal "$entity" "unusual_port" "$netid $host:$port proc=$proc"
    if [[ "$package" == "sin-paquete-dpkg" && -n "$pid" ]]; then
      record_signal "$entity" "no_package" "exe=$exe"
    fi
    if [[ "$exe" == /tmp/* || "$exe" == /var/tmp/* || "$exe" == /dev/shm/* ]]; then
      record_signal "$entity" "temp_exec" "exe=$exe escucha=$host:$port"
      record_signal "path:${exe% (deleted)}" "temp_exec" "escucha=$host:$port pid=$pid"
      add_finding_once "temp-listener-$pid-$port" "NET" "Red" "ALTO" \
        "Proceso ejecutado desde una ruta temporal mantiene un puerto en escucha" \
        "pid=$pid proceso=$proc exe=$(safe_path "$exe") socket=$netid $host:$port uid=$uid" \
        "Combina ejecución desde área escribible con exposición de red, un patrón de alto interés forense." \
        "Pruebas, instaladores o herramientas portables autorizadas pueden ejecutarse temporalmente." \
        "Preservar binario y metadatos, calcular hash, revisar proceso padre, conexiones y origen sin ejecutarlo." "alta"
    elif ((wildcard == 1 && unusual == 1)); then
      add_finding_once "wild-unusual-$pid-$port" "NET" "Red" "MEDIO" \
        "Servicio en puerto poco habitual escucha en todas las interfaces" \
        "socket=$netid $host:$port pid=${pid:-no_visible} proceso=${proc:-no_visible} exe=$(safe_path "$exe") paquete=$package uid=$uid" \
        "La exposición amplia y un puerto no estándar justifican identificar el servicio, pero no prueban malicia." \
        "Aplicaciones internas, desarrollo, contenedores y software empresarial usan puertos no estándar." \
        "Relacionar PID, unidad systemd/contenedor, paquete, propietario, reglas de firewall y necesidad de exposición." "media"
    elif ((wildcard == 1)) && is_uint "$uid" && ((uid >= 1000)); then
      add_finding_once "user-wild-$pid-$port" "NET" "Red" "BAJO" \
        "Proceso de usuario escucha en todas las interfaces" \
        "socket=$netid $host:$port pid=$pid proceso=$proc exe=$(safe_path "$exe") uid=$uid" \
        "Un servicio de usuario podría quedar accesible desde otras redes según el cortafuegos." \
        "Servidores de desarrollo, sincronización y aplicaciones de escritorio pueden hacerlo legítimamente." \
        "Confirmar propietario, finalidad, alcance de red y configuración de enlace." "media"
    fi
    if [[ "$package" == "sin-paquete-dpkg" && $wildcard -eq 1 && $unusual -eq 1 ]]; then
      record_signal "$entity" "unknown_listener" "socket=$host:$port exe=$exe"
    fi
  done < "$ss_listen"

  local remote_ip
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    read -r netid state recvq sendq local_ep peer_ep _ <<< "$line"
    # ss con filtro de estado puede omitir la columna textual ESTAB en algunas versiones.
    if [[ "$state" =~ ^[0-9]+$ ]]; then
      peer_ep="${local_ep:-}"
      local_ep="${sendq:-}"
    fi
    remote_ip="$(endpoint_host "${peer_ep:-}")"
    [[ -n "$remote_ip" ]] || continue
    pid="$(pid_from_ss_line "$line")"
    proc="$(proc_name_from_ss_line "$line")"
    if is_public_ip "$remote_ip"; then
      printf '%s\n' "$remote_ip" >> "$remote_ips"
      record_signal "ip:$remote_ip" "remote_connection" "conexión establecida pid=${pid:-?} proceso=${proc:-?}"
    fi
    if [[ -n "$pid" ]]; then
      exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || readlink "/proc/$pid/exe" 2>/dev/null || true)"
      record_signal "pid:$pid" "remote_connection" "remoto=$remote_ip proceso=$proc exe=$exe"
      [[ -n "$exe" ]] && record_signal "path:${exe% (deleted)}" "remote_connection" "remoto=$remote_ip pid=$pid"
      if [[ "$exe" == /tmp/* || "$exe" == /var/tmp/* || "$exe" == /dev/shm/* ]]; then
        add_finding_once "temp-conn-$pid" "NET" "Red" "ALTO" \
          "Proceso desde ruta temporal mantiene una conexión de red" \
          "pid=$pid proceso=$proc exe=$(safe_path "$exe") remoto=$remote_ip" \
          "La combinación es compatible con cargas efímeras o malware y merece adquisición inmediata." \
          "Actualizadores, pruebas o software portable pueden ser legítimos." \
          "Preservar proceso/binario, revisar padre, usuario, hash, DNS y línea temporal; no terminarlo automáticamente." "alta"
      elif [[ "$exe" == /home/* ]] && [[ "$exe" == */.*/* || "$exe" =~ /\.[^/]+$ ]]; then
        add_finding_once "hidden-home-conn-$pid" "NET" "Red" "MEDIO" \
          "Ejecutable en ruta oculta de un home mantiene conexión de red" \
          "pid=$pid proceso=$proc exe=$(safe_path "$exe") remoto=$remote_ip" \
          "Las rutas ocultas son usadas tanto por aplicaciones legítimas como por persistencia discreta." \
          "Aplicaciones instaladas por usuario suelen residir en .local, .config o cachés." \
          "Validar firma/origen, paquete, autostart, hash y comportamiento de red." "media"
      fi
    fi
  done < "$ss_estab"
  sort -u "$remote_ips" -o "$remote_ips" 2>/dev/null || true

  printf '\n===== RESUMEN NORMALIZADO DE ESCUCHAS =====\n' >> "$out"
  printf 'proto\tdireccion\tpuerto\tpid\tproceso\tejecutable\tuid\tpaquete\twildcard\n' >> "$out"
  redact_stream < "$listeners" >> "$out"
  printf '\n===== IP REMOTAS PÚBLICAS EN CONEXIONES ESTABLECIDAS =====\n' >> "$out"
  if [[ -s "$remote_ips" ]]; then cat "$remote_ips" >> "$out"; else printf 'Ninguna visible.\n' >> "$out"; fi

  if have_cmd ufw; then
    run_limited "$out" "Reglas UFW" 800 50 ufw status verbose
  fi
  if have_cmd nft; then
    run_limited "$out" "Reglas nftables" 1800 60 nft list ruleset
  fi
  if have_cmd iptables; then
    run_limited "$out" "Reglas iptables filter" 800 45 iptables -S
    run_limited "$out" "Reglas iptables NAT/redirección" 800 45 iptables -t nat -S
  fi
  if have_cmd ip6tables; then
    run_limited "$out" "Reglas ip6tables" 800 45 ip6tables -S
  fi
  if have_cmd firewall-cmd; then
    run_limited "$out" "firewalld" 500 30 firewall-cmd --list-all-zones
  fi

  printf '\n===== /etc/hosts Y RESOLUCIÓN =====\n' >> "$out"
  for cfg in /etc/hosts /etc/hostname /etc/resolv.conf /etc/nsswitch.conf /etc/systemd/resolved.conf; do
    [[ -e "$cfg" ]] || continue
    file_metadata "$cfg" >> "$out"
    if [[ "$cfg" == "/etc/hosts" && -r "$cfg" ]]; then
      grep -vE '^[[:space:]]*(#|$)' "$cfg" 2>/dev/null | head -n 300 | redact_stream >> "$out" || true
    elif [[ "$cfg" == "/etc/systemd/resolved.conf" && -r "$cfg" ]]; then
      grep -E '^[[:space:]]*(DNS|FallbackDNS|Domains|DNSSEC|DNSOverTLS)=' "$cfg" 2>/dev/null | redact_stream >> "$out" || true
    fi
    if file_is_recent "$cfg"; then
      add_finding_once "recent-net-$cfg" "NET" "Red" "BAJO" \
        "Archivo de resolución o identidad de red modificado recientemente" "$(file_metadata "$cfg")" \
        "Cambios podrían redirigir nombres o alterar rutas de resolución, pero la recencia aislada es débil." \
        "DHCP, NetworkManager, cloud-init y administración normal cambian estos archivos." \
        "Comparar contenido, destino de symlink, logs de red y configuración gestionada." "media"
      record_signal "path:$cfg" "recent_file" "$cfg"
    fi
  done

  printf '\n===== NETWORKMANAGER (sin PSK, secretos ni certificados) =====\n' >> "$out"
  if [[ -d /etc/NetworkManager ]]; then
    find /etc/NetworkManager -xdev -maxdepth 3 -type f -printf '%M %u:%g %TY-%Tm-%Td %TH:%TM:%TS %p\n' 2>/dev/null \
      | redact_stream | head -n 500 >> "$out" || true
    local nm
    while IFS= read -r -d '' nm; do
      printf -- '-- %s --\n' "$(safe_path "$nm")" >> "$out"
      grep -E '^[[:space:]]*(dns|dns-search|method|never-default|ignore-auto-dns)=' "$nm" 2>/dev/null \
        | redact_stream | head -n 80 >> "$out" || true
    done < <(find /etc/NetworkManager -xdev -maxdepth 3 -type f \( -name '*.conf' -o -name '*.nmconnection' \) -print0 2>/dev/null)
  fi

  detect_network_tools "$out"
}

detect_network_tools() {
  local out="$1" tool path found_presence="" running="$TMP_DIR/network_tools_running.txt"
  : > "$running"
  printf '\n===== HERRAMIENTAS DE TÚNEL/PROXY/RED: PRESENCIA LOCAL =====\n' >> "$out"
  for tool in nc netcat ncat socat chisel ngrok cloudflared frpc frps ligolo-proxy ligolo-agent proxychains proxychains4 redsocks gost sshuttle corkscrew; do
    path="$(command -v "$tool" 2>/dev/null || true)"
    if [[ -n "$path" ]]; then
      printf '%s\t%s\tpaquete=%s\n' "$tool" "$(safe_path "$path")" "$(package_owner "$(readlink -f "$path" 2>/dev/null || printf '%s' "$path")")" >> "$out"
      found_presence+="$tool=$(safe_path "$path"); "
    fi
  done
  if [[ -n "$found_presence" ]]; then
    add_finding_once "network-tools-present" "NET" "Herramientas" "INFORMATIVO" \
      "Hay herramientas capaces de crear conexiones, túneles o proxies" "$found_presence" \
      "La presencia permite uso legítimo o abusivo; no constituye ejecución ni compromiso." \
      "Son utilidades comunes de administración, desarrollo, VPN, soporte y diagnóstico." \
      "Validar instalación, paquete, propietario y necesidad; dar más peso solo si hay ejecución o persistencia relacionada." "alta"
  fi

  local psraw="$TMP_DIR/ps_network_scan.raw"
  if have_cmd ps; then
    capture_bounded "$psraw" "ps para herramientas de red" 40 ps -eo pid=,user=,args= --width 1000
    grep -Eai '(^|[[:space:]/])(nc|netcat|ncat|socat|chisel|ngrok|cloudflared|frpc|frps|ligolo-(proxy|agent)|proxychains4?|redsocks|gost|sshuttle)([[:space:]]|$)|(^|[[:space:]])ssh[[:space:]].*-[A-Za-z]*[LRD]' "$psraw" 2>/dev/null \
      | head -n 300 > "$running" || true
  fi
  if [[ -s "$running" ]]; then
    printf '\n===== POSIBLES TÚNELES/PROXIES EN EJECUCIÓN (argumentos redactados) =====\n' >> "$out"
    redact_stream < "$running" >> "$out"
    local sev="MEDIO"
    grep -Eq '/(tmp|var/tmp|dev/shm)/' "$running" && sev="ALTO"
    add_finding "NET" "Herramientas" "$sev" \
      "Proceso compatible con túnel, proxy o herramienta de red avanzada" "$(redact_stream < "$running" | head -n 8 | tr '\n' '; ')" \
      "Estas herramientas pueden crear reenvíos y canales persistentes; la línea de proceso requiere contexto." \
      "Administración remota, VPN, soporte, desarrollo y pruebas pueden justificar su uso." \
      "Identificar usuario, proceso padre, configuración, destino, ticket de cambio y sockets asociados." "media"
    while read -r pid _; do
      [[ "$pid" =~ ^[0-9]+$ ]] && record_signal "pid:$pid" "tunnel_tool" "proceso de túnel/proxy"
    done < "$running"
  fi
}

collect_processes() {
  local out="$OUTPUT_DIR/procesos.txt" psraw="$TMP_DIR/ps_all.raw"
  printf 'Ventana de observación: instantánea; CPU/memoria no son una serie temporal.\n' >> "$out"
  if have_cmd ps; then
    capture_bounded "$psraw" "lista completa de procesos" 60 ps -eo pid=,ppid=,uid=,user=,lstart=,etimes=,pcpu=,pmem=,stat=,comm=,args= --sort=-pcpu --width 1200
    printf '\n===== PROCESOS ACTIVOS (argumentos completos con redacción heurística) =====\n' >> "$out"
    redact_stream < "$psraw" | head -n 10000 >> "$out"
    run_limited "$out" "Árbol de procesos ps" 5000 60 ps -eo user,pid,ppid,etimes,stat,comm,args --forest --width 1200
  else
    : > "$psraw"
    add_limitation "ps no está disponible; la enumeración de procesos es incompleta."
  fi
  if have_cmd pstree; then
    run_limited "$out" "Árbol pstree" 5000 60 pstree -alp
  fi

  printf '\n===== EJECUTABLE REAL, PROPIEDAD Y PAQUETE POR PROCESO =====\n' >> "$out"
  local procdir pid ppid uid user comm args exe clean_exe package meta entity deleted temp home_exec system_mimic
  local processed=0
  for procdir in /proc/[0-9]*; do
    [[ -d "$procdir" ]] || continue
    pid="${procdir##*/}"
    processed=$((processed + 1))
    ((processed <= 50000)) || { add_limitation "Se alcanzó el límite de 50000 procesos enumerados."; break; }
    uid="$(awk '/^Uid:/ {print $2; exit}' "$procdir/status" 2>/dev/null || printf '?')"
    user="$(local_username_by_uid "$uid")"
    comm="$(tr '\000\r\n\t' '    ' < "$procdir/comm" 2>/dev/null | cut -c1-80)"
    ppid="$(awk '/^PPid:/ {print $2; exit}' "$procdir/status" 2>/dev/null || printf '?')"
    exe="$(readlink "$procdir/exe" 2>/dev/null || true)"
    args="$(tr '\000' ' ' < "$procdir/cmdline" 2>/dev/null | cut -c1-2000)"
    deleted=0; temp=0; home_exec=0; system_mimic=0
    [[ "$exe" == *" (deleted)" ]] && deleted=1
    clean_exe="${exe% (deleted)}"
    package="desconocido"
    [[ -n "$clean_exe" ]] && package="$(package_owner "$clean_exe")"
    meta=""
    [[ -e "$clean_exe" ]] && meta="$(file_metadata "$clean_exe")"
    printf 'pid=%s ppid=%s uid=%s user=%s comm=%s exe=%s paquete=%s args=%s %s\n' \
      "$pid" "$ppid" "$uid" "${user:-?}" "$(sanitize_inline "$comm")" "$(safe_path "$exe")" "$package" "$(sanitize_inline "$args")" "$meta" >> "$out"
    entity="pid:$pid"

    if [[ "$uid" == "0" ]]; then
      record_signal "$entity" "root_exec" "exe=$exe comm=$comm"
      [[ -n "$clean_exe" ]] && record_signal "path:$clean_exe" "root_exec" "pid=$pid comm=$comm"
    fi
    if ((deleted == 1)); then
      add_finding_once "deleted-exe-$pid" "PROC" "Procesos" "ALTO" \
        "Proceso activo con ejecutable eliminado" "pid=$pid ppid=$ppid uid=$uid comm=$comm exe=$(safe_path "$exe") args=$(sanitize_inline "$args")" \
        "Puede indicar actualización legítima, ocultación o ejecución de un artefacto ya borrado; preserva código en memoria." \
        "Actualizaciones de paquetes y despliegues reemplazan binarios mientras procesos antiguos siguen activos." \
        "Correlacionar hora de borrado/actualización, paquete, mapas de memoria, sockets y servicio; adquirir antes de reiniciar." "alta"
      record_signal "$entity" "deleted_exec" "$exe"
      record_signal "path:$clean_exe" "deleted_exec" "pid=$pid"
    fi
    if [[ "$clean_exe" == /tmp/* || "$clean_exe" == /var/tmp/* || "$clean_exe" == /dev/shm/* ]]; then
      temp=1
      add_finding_once "temp-exe-$pid" "PROC" "Procesos" "ALTO" \
        "Proceso ejecutándose desde directorio temporal" "pid=$pid ppid=$ppid uid=$uid comm=$comm exe=$(safe_path "$exe") paquete=$package args=$(sanitize_inline "$args")" \
        "Las rutas temporales son escribibles y frecuentes en ejecuciones efímeras de malware." \
        "Instaladores, AppImages, pruebas y compilaciones temporales pueden ser legítimos." \
        "Preservar ejecutable, hash, proceso padre, usuario, cgroup y conexiones antes de cualquier contención." "alta"
      record_signal "$entity" "temp_exec" "$clean_exe"
      record_signal "path:$clean_exe" "temp_exec" "pid=$pid"
    elif [[ "$clean_exe" == /home/* ]]; then
      home_exec=1
      record_signal "$entity" "home_exec" "$clean_exe"
      record_signal "path:$clean_exe" "home_exec" "pid=$pid uid=$uid"
      if [[ "$uid" == "0" ]]; then
        add_finding_once "root-home-exe-$pid" "PROC" "Procesos" "ALTO" \
          "Root ejecuta un binario desde un directorio personal" "pid=$pid exe=$(safe_path "$clean_exe") paquete=$package args=$(sanitize_inline "$args")" \
          "Combina privilegio máximo con una ubicación normalmente controlada por usuario." \
          "Herramientas administrativas locales y scripts de despliegue pueden residir en homes." \
          "Validar propietario, permisos del árbol, origen, hash, servicio/padre y cambio autorizado." "media"
      fi
    fi
    if [[ "$package" == "sin-paquete-dpkg" && -n "$clean_exe" ]]; then
      record_signal "$entity" "no_package" "$clean_exe"
      record_signal "path:$clean_exe" "no_package" "pid=$pid"
    fi

    case "$comm" in
      sshd|systemd|systemd-*|cron|crond|rsyslogd|dbus-daemon|NetworkManager|polkitd|kthreadd|kworker*|migration/*|watchdog/*)
        if [[ -n "$clean_exe" && "$clean_exe" != /usr/* && "$clean_exe" != /bin/* && "$clean_exe" != /sbin/* && "$clean_exe" != /lib/* && "$clean_exe" != /snap/* ]]; then
          system_mimic=1
          add_finding_once "mimic-$pid" "PROC" "Procesos" "MEDIO" \
            "Nombre de proceso imita un componente habitual desde una ruta atípica" "pid=$pid comm=$comm exe=$(safe_path "$clean_exe") uid=$uid paquete=$package" \
            "La suplantación de nombres puede reducir la visibilidad, pero la comparación es heurística." \
            "Contenedores, chroots, builds y software local pueden usar nombres legítimos fuera de rutas de paquetes." \
            "Comparar hash, paquete, cgroup, mount namespace, proceso padre y unidad de servicio." "media"
          record_signal "$entity" "mimic_name" "comm=$comm exe=$clean_exe"
        fi
        ;;
    esac

    if [[ -n "$clean_exe" && -e "$clean_exe" ]]; then
      local ex_mode ex_uid
      ex_mode="$(stat -c '%a' -- "$clean_exe" 2>/dev/null || printf '0')"
      ex_uid="$(stat -c '%u' -- "$clean_exe" 2>/dev/null || printf '?')"
      if is_uint "$ex_mode" && (( (8#$ex_mode & 002) != 0 )); then
        add_finding_once "world-write-exe-$clean_exe" "PROC" "Procesos" "ALTO" \
          "Ejecutable de un proceso es escribible por cualquiera" "pid=$pid exe=$(safe_path "$clean_exe") $(file_metadata "$clean_exe")" \
          "Otro usuario podría reemplazar código que luego se ejecute con el contexto del proceso." \
          "Entornos de laboratorio o volúmenes compartidos pueden configurarlo deliberadamente." \
          "Preservar ACL/metadatos, identificar quién puede escribir y comprobar hash/origen." "alta"
      fi
      if [[ "$clean_exe" == /usr/* || "$clean_exe" == /bin/* || "$clean_exe" == /sbin/* || "$clean_exe" == /lib/* ]] && [[ "$ex_uid" != "0" ]]; then
        add_finding_once "nonroot-system-exe-$clean_exe" "PROC" "Procesos" "ALTO" \
          "Binario activo en ruta del sistema no pertenece a root" "pid=$pid exe=$(safe_path "$clean_exe") $(file_metadata "$clean_exe")" \
          "La propiedad inesperada en rutas de sistema puede permitir manipulación del ejecutable." \
          "Imágenes especiales, bind mounts o paquetes construidos localmente pueden alterar propietarios." \
          "Comprobar mounts, paquete, ACL, integridad y baseline de la imagen." "alta"
      fi
    fi

    if [[ "$args" =~ (^|[[:space:]])(python[0-9.]*|perl|php|ruby|bash|sh)[[:space:]]+(/tmp/|/var/tmp/|/dev/shm/) ]]; then
      add_finding_once "interp-temp-$pid" "PROC" "Procesos" "ALTO" \
        "Intérprete ejecuta código desde una ruta temporal" "pid=$pid uid=$uid args=$(sanitize_inline "$args")" \
        "Los intérpretes permiten ejecución sin un ELF persistente y son comunes en cargas maliciosas." \
        "Scripts de instalación, CI, pruebas y administración pueden hacerlo legítimamente." \
        "Preservar script, entorno accesible, hash, padre, sockets y unidad/cgroup." "alta"
      record_signal "$entity" "temp_script" "$args"
    fi
  done

  printf '\n===== USO ALTO INSTANTÁNEO =====\n' >> "$out"
  if [[ -s "$psraw" ]]; then
    awk '$0 ~ /^[[:space:]]*[0-9]+/ {print}' "$psraw" | head -n 30 | redact_stream >> "$out" || true
    local cpu_line cpu_val mem_val high_usage=""
    while IFS= read -r cpu_line; do
      # Campos fijos antes de lstart dificultan parsing portable; extraemos con ps dedicado abajo.
      :
    done < /dev/null
    high_usage="$(ps -eo pid=,user=,pcpu=,pmem=,comm=,args= --sort=-pcpu --width 1000 2>/dev/null \
      | awk '$3+0 >= 90 || $4+0 >= 60 {print}' | head -n 20)"
    if [[ -n "$high_usage" ]]; then
      printf '%s\n' "$high_usage" | redact_stream >> "$out"
      add_finding "PROC" "Procesos" "BAJO" \
        "Proceso con uso instantáneo muy alto de CPU o memoria" "$(printf '%s' "$high_usage" | redact_stream | tr '\n' '; ')" \
        "Minería, bucles o cargas anómalas pueden consumir recursos, pero una sola instantánea no establece tendencia." \
        "Compilación, vídeo, navegador, actualizaciones y cargas científicas son causas normales." \
        "Observar una serie temporal y correlacionar ejecutable, usuario, paquete, sockets y carga esperada." "baja"
    fi
  fi

  if have_cmd lsof; then
    run_limited "$out" "Archivos abiertos con link count cero" 1200 90 lsof -nP +L1
  else
    printf '\n[lsof no instalado; los ejecutables eliminados sí se revisaron vía /proc]\n' >> "$out"
    add_limitation "lsof no está instalado; la cobertura de archivos abiertos eliminados es parcial."
  fi

  # Comparación prudente /proc frente a ps. Las discrepancias se revalidan para reducir carreras.
  local proc_pids="$TMP_DIR/proc_pids" ps_pids="$TMP_DIR/ps_pids" missing="$TMP_DIR/pids_missing_ps"
  if ! have_cmd ps; then
    printf '\n[Comparación /proc frente a ps omitida: ps no disponible]\n' >> "$out"
    return 0
  fi
  find /proc -maxdepth 1 -type d -regextype posix-extended -regex '/proc/[0-9]+' -printf '%f\n' 2>/dev/null | sort -n > "$proc_pids"
  ps -e -o pid= 2>/dev/null | tr -d ' ' | awk '/^[0-9]+$/' | sort -n > "$ps_pids"
  comm -23 "$proc_pids" "$ps_pids" > "$missing" 2>/dev/null || true
  local stable_missing=""
  while IFS= read -r pid; do
    [[ -d "/proc/$pid" && -r "/proc/$pid/stat" ]] || continue
    if ! ps -p "$pid" -o pid= >/dev/null 2>&1; then
      stable_missing+="pid=$pid comm=$(tr '\000\n' '  ' < "/proc/$pid/comm" 2>/dev/null | cut -c1-80); "
    fi
  done < "$missing"
  if [[ -n "$stable_missing" ]]; then
    add_finding "PROC" "Procesos" "MEDIO" \
      "PID visible en /proc pero no en dos consultas ps" "$stable_missing" \
      "Puede indicar una herramienta ps manipulada u ocultación, aunque las carreras y namespaces generan diferencias." \
      "Procesos muy breves, permisos hidepid, contenedores y cambios concurrentes son explicaciones frecuentes." \
      "Repetir desde medio confiable/offline, comparar syscall getdents, namespaces y hashes del paquete procps." "baja"
  fi
}

suspicious_command_pattern() {
  # Se usa solo para buscar texto; nunca se evalúa ni ejecuta una coincidencia.
  printf '%s' '(\/tmp\/|\/var\/tmp\/|\/dev\/shm\/|https?:\/\/|(^|[[:space:];|])(curl|wget|nc|ncat|netcat|socat|chisel|ngrok|bash[[:space:]]+-c|sh[[:space:]]+-c|python[0-9.]*[[:space:]]+-c|perl[[:space:]]+-e|php[[:space:]]+-r|base64[[:space:]]+(-d|--decode)|mkfifo)([[:space:];|]|$)|\/dev\/tcp\/|ssh[[:space:]].*-[A-Za-z]*[LRD])'
}

analyze_persistence_text() {
  local source="$1" textfile="$2" entity matches
  entity="path:$source"
  matches="$TMP_DIR/persist_match.$RANDOM"
  [[ -r "$textfile" ]] || return 0
  grep -Ein "$(suspicious_command_pattern)" "$textfile" 2>/dev/null | head -n 40 > "$matches" || true
  if [[ -s "$matches" ]]; then
    local sev="MEDIO"
    if [[ "$source" == "/etc/environment" || "$source" == */.profile || "$source" == */.bashrc || "$source" == */.zshrc ]] \
       && ! grep -Eqi '(/tmp/|/var/tmp/|/dev/shm/|curl[[:space:]]|wget[[:space:]]|nc[[:space:]]|socat[[:space:]]|bash[[:space:]]+-c|sh[[:space:]]+-c|base64|/dev/tcp/|ssh[[:space:]].*-[A-Za-z]*[LRD])' "$matches"; then
      sev="BAJO"
    fi
    grep -Eqi '(/tmp/|/var/tmp/|/dev/shm/|curl.*\|.*(sh|bash)|wget.*\|.*(sh|bash)|/dev/tcp/|nc.*-e|socat.*exec)' "$matches" && sev="ALTO"
    add_finding_once "persist-text-$source" "PERS" "Persistencia" "$sev" \
      "Persistencia contiene rutas temporales, red, túnel o ejecución dinámica" \
      "origen=$(safe_path "$source"); coincidencias=$(redact_stream < "$matches" | tr '\n' '; ')" \
      "Cron, unidades o perfiles pueden ejecutar automáticamente el contenido en futuros arranques/sesiones." \
      "Actualizadores, agentes, proxies y automatización legítima pueden usar red o intérpretes." \
      "Validar propietario, creación, paquete, destino, hash, frecuencia y cambio autorizado; no ejecutar la línea." "media"
    record_signal "$entity" "persistence" "$source"
    grep -Eq '/tmp/|/var/tmp/|/dev/shm/' "$matches" && record_signal "$entity" "temp_exec" "$source"
  fi
  rm -f -- "$matches"
}

collect_cron() {
  local out="$1" cfg tmp user uid home shell max_users=500 count=0
  printf '\n===== CRON DEL SISTEMA =====\n' >> "$out"
  for cfg in /etc/crontab /etc/anacrontab; do
    [[ -f "$cfg" ]] || continue
    file_metadata "$cfg" >> "$out"
    printf -- '-- contenido no comentado de %s --\n' "$(safe_path "$cfg")" >> "$out"
    grep -vE '^[[:space:]]*(#|$)' "$cfg" 2>/dev/null | head -n 500 | redact_stream >> "$out" || true
    analyze_persistence_text "$cfg" "$cfg"
    file_is_recent "$cfg" && record_signal "path:$cfg" "recent_file" "$cfg"
  done

  local d
  for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron/crontabs; do
    [[ -d "$d" ]] || continue
    printf '\n-- inventario %s --\n' "$(safe_path "$d")" >> "$out"
    find "$d" -xdev -maxdepth 2 -type f -printf '%M %u:%g %s %TY-%Tm-%Td %TH:%TM:%TS %p\n' 2>/dev/null \
      | sort | head -n 2000 | redact_stream >> "$out" || true
    while IFS= read -r -d '' cfg; do
      printf -- '-- entradas activas %s --\n' "$(safe_path "$cfg")" >> "$out"
      grep -vE '^[[:space:]]*(#|$)' "$cfg" 2>/dev/null | head -n 120 | redact_stream >> "$out" || true
      analyze_persistence_text "$cfg" "$cfg"
      if file_is_recent "$cfg"; then
        record_signal "path:$cfg" "recent_file" "$cfg"
        add_finding_once "recent-cron-$cfg" "PERS" "Persistencia" "MEDIO" \
          "Archivo de cron modificado recientemente" "$(file_metadata "$cfg")" \
          "Cron es un mecanismo habitual de persistencia; la recencia requiere contexto." \
          "Paquetes, mantenimiento y cambios administrativos crean tareas cron legítimas." \
          "Relacionar con dpkg, logs, propietario, contenido y control de cambios." "media"
      fi
    done < <(find "$d" -xdev -maxdepth 2 -type f -print0 2>/dev/null)
  done

  if have_cmd crontab; then
    printf '\n===== CRONTABS POR USUARIO =====\n' >> "$out"
    while IFS=: read -r user _ uid _ _ home shell; do
      count=$((count + 1)); ((count <= max_users)) || break
      if [[ "$MODE" == "quick" && "$uid" != "0" && "$shell" =~ (nologin|false)$ ]]; then
        continue
      fi
      tmp="$TMP_DIR/crontab.$count"
      if crontab -l -u "$user" > "$tmp" 2>/dev/null; then
        printf -- '-- crontab usuario=%s --\n' "$user" >> "$out"
        redact_stream < "$tmp" | head -n 500 >> "$out"
        analyze_persistence_text "crontab:$user" "$tmp"
      fi
    done < /etc/passwd
  fi

  if have_cmd atq; then
    run_limited "$out" "Trabajos at pendientes (contenido omitido para no exponer entorno/secretos)" 500 30 atq
    local at_count
    at_count="$(atq 2>/dev/null | wc -l | tr -d ' ')"
    if is_uint "$at_count" && ((at_count > 0)); then
      add_finding "PERS" "Persistencia" "BAJO" \
        "Existen trabajos at pendientes" "cantidad=$at_count; ver persistencia.txt para propietario y horario" \
        "at puede ejecutar una acción futura, aunque no es persistencia recurrente." \
        "Mantenimiento y tareas administrativas puntuales son usos legítimos." \
        "Revisar cada trabajo con privilegios adecuados en una copia controlada; el informe omite su entorno por privacidad." "alta"
    fi
  else
    printf '\n[at/atq no instalado]\n' >> "$out"
  fi
}

collect_systemd_persistence() {
  local out="$1" enabled="$TMP_DIR/systemd_enabled.txt" unit unit_count=0 showfile fragment execstart svc_user entity clean_path candidate_reason
  if ! have_cmd systemctl; then
    printf '\n[systemctl no disponible]\n' >> "$out"
    add_limitation "systemctl no está disponible; no se enumeraron servicios/timers habilitados."
    return 0
  fi
  capture_bounded "$enabled" "unidades systemd habilitadas" 90 systemctl list-unit-files --state=enabled --no-legend --no-pager
  printf '\n===== UNIDADES SYSTEMD HABILITADAS =====\n' >> "$out"
  redact_stream < "$enabled" | head -n 3000 >> "$out"
  run_limited "$out" "Timers systemd" 1500 90 systemctl list-timers --all --no-pager
  run_limited "$out" "Servicios en ejecución" 1500 90 systemctl list-units --type=service --state=running --no-pager --no-legend

  printf '\n===== DETALLE DE SERVICIOS HABILITADOS =====\n' >> "$out"
  while read -r unit _; do
    [[ "$unit" == *.service ]] || continue
    unit_count=$((unit_count + 1)); ((unit_count <= 700)) || { add_limitation "Detalle systemd limitado a 700 servicios habilitados."; break; }
    showfile="$TMP_DIR/systemd_show.$unit_count"
    systemctl show "$unit" -p Id -p FragmentPath -p SourcePath -p User -p Group -p ExecStart -p ExecStartPre -p ExecStartPost -p LoadState -p ActiveState > "$showfile" 2>/dev/null || continue
    printf -- '-- %s --\n' "$unit" >> "$out"
    redact_stream < "$showfile" | head -n 30 >> "$out"
    fragment="$(sed -n 's/^FragmentPath=//p' "$showfile" | head -n 1)"
    execstart="$(sed -n 's/^ExecStart=//p' "$showfile" | head -n 1)"
    svc_user="$(sed -n 's/^User=//p' "$showfile" | head -n 1)"
    candidate_reason=""
    [[ -n "$fragment" ]] && entity="path:$fragment" || entity="unit:$unit"
    record_signal "$entity" "persistence" "servicio habilitado=$unit user=${svc_user:-root/default}"
    [[ "$fragment" == /etc/systemd/system/* || "$fragment" == /usr/local/* ]] && candidate_reason+="unidad_local;"
    if [[ -n "$fragment" && -e "$fragment" ]] && file_is_recent "$fragment"; then
      add_finding_once "recent-unit-$fragment" "PERS" "Persistencia" "MEDIO" \
        "Unidad systemd habilitada modificada recientemente" "unidad=$unit; $(file_metadata "$fragment")" \
        "Una unidad habilitada puede ejecutar código al arranque y es un mecanismo habitual de persistencia." \
        "Instalaciones, actualizaciones y despliegues autorizados modifican unidades legítimas." \
        "Comparar con paquete, control de cambios, contenido, symlinks de enablement y logs de inicio." "media"
      record_signal "$entity" "recent_file" "$fragment"
      candidate_reason+="unidad_reciente;"
    fi
    if [[ "$execstart" =~ (/tmp/|/var/tmp/|/dev/shm/) ]]; then
      add_finding_once "temp-unit-$unit" "PERS" "Persistencia" "ALTO" \
        "Servicio systemd habilitado ejecuta desde una ruta temporal" "unidad=$unit usuario=${svc_user:-root/default} fragment=$(safe_path "$fragment") exec=$(sanitize_inline "$execstart")" \
        "Combina ejecución automática con una ubicación escribible y efímera." \
        "Unidades de prueba o instaladores mal diseñados pueden hacerlo temporalmente." \
        "Preservar unidad y ejecutable, obtener hash/propietario, revisar journal y origen del enablement." "alta"
      record_signal "$entity" "temp_exec" "$execstart"
      candidate_reason+="ruta_temporal;"
    elif [[ "$execstart" =~ /home/ ]]; then
      add_finding_once "home-unit-$unit" "PERS" "Persistencia" "MEDIO" \
        "Servicio systemd de sistema ejecuta contenido desde un home" "unidad=$unit usuario=${svc_user:-root/default} fragment=$(safe_path "$fragment") exec=$(sanitize_inline "$execstart")" \
        "El contenido puede quedar bajo control de un usuario y ejecutarse automáticamente." \
        "Servicios personales promovidos, aplicaciones locales y entornos de desarrollo pueden ser autorizados." \
        "Validar propietario/permisos de toda la ruta, usuario efectivo, hash y aprobación." "media"
      record_signal "$entity" "home_exec" "$execstart"
      candidate_reason+="ruta_home;"
    fi
    if [[ "$execstart" =~ (https?://|curl[[:space:]]|wget[[:space:]]|bash[[:space:]]+-c|sh[[:space:]]+-c|base64) ]]; then
      add_finding_once "dynamic-unit-$unit" "PERS" "Persistencia" "ALTO" \
        "Servicio systemd contiene descarga, URL o ejecución dinámica" "unidad=$unit exec=$(sanitize_inline "$execstart")" \
        "Una unidad persistente que obtiene o interpreta código dinámico reduce trazabilidad e integridad." \
        "Agentes de actualización y bootstrap autorizados pueden usar estos patrones." \
        "Inspeccionar unidad completa, binarios invocados, destinos y logs; validar contra el proveedor." "media"
      candidate_reason+="ejecucion_dinamica;"
    fi

    clean_path="$(sed -nE 's/.*path=([^ ;]+).*/\1/p' "$showfile" | head -n 1)"
    if [[ -n "$clean_path" ]]; then
      record_signal "path:$clean_path" "persistence" "unidad=$unit"
      if [[ "$(package_owner "$clean_path")" == "sin-paquete-dpkg" ]]; then
        record_signal "path:$clean_path" "no_package" "unidad=$unit"
        candidate_reason+="binario_sin_paquete;"
      fi
    fi
    if [[ -n "$candidate_reason" ]]; then
      printf '%s\t%s\t%s\t%s\n' "$unit" "$candidate_reason" "$(safe_path "$fragment")" "$(sanitize_inline "$execstart")" >> "$TMP_DIR/persistence_candidates.tsv"
    fi
  done < "$enabled"

  printf '\n===== INVENTARIO DE UNIDADES EN DISCO =====\n' >> "$out"
  local d f
  for d in /etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
    [[ -d "$d" ]] || continue
    find "$d" -xdev -maxdepth 3 \( -type f -o -type l \) -printf '%y %M %u:%g %TY-%Tm-%Td %TH:%TM:%TS %p -> %l\n' 2>/dev/null \
      | head -n 5000 | redact_stream >> "$out" || true
  done
}

collect_profile_persistence() {
  local out="$1" file user uid home shell d pattern
  pattern="$(suspicious_command_pattern)|(^|[[:space:]])(alias|function)[[:space:]]+|PROMPT_COMMAND=|BASH_ENV=|ENV=|LD_PRELOAD="
  printf '\n===== PERFILES Y SCRIPTS DE INICIO =====\n' >> "$out"
  for file in /etc/profile /etc/bash.bashrc /etc/zsh/zshrc /etc/zsh/zprofile /etc/environment /etc/profile.d/* /etc/rc.local; do
    [[ -f "$file" && -r "$file" ]] || continue
    file_metadata "$file" >> "$out"
    grep -Ein "$pattern" "$file" 2>/dev/null | head -n 100 | redact_stream >> "$out" || true
    analyze_persistence_text "$file" "$file"
    if file_is_recent "$file"; then
      record_signal "path:$file" "recent_file" "$file"
    fi
  done

  if ((INCLUDE_HOME == 1)); then
    local profile_user_count=0
    while IFS=: read -r user _ uid _ _ home shell; do
      profile_user_count=$((profile_user_count + 1))
      ((profile_user_count <= 5000)) || { add_limitation "Perfiles de usuario limitados a 5000 cuentas locales."; break; }
      [[ -d "$home" ]] || continue
      for file in "$home/.profile" "$home/.bashrc" "$home/.bash_profile" "$home/.bash_login" "$home/.zshrc" "$home/.zprofile" "$home/.config/fish/config.fish"; do
        [[ -f "$file" && -r "$file" ]] || continue
        printf -- '-- usuario=%s archivo=%s --\n' "$user" "$(safe_path "$file")" >> "$out"
        file_metadata "$file" >> "$out"
        grep -Ein "$pattern" "$file" 2>/dev/null | head -n 100 | redact_stream >> "$out" || true
        analyze_persistence_text "$file" "$file"
      done
      for d in "$home/.config/autostart" "$home/.config/systemd/user"; do
        [[ -d "$d" ]] || continue
        printf -- '-- persistencia usuario=%s directorio=%s --\n' "$user" "$(safe_path "$d")" >> "$out"
        find "$d" -xdev -maxdepth 4 -type f -printf '%M %u:%g %TY-%Tm-%Td %TH:%TM:%TS %p\n' 2>/dev/null \
          | head -n 1000 | redact_stream >> "$out" || true
        while IFS= read -r -d '' file; do
          grep -Ein '^[[:space:]]*(Exec|ExecStart|ExecStartPre|ExecStartPost)=|(/tmp/|/var/tmp/|/dev/shm/|https?://|curl|wget|base64)' "$file" 2>/dev/null \
            | head -n 100 | redact_stream >> "$out" || true
          analyze_persistence_text "$file" "$file"
          record_signal "path:$file" "persistence" "autostart/unidad de usuario=$user"
          file_is_recent "$file" && record_signal "path:$file" "recent_file" "$file"
        done < <(find "$d" -xdev -maxdepth 4 -type f -print0 2>/dev/null)
      done
    done < /etc/passwd
  else
    printf '[Perfiles y autostart de usuarios omitidos; use --include-home o --full.]\n' >> "$out"
    add_limitation "El modo rápido sin --include-home omite parte de la persistencia en perfiles/autostart de usuarios."
  fi
}

collect_low_level_persistence() {
  local out="$1" file d
  printf '\n===== PAM =====\n' >> "$out"
  if [[ -d /etc/pam.d ]]; then
    find /etc/pam.d -xdev -maxdepth 1 -type f -printf '%M %u:%g %TY-%Tm-%Td %TH:%TM:%TS %p\n' 2>/dev/null \
      | sort | redact_stream >> "$out" || true
    while IFS= read -r -d '' file; do
      if file_is_recent "$file"; then
        add_finding_once "recent-pam-$file" "PERS" "Persistencia" "MEDIO" \
          "Configuración PAM modificada recientemente" "$(file_metadata "$file")" \
          "PAM controla autenticación y sesiones; cambios pueden alterar acceso o ejecutar módulos." \
          "Actualizaciones de paquetes y políticas de autenticación legítimas modifican PAM." \
          "Comparar con dpkg --verify, paquete propietario y cambio aprobado; revisar módulos referenciados." "media"
        record_signal "path:$file" "recent_file" "$file"
      fi
    done < <(find /etc/pam.d -xdev -maxdepth 1 -type f -print0 2>/dev/null)
  fi

  printf '\n===== LD.SO.PRELOAD Y PRECARGA =====\n' >> "$out"
  if [[ -e /etc/ld.so.preload ]]; then
    file_metadata /etc/ld.so.preload >> "$out"
    if [[ -s /etc/ld.so.preload && -r /etc/ld.so.preload ]]; then
      grep -vE '^[[:space:]]*(#|$)' /etc/ld.so.preload 2>/dev/null | head -n 100 | redact_stream >> "$out" || true
      add_finding "PERS" "Persistencia" "ALTO" \
        "/etc/ld.so.preload contiene bibliotecas" "$(grep -vE '^[[:space:]]*(#|$)' /etc/ld.so.preload 2>/dev/null | head -n 20 | redact_stream | tr '\n' '; ')" \
        "La precarga global puede inyectar código en numerosos procesos y es una técnica potente de persistencia." \
        "Agentes de monitorización, compatibilidad o instrumentación autorizados pueden usarla." \
        "Preservar archivo/bibliotecas, verificar paquetes, firmas, hashes, propietarios y aprobación antes de modificar." "alta"
      record_signal "path:/etc/ld.so.preload" "persistence" "precarga global"
      file_is_recent /etc/ld.so.preload && record_signal "path:/etc/ld.so.preload" "recent_file" "/etc/ld.so.preload"
    else
      printf '[vacío]\n' >> "$out"
    fi
  else
    printf '[no existe /etc/ld.so.preload]\n' >> "$out"
  fi
  run_optional "$out" "Variables LD_PRELOAD en procesos (solo nombres/rutas redactadas)" 500 60 sh -c 'for f in /proc/[0-9]*/environ; do [ -r "$f" ] || continue; tr "\0" "\n" < "$f" 2>/dev/null | grep -H "^LD_PRELOAD=" && printf "pid_source=%s\n" "$f"; done'

  printf '\n===== UDEV, MÓDULOS Y SCRIPTS DE ARRANQUE =====\n' >> "$out"
  for d in /etc/udev/rules.d /etc/modules-load.d /etc/modprobe.d /etc/init.d /etc/init; do
    [[ -d "$d" ]] || continue
    printf -- '-- %s --\n' "$(safe_path "$d")" >> "$out"
    find "$d" -xdev -maxdepth 3 -type f -printf '%M %u:%g %TY-%Tm-%Td %TH:%TM:%TS %p\n' 2>/dev/null \
      | head -n 2000 | redact_stream >> "$out" || true
    while IFS= read -r -d '' file; do
      if file_is_recent "$file"; then
        record_signal "path:$file" "recent_file" "$file"
        if [[ "$d" == "/etc/udev/rules.d" ]]; then
          add_finding_once "recent-udev-$file" "PERS" "Persistencia" "MEDIO" \
            "Regla udev modificada recientemente" "$(file_metadata "$file")" \
            "udev puede ejecutar acciones al aparecer dispositivos y servir como disparador persistente." \
            "Instaladores de hardware y administración normal crean reglas legítimas." \
            "Revisar RUN/PROGRAM, paquete, dispositivo asociado y control de cambios." "media"
        fi
      fi
      grep -Ein '(^|[,[:space:]])(RUN\+?=|PROGRAM=)|(/tmp/|/var/tmp/|/dev/shm/|curl|wget|nc[[:space:]]|socat)' "$file" 2>/dev/null \
        | head -n 50 | redact_stream >> "$out" || true
      analyze_persistence_text "$file" "$file"
    done < <(find "$d" -xdev -maxdepth 3 -type f -print0 2>/dev/null)
  done

  printf '\n===== AUTOSTART GLOBAL =====\n' >> "$out"
  for d in /etc/xdg/autostart /usr/share/autostart; do
    [[ -d "$d" ]] || continue
    find "$d" -xdev -maxdepth 2 -type f -name '*.desktop' -printf '%M %u:%g %TY-%Tm-%Td %TH:%TM:%TS %p\n' 2>/dev/null \
      | head -n 1000 | redact_stream >> "$out" || true
    while IFS= read -r -d '' file; do
      printf -- '-- %s --\n' "$(safe_path "$file")" >> "$out"
      grep -E '^[[:space:]]*(Name|Exec|TryExec|Hidden|X-GNOME-Autostart-enabled)=' "$file" 2>/dev/null \
        | head -n 100 | redact_stream >> "$out" || true
      analyze_persistence_text "$file" "$file"
    done < <(find "$d" -xdev -maxdepth 2 -type f -name '*.desktop' -print0 2>/dev/null)
  done
}

collect_persistence() {
  local out="$OUTPUT_DIR/persistencia.txt"
  : > "$TMP_DIR/persistence_candidates.tsv"
  collect_cron "$out"
  collect_systemd_persistence "$out"
  collect_profile_persistence "$out"
  collect_low_level_persistence "$out"
}

path_is_excluded() {
  local path="$1" ex
  [[ "$path" == "$OUTPUT_DIR" || "$path" == "$OUTPUT_DIR/"* ]] && return 0
  for ex in "${EXCLUDE_DIRS[@]}"; do
    [[ -n "$ex" ]] || continue
    [[ "$path" == "$ex" || "$path" == "$ex/"* ]] && return 0
  done
  return 1
}

make_find_prefix() {
  # Imprime una matriz NUL-delimitada que el llamador reconstruye con mapfile.
  local root="$1" ex ex_pattern
  local -a cmd=(find "$root" -xdev -maxdepth "$MAX_DEPTH")
  for ex in "${EXCLUDE_DIRS[@]}" "$OUTPUT_DIR"; do
    [[ -n "$ex" ]] || continue
    if [[ "$ex" == "$root" ]]; then
      printf '%s\0' "false"
      return 0
    elif [[ "$ex" == "$root/"* ]]; then
      ex_pattern="$(find_pattern_escape "$ex")"
      cmd+=( \( -path "$ex_pattern" -o -path "$ex_pattern/*" \) -prune -o )
    fi
  done
  printf '%s\0' "${cmd[@]}"
}

hash_candidate() {
  local path="$1" reason="$2" out="$3" size hash
  ((HASH_FILES == 1)) || return 0
  [[ -f "$path" && ! -L "$path" ]] || return 0
  size="$(stat -c '%s' -- "$path" 2>/dev/null || printf '0')"
  is_uint "$size" || return 0
  if ((size > MAX_HASH_MB * 1024 * 1024)); then
    printf 'sha256=omitido_por_tamaño limite=%sMiB ruta=%s\n' "$MAX_HASH_MB" "$(safe_path "$path")" >> "$out"
    return 0
  fi
  if have_cmd sha256sum; then
    if have_cmd timeout; then
      hash="$(timeout 30s sha256sum -- "$path" 2>/dev/null | awk '{print $1}')"
    else
      hash="$(sha256sum -- "$path" 2>/dev/null | awk '{print $1}')"
    fi
    if [[ "$hash" =~ ^[0-9a-fA-F]{64}$ ]]; then
      printf 'sha256=%s tamaño=%s motivo=%s ruta=%s\n' "$hash" "$size" "$(sanitize_inline "$reason")" "$(safe_path "$path")" >> "$out"
      printf '%s\t%s\t%s\t%s\n' "$(safe_path "$path")" "$(sanitize_inline "$reason")" "$hash" "$size" >> "$TMP_DIR/suspicious_files.tsv"
    else
      log_error "sha256 $(safe_path "$path")" "1" "No se pudo calcular el hash"
    fi
  fi
}

inspect_candidate_file() {
  local path="$1" origin="$2" out="$OUTPUT_DIR/archivos_recientes.txt"
  [[ -f "$path" && ! -L "$path" ]] || return 0
  path_is_excluded "$path" && return 0
  [[ -z "${SEEN_RECENT[$path]:-}" ]] || return 0
  ((TOTAL_FILES_INSPECTED < MAX_TOTAL_FILES)) || return 0
  TOTAL_FILES_INSPECTED=$((TOTAL_FILES_INSPECTED + 1))
  SEEN_RECENT[$path]=1
  printf '%s\0' "$path" >> "$TMP_DIR/recent_paths.nul"

  local mode uid size base parent desc package="" executable=0 is_elf=0 is_script=0 world_write=0 suspicious=0 reason=""
  mode="$(stat -c '%a' -- "$path" 2>/dev/null || printf '0')"
  uid="$(stat -c '%u' -- "$path" 2>/dev/null || printf '?')"
  size="$(stat -c '%s' -- "$path" 2>/dev/null || printf '0')"
  base="${path##*/}"; parent="${path%/*}"
  desc="$(describe_file "$path" 500)"
  if is_uint "$mode" && (( (8#$mode & 0111) != 0 )); then executable=1; fi
  [[ "$desc" == *ELF* ]] && is_elf=1
  [[ "$desc" =~ (script|text|JSON|XML|PHP|Python|Perl|shell) ]] && is_script=1
  if [[ "$(head -c 2 -- "$path" 2>/dev/null || true)" == '#!' ]]; then is_script=1; fi
  if is_uint "$mode" && (( (8#$mode & 0002) != 0 )); then world_write=1; fi

  printf '%s | origen=%s | tipo=%s\n' "$(file_metadata "$path")" "$(sanitize_inline "$origin")" "$(sanitize_inline "$desc")" >> "$out"
  record_signal "path:$path" "recent_file" "origen=$origin"

  if ((executable == 1 || is_elf == 1)); then
    package="$(package_owner "$path")"
    printf '  ejecutable/ELF paquete=%s\n' "$package" >> "$out"
    if [[ "$package" == "sin-paquete-dpkg" ]]; then
      record_signal "path:$path" "no_package" "ejecutable sin paquete dpkg"
    fi
  fi

  if [[ "$path" == /tmp/* || "$path" == /var/tmp/* || "$path" == /dev/shm/* ]]; then
    if ((executable == 1 || is_elf == 1 || is_script == 1)); then
      suspicious=1; reason+="temporal_ejecutable_o_script; "
      record_signal "path:$path" "temp_exec" "$desc"
      add_finding_once "file-temp-exec-$path" "FILE" "Archivos" "ALTO" \
        "Ejecutable, ELF o script en un directorio temporal" "$(file_metadata "$path"); tipo=$(sanitize_inline "$desc"); paquete=${package:-no_aplica}" \
        "Las áreas temporales son escribibles y se usan para cargas efímeras; el archivo no fue ejecutado por el script." \
        "Instaladores, sockets auxiliares, compilaciones y pruebas pueden crear artefactos legítimos." \
        "Conservar copia forense, hash, xattrs, proceso asociado, creador y línea temporal antes de retirar nada." "alta"
    fi
  fi

  if ((world_write == 1)); then
    suspicious=1; reason+="escritura_global; "
    local sev="MEDIO"
    [[ "$path" == /etc/* || "$path" == /usr/* || "$path" == /bin/* || "$path" == /sbin/* || "$path" == /lib/* || "$path" == /boot/* ]] && sev="ALTO"
    add_finding_once "file-worldwrite-$path" "FILE" "Archivos" "$sev" \
      "Archivo reciente escribible por cualquiera" "$(file_metadata "$path")" \
      "Otros usuarios podrían modificar contenido que luego sea cargado o ejecutado." \
      "Directorios colaborativos y archivos temporales pueden usar permisos globales deliberadamente." \
      "Revisar ACL, sticky bit del padre, consumidores del archivo y baseline de permisos." "alta"
  fi

  if [[ "$path" == /etc/* || "$path" == /usr/* || "$path" == /bin/* || "$path" == /sbin/* || "$path" == /lib/* || "$path" == /boot/* ]] && [[ "$uid" != "0" ]]; then
    suspicious=1; reason+="propietario_no_root_en_ruta_sistema; "
    add_finding_once "file-owner-$path" "FILE" "Archivos" "ALTO" \
      "Archivo reciente en ruta de sistema no pertenece a root" "$(file_metadata "$path")" \
      "La propiedad inesperada puede permitir manipulación por una cuenta sin privilegios." \
      "Bind mounts, contenedores, árboles de build o diseños especiales pueden explicarlo." \
      "Verificar mount namespace, ACL, paquete, origen del despliegue y cambios aprobados." "alta"
  fi

  if [[ "$base" =~ \.(jpg|jpeg|png|gif|pdf|doc|docx|txt)\.(sh|bash|py|pl|php|so|bin|run|desktop)$ ]] \
     || [[ "$base" =~ \.(sh|bash|py|pl|php|so|bin|run)\.(jpg|jpeg|png|gif|pdf|txt)$ ]]; then
    suspicious=1; reason+="extension_engañosa; "
    add_finding_once "deceptive-$path" "FILE" "Archivos" "MEDIO" \
      "Nombre de archivo con extensiones potencialmente engañosas" "$(file_metadata "$path"); tipo_real=$(sanitize_inline "$desc")" \
      "Las extensiones dobles pueden ocultar ejecutables o scripts frente a revisión superficial." \
      "Builds, ejemplos, copias de seguridad y nombres generados pueden ser legítimos." \
      "Comparar tipo real, contenido sin ejecutarlo, hash, origen y consumidores." "media"
  fi

  if [[ "$base" == .* ]] && ((executable == 1 || is_elf == 1)) && [[ "$base" != "." && "$base" != ".." ]]; then
    suspicious=1; reason+="ejecutable_oculto; "
    add_finding_once "hidden-exec-$path" "FILE" "Archivos" "MEDIO" \
      "Ejecutable reciente con nombre oculto" "$(file_metadata "$path"); tipo=$(sanitize_inline "$desc")" \
      "Ocultar un ejecutable puede reducir su visibilidad, pero los dotfiles son convencionales en Linux." \
      "Gestores de versiones, entornos virtuales y aplicaciones de usuario crean ejecutables ocultos legítimos." \
      "Validar función, paquete/origen, hash, proceso y persistencia relacionada." "media"
  fi

  if [[ "$base" =~ ^[A-Za-z0-9]{14,}$ ]] && ((executable == 1 || is_elf == 1 || is_script == 1)); then
    suspicious=1; reason+="nombre_aleatorio; "
    add_finding_once "random-name-$path" "FILE" "Archivos" "BAJO" \
      "Archivo ejecutable o script con nombre aparentemente aleatorio" "$(file_metadata "$path"); tipo=$(sanitize_inline "$desc")" \
      "Algunas cargas generan nombres aleatorios, pero esta señal aislada tiene baja especificidad." \
      "Cachés, contenido direccionado por hash, builds y temporales usan nombres similares." \
      "Correlacionar con ejecución, red, paquete, persistencia y hash antes de elevar severidad." "baja"
  fi

  if ((executable == 1 || is_elf == 1)) && [[ "$package" == "sin-paquete-dpkg" ]]; then
    suspicious=1; reason+="sin_paquete_dpkg; "
    local sev_np="BAJO"
    [[ "$path" == /tmp/* || "$path" == /var/tmp/* || "$path" == /dev/shm/* || "$path" == /usr/bin/* || "$path" == /usr/sbin/* || "$path" == /bin/* || "$path" == /sbin/* ]] && sev_np="MEDIO"
    add_finding_once "no-package-$path" "FILE" "Integridad" "$sev_np" \
      "Ejecutable reciente sin propietario dpkg identificado" "$(file_metadata "$path"); tipo=$(sanitize_inline "$desc")" \
      "Los binarios fuera de paquetes requieren atribuir su origen; desconocido no equivale a malicioso." \
      "Software compilado, /usr/local, AppImages, Snap, Flatpak y productos comerciales pueden no pertenecer a dpkg." \
      "Buscar manifiesto del producto, firma, hash, instalador, paquete alternativo y cambio autorizado." "media"
  fi

  if ((suspicious == 1)); then
    printf '%s\t%s\t\t%s\n' "$(safe_path "$path")" "$(sanitize_inline "$reason")" "$size" >> "$TMP_DIR/suspicious_files.tsv"
    hash_candidate "$path" "$reason" "$out"
  elif [[ "$MODE" == "full" ]] && ((HASH_FILES == 1 && (is_elf == 1 || executable == 1) )); then
    hash_candidate "$path" "ejecutable_reciente" "$out"
  fi
}

scan_recent_root() {
  local root="$1" origin="$2" max_results="$3" out="$OUTPUT_DIR/archivos_recientes.txt"
  ((TOTAL_FILES_INSPECTED < MAX_TOTAL_FILES)) || return 0
  [[ -d "$root" ]] || return 0
  path_is_excluded "$root" && return 0
  local -a cmd=()
  mapfile -d '' -t cmd < <(make_find_prefix "$root")
  [[ "${cmd[0]:-}" != "false" ]] || return 0
  cmd+=( -type f -newermt "$CUTOFF_TEXT" -print0 )
  printf '\n===== ARCHIVOS RECIENTES: %s =====\n' "$(safe_path "$root")" >> "$out"
  local path count=0 errfile
  errfile="$(mktemp "$TMP_DIR/find_err.XXXXXX")" || return 0
  while IFS= read -r -d '' path; do
    if ((TOTAL_FILES_INSPECTED >= MAX_TOTAL_FILES)); then
      printf '[límite global alcanzado: %s archivos inspeccionados]\n' "$MAX_TOTAL_FILES" >> "$out"
      if ((FILE_LIMIT_REPORTED == 0)); then
        add_limitation "Se alcanzó el límite global de $MAX_TOTAL_FILES archivos inspeccionados."
        FILE_LIMIT_REPORTED=1
      fi
      break
    fi
    count=$((count + 1))
    inspect_candidate_file "$path" "$origin"
    if ((count >= max_results)); then
      printf '[límite alcanzado: %s entradas en %s]\n' "$max_results" "$(safe_path "$root")" >> "$out"
      add_limitation "Búsqueda reciente truncada en $root tras $max_results archivos."
      break
    fi
  done < <(
    if have_cmd timeout; then
      timeout --signal=TERM --kill-after=5s "${COMMAND_TIMEOUT}s" "${cmd[@]}" 2>"$errfile"
    else
      "${cmd[@]}" 2>"$errfile"
    fi
  )
  if [[ -s "$errfile" ]]; then
    log_error "find recientes $(safe_path "$root")" "1" "$(head -n 4 "$errfile" | tr '\n' ' ')"
  fi
  rm -f -- "$errfile"
}

scan_since_boot_summary() {
  local out="$OUTPUT_DIR/archivos_recientes.txt" root count path
  ((BOOT_EPOCH > 0)) || { printf '\n[No se pudo determinar btime para cambios desde arranque]\n' >> "$out"; return 0; }
  local boot_text
  boot_text="$(date -d "@$BOOT_EPOCH" '+%Y-%m-%d %H:%M:%S %z' 2>/dev/null || true)"
  printf '\n===== CAMBIOS DESDE EL ÚLTIMO ARRANQUE (muestra crítica) =====\nInicio=%s\n' "$boot_text" >> "$out"
  for root in /etc /usr/local/bin /usr/local/sbin /boot /tmp /var/tmp /dev/shm; do
    [[ -d "$root" ]] || continue
    count=0
    while IFS= read -r -d '' path; do
      count=$((count + 1))
      printf '%s\n' "$(file_metadata "$path")" >> "$out"
      ((count >= 600)) && { printf '[muestra truncada en %s]\n' "$(safe_path "$root")" >> "$out"; break; }
    done < <(find "$root" -xdev -maxdepth "$MAX_DEPTH" \( -path "$OUTPUT_FIND_PATTERN" -o -path "$OUTPUT_FIND_PATTERN/*" \) -prune -o -type f -newermt "$boot_text" -print0 2>/dev/null)
  done
}

scan_temp_locations() {
  local out="$OUTPUT_DIR/archivos_recientes.txt" root path count desc mode
  printf '\n===== INVENTARIO LIMITADO DE TEMPORALES =====\n' >> "$out"
  for root in /tmp /var/tmp /dev/shm; do
    [[ -d "$root" ]] || continue
    count=0
    while IFS= read -r -d '' path; do
      count=$((count + 1))
      printf '%s\n' "$(file_metadata "$path")" >> "$out"
      mode="$(stat -c '%a' -- "$path" 2>/dev/null || printf '0')"
      desc="$(describe_file "$path" 400)"
      if { is_uint "$mode" && (( (8#$mode & 0111) != 0 )); } || [[ "$desc" == *ELF* ]] || [[ "$(head -c 2 -- "$path" 2>/dev/null || true)" == '#!' ]]; then
        if [[ -z "${SEEN_RECENT[$path]:-}" ]]; then
          inspect_candidate_file "$path" "inventario_temporal"
        fi
      fi
      ((count >= 2500)) && { printf '[inventario truncado en %s]\n' "$root" >> "$out"; add_limitation "Inventario de $root truncado a 2500 archivos."; break; }
    done < <(find "$root" -xdev -maxdepth "$MAX_DEPTH" \( -path "$OUTPUT_FIND_PATTERN" -o -path "$OUTPUT_FIND_PATTERN/*" \) -prune -o -type f -print0 2>/dev/null)
  done
}

scan_special_permissions() {
  local out="$OUTPUT_DIR/archivos_recientes.txt" path count=0 package mode
  printf '\n===== ARCHIVOS SUID/SGID =====\n' >> "$out"
  if [[ "$MODE" != "full" ]]; then
    printf '[Búsqueda global omitida en modo rápido; use --full.]\n' >> "$out"
    return 0
  fi
  while IFS= read -r -d '' path; do
    count=$((count + 1))
    package="$(package_owner "$path")"
    printf '%s paquete=%s\n' "$(file_metadata "$path")" "$package" >> "$out"
    if [[ "$package" == "sin-paquete-dpkg" ]]; then
      add_finding_once "suid-unowned-$path" "FILE" "Permisos especiales" "MEDIO" \
        "Archivo SUID/SGID sin propietario dpkg identificado" "$(file_metadata "$path")" \
        "SUID/SGID puede elevar privilegios y un binario local requiere atribución, pero no es malicioso por definición." \
        "Productos comerciales, software local o binarios administrativos pueden instalarlo deliberadamente." \
        "Comparar con baseline, firma/hash, código/origen, necesidad y fecha de instalación." "media"
      record_signal "path:$path" "privileged_binary" "SUID/SGID"
    fi
    if file_is_recent "$path"; then
      add_finding_once "suid-recent-$path" "FILE" "Permisos especiales" "MEDIO" \
        "Archivo SUID/SGID modificado recientemente" "$(file_metadata "$path"); paquete=$package" \
        "La combinación de privilegio especial y cambio reciente merece validación." \
        "Actualizaciones de paquetes pueden reemplazar binarios SUID/SGID legítimos." \
        "Verificar paquete, dpkg --verify, logs de actualización, hash y baseline." "alta"
      record_signal "path:$path" "recent_file" "$path"
    fi
    ((count >= 8000)) && { add_limitation "Lista SUID/SGID truncada a 8000 archivos."; break; }
  done < <(find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path "$OUTPUT_FIND_PATTERN" \) -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print0 2>/dev/null)

  printf '\n===== CAPABILITIES LINUX =====\n' >> "$out"
  if have_cmd getcap; then
    local caps="$TMP_DIR/capabilities.raw"
    capture_bounded "$caps" "búsqueda de capabilities" 420 find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path "$OUTPUT_FIND_PATTERN" \) -prune -o -type f -exec getcap -n '{}' +
    redact_stream < "$caps" | head -n 10000 >> "$out"
    while IFS= read -r line; do
      path="${line%% *}"
      [[ -n "$path" ]] || continue
      package="$(package_owner "$path")"
      if [[ "$package" == "sin-paquete-dpkg" ]]; then
        add_finding_once "cap-unowned-$path" "FILE" "Permisos especiales" "MEDIO" \
          "Binario con capabilities sin propietario dpkg" "$(sanitize_inline "$line"); paquete=$package" \
          "Capabilities pueden conceder privilegios selectivos y requieren atribución." \
          "Software local y contenedores pueden configurarlas de forma legítima." \
          "Validar necesidad, hash, propietario, xattrs, origen y baseline." "media"
        record_signal "path:$path" "privileged_binary" "$line"
      fi
    done < "$caps"
  else
    printf '[getcap no instalado; instale opcionalmente libcap2-bin con autorización.]\n' >> "$out"
    add_limitation "getcap no disponible; no se enumeraron capabilities de archivo."
  fi
}

scan_world_writable_system_files() {
  local out="$OUTPUT_DIR/archivos_recientes.txt" root path count=0
  printf '\n===== ARCHIVOS ESCRIBIBLES GLOBALMENTE EN RUTAS SENSIBLES =====\n' >> "$out"
  for root in /etc /usr/local /boot /opt; do
    [[ -d "$root" ]] || continue
    while IFS= read -r -d '' path; do
      count=$((count + 1))
      printf '%s\n' "$(file_metadata "$path")" >> "$out"
      add_finding_once "world-sensitive-$path" "FILE" "Permisos" "MEDIO" \
        "Archivo escribible globalmente en una ruta sensible" "$(file_metadata "$path")" \
        "Cualquier usuario local podría alterar contenido consumido por administradores o servicios." \
        "Áreas colaborativas específicas bajo /opt o /usr/local pueden estar diseñadas así." \
        "Revisar ACL, sticky bit, consumidores, propietario y baseline antes de corregir." "alta"
      ((count >= 3000)) && { add_limitation "Archivos world-writable sensibles truncados a 3000."; return 0; }
    done < <(find "$root" -xdev -maxdepth "$MAX_DEPTH" \( -path "$OUTPUT_FIND_PATTERN" -o -path "$OUTPUT_FIND_PATTERN/*" \) -prune -o -type f -perm -0002 -print0 2>/dev/null)
  done
}

scan_immutable_recent() {
  local out="$OUTPUT_DIR/archivos_recientes.txt" path attrs checked=0 listfile="$TMP_DIR/immutable_candidates.nul"
  printf '\n===== ATRIBUTO INMUTABLE (alcance: recientes y archivos críticos) =====\n' >> "$out"
  if ! have_cmd lsattr; then
    printf '[lsattr no disponible]\n' >> "$out"
    add_limitation "lsattr no disponible; no se comprobaron atributos inmutables."
    return 0
  fi
  {
    printf '%s\0' /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/hosts /etc/ld.so.preload
    [[ -f "$TMP_DIR/recent_paths.nul" ]] && cat "$TMP_DIR/recent_paths.nul"
  } > "$listfile"
  while IFS= read -r -d '' path; do
    [[ -e "$path" && ! -L "$path" ]] || continue
    checked=$((checked + 1)); ((checked <= 15000)) || break
    attrs="$(lsattr -d -- "$path" 2>/dev/null || true)"
    if [[ "${attrs%% *}" == *i* ]]; then
      printf '%s\n' "$(sanitize_inline "$attrs")" >> "$out"
      add_finding_once "immutable-$path" "FILE" "Atributos" "MEDIO" \
        "Archivo relevante tiene atributo inmutable" "$(sanitize_inline "$attrs"); $(file_metadata "$path")" \
        "El atributo puede dificultar cambios y se ha usado para proteger persistencia, pero también para endurecimiento." \
        "Administradores pueden marcar resolvers, cuentas o configuraciones como inmutables deliberadamente." \
        "Confirmar política, quién aplicó chattr, filesystem, paquete y necesidad; no retirar el atributo durante triage." "media"
    fi
  done < "$listfile"
}

scan_web_shell_indicators() {
  local out="$OUTPUT_DIR/archivos_recientes.txt" root file matches count=0 size max=6000
  printf '\n===== HEURÍSTICAS DE WEB SHELL (solo texto, no ejecución) =====\n' >> "$out"
  for root in /var/www /srv/www /usr/share/nginx/html; do
    [[ -d "$root" ]] || continue
    while IFS= read -r -d '' file; do
      count=$((count + 1)); ((count <= max)) || { add_limitation "Análisis web shell truncado a $max archivos."; return 0; }
      size="$(stat -c '%s' -- "$file" 2>/dev/null || printf '0')"
      is_uint "$size" && ((size <= 2 * 1024 * 1024)) || continue
      if [[ "$MODE" == "quick" ]] && ! file_is_recent "$file"; then continue; fi
      matches="$(grep -IEn 'eval[[:space:]]*\([[:space:]]*base64_decode|assert[[:space:]]*\([[:space:]]*\$_|preg_replace[[:space:]]*\(.*/e|shell_exec[[:space:]]*\([[:space:]]*\$_|passthru[[:space:]]*\([[:space:]]*\$_|system[[:space:]]*\([[:space:]]*\$_|proc_open[[:space:]]*\([[:space:]]*\$_|Runtime\.getRuntime\(\)\.exec|ProcessBuilder[[:space:]]*\(' "$file" 2>/dev/null | head -n 15 || true)"
      if [[ -n "$matches" ]]; then
        printf -- '-- %s --\n%s\n' "$(safe_path "$file")" "$(printf '%s' "$matches" | redact_stream)" >> "$out"
        add_finding_once "webshell-$file" "MAL" "Malware/Web" "ALTO" \
          "Archivo web coincide con patrones frecuentes de web shell" "ruta=$(safe_path "$file"); coincidencias=$(printf '%s' "$matches" | redact_stream | tr '\n' '; ')" \
          "La combinación de entrada de usuario y ejecución de comandos/código es de alto interés, pero requiere revisar el contexto." \
          "Frameworks, consolas administrativas, pruebas o código vulnerable pueden contener patrones similares." \
          "Preservar archivo/logs, calcular hash, revisar solicitudes y proceso web; validar código sin ejecutarlo." "media"
        record_signal "path:$file" "webshell_pattern" "$matches"
        record_signal "path:$file" "recent_file" "$file"
        hash_candidate "$file" "patron_webshell" "$out"
      fi
    done < <(find "$root" -xdev -maxdepth "$MAX_DEPTH" \( -path "$OUTPUT_FIND_PATTERN" -o -path "$OUTPUT_FIND_PATTERN/*" \) -prune -o -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.jsp' -o -iname '*.jspx' -o -iname '*.asp' -o -iname '*.aspx' \) -print0 2>/dev/null)
  done
}

collect_files() {
  local out="$OUTPUT_DIR/archivos_recientes.txt" root home user uid shell
  : > "$TMP_DIR/recent_paths.nul"
  : > "$TMP_DIR/suspicious_files.tsv"
  printf 'Configuración: días=%s cutoff=%s profundidad=%s hash_max=%sMiB include_home=%s modo=%s\n' \
    "$DAYS" "$CUTOFF_TEXT" "$MAX_DEPTH" "$MAX_HASH_MB" "$INCLUDE_HOME" "$MODE" >> "$out"
  printf 'Raíces configuradas: %s\n' "$(IFS=:; printf '%s' "${INCLUDE_DIRS[*]}")" >> "$out"
  printf 'Exclusiones configuradas: %s\n' "$(IFS=:; printf '%s' "${EXCLUDE_DIRS[*]}")" >> "$out"

  # Modo rápido limita raíces amplias; mantiene rutas críticas y temporales.
  if [[ "$MODE" == "quick" ]]; then
    for root in /etc /usr/local/bin /usr/local/sbin /boot /tmp /var/tmp /dev/shm; do
      scan_recent_root "$root" "ventana_principal" 1200
    done
  else
    for root in "${INCLUDE_DIRS[@]}"; do
      [[ -n "$root" ]] || continue
      scan_recent_root "$root" "ventana_principal" "$MAX_FIND_RESULTS"
    done
  fi

  if ((INCLUDE_HOME == 1)); then
    while IFS=: read -r user _ uid _ _ home shell; do
      [[ -d "$home" && "$home" == /* ]] || continue
      scan_recent_root "$home" "home_usuario=$user" "$MAX_FIND_RESULTS"
    done < /etc/passwd
  fi

  scan_since_boot_summary
  scan_temp_locations
  scan_special_permissions
  scan_world_writable_system_files
  scan_immutable_recent
  scan_web_shell_indicators
}

collect_apt_repositories() {
  local out="$1" file host external_hosts="$TMP_DIR/external_repo_hosts.txt" keyfile
  : > "$external_hosts"
  printf '\n===== REPOSITORIOS APT CONFIGURADOS (credenciales de URL redactadas) =====\n' >> "$out"
  local -a source_files=()
  [[ -f /etc/apt/sources.list ]] && source_files+=(/etc/apt/sources.list)
  if [[ -d /etc/apt/sources.list.d ]]; then
    while IFS= read -r -d '' file; do source_files+=("$file"); done \
      < <(find /etc/apt/sources.list.d -xdev -maxdepth 1 -type f \( -name '*.list' -o -name '*.sources' \) -print0 2>/dev/null)
  fi
  for file in "${source_files[@]}"; do
    printf -- '-- %s --\n' "$(safe_path "$file")" >> "$out"
    file_metadata "$file" >> "$out"
    grep -vE '^[[:space:]]*(#|$)' "$file" 2>/dev/null | head -n 500 | redact_stream >> "$out" || true
    while IFS= read -r host; do
      host="${host,,}"
      host="${host%%:*}"
      [[ -n "$host" ]] || continue
      case "$host" in
        archive.ubuntu.com|security.ubuntu.com|ports.ubuntu.com|*.archive.ubuntu.com|*.ubuntu.com|*.canonical.com) ;;
        *) printf '%s\t%s\n' "$host" "$file" >> "$external_hosts" ;;
      esac
    done < <(grep -Eho 'https?://[^/[:space:]]+' "$file" 2>/dev/null | sed -E 's#https?://([^/@]+@)?##')
  done
  if [[ -s "$external_hosts" ]]; then
    sort -u "$external_hosts" -o "$external_hosts"
    add_finding "PKG" "APT" "BAJO" \
      "Se detectaron repositorios APT externos a los dominios oficiales reconocidos" \
      "$(head -n 30 "$external_hosts" | redact_stream | tr '\n' '; ')" \
      "Repositorios externos amplían la cadena de suministro y deben atribuirse; no son maliciosos por definición." \
      "PPAs y proveedores de software legítimos requieren repositorios propios." \
      "Confirmar proveedor, firma, alcance, pinning, necesidad y aprobación; revisar cambios recientes." "alta"
  fi

  printf '\n===== PREFERENCIAS/PINNING APT =====\n' >> "$out"
  for file in /etc/apt/preferences /etc/apt/preferences.d/*; do
    [[ -f "$file" && -r "$file" ]] || continue
    printf -- '-- %s --\n' "$(safe_path "$file")" >> "$out"
    head -n 500 "$file" 2>/dev/null | redact_stream >> "$out" || true
  done

  printf '\n===== CLAVES DE REPOSITORIO: METADATOS Y HUELLAS =====\n' >> "$out"
  if have_cmd gpg; then
    for keyfile in /etc/apt/trusted.gpg /etc/apt/trusted.gpg.d/* /etc/apt/keyrings/* /usr/share/keyrings/*; do
      [[ -f "$keyfile" && -r "$keyfile" ]] || continue
      printf -- '-- %s --\n' "$(safe_path "$keyfile")" >> "$out"
      file_metadata "$keyfile" >> "$out"
      gpg --batch --show-keys --with-colons --fingerprint "$keyfile" 2>/dev/null \
        | awk -F: '$1=="pub" {print "pub algoritmo=" $4 " keyid=" $5 " creado=" $6 " expira=" $7} $1=="fpr" {print "fingerprint=" $10} $1=="uid" {print "uid=" $10}' \
        | head -n 300 | redact_stream >> "$out" || true
    done
  else
    printf '[gpg no disponible; solo se muestran metadatos de archivos de claves]\n' >> "$out"
    for keyfile in /etc/apt/trusted.gpg /etc/apt/trusted.gpg.d/* /etc/apt/keyrings/* /usr/share/keyrings/*; do
      [[ -f "$keyfile" ]] && file_metadata "$keyfile" >> "$out"
    done
    add_limitation "gpg no disponible; no se extrajeron huellas de claves APT."
  fi
}

collect_recent_packages() {
  local out="$1" cutoff_date pkglog="$TMP_DIR/dpkg_recent.log" file
  cutoff_date="$(date -d "@$CUTOFF_EPOCH" '+%Y-%m-%d' 2>/dev/null || printf '0000-00-00')"
  : > "$pkglog"
  if [[ -r /var/log/dpkg.log ]]; then
    awk -v c="$cutoff_date" '$1>=c && $3 ~ /^(install|upgrade|remove|purge|status)$/ {print}' /var/log/dpkg.log 2>/dev/null | tail -n 6000 >> "$pkglog" || true
  fi
  if [[ "$MODE" == "full" ]] && have_cmd zcat; then
    for file in /var/log/dpkg.log.*.gz; do
      [[ -r "$file" ]] || continue
      zcat -- "$file" 2>/dev/null | awk -v c="$cutoff_date" '$1>=c && $3 ~ /^(install|upgrade|remove|purge|status)$/ {print}' | tail -n 1500 >> "$pkglog" || true
    done
  fi
  printf '\n===== CAMBIOS RECIENTES DE PAQUETES =====\n' >> "$out"
  if [[ -s "$pkglog" ]]; then
    sort "$pkglog" | uniq | tail -n 6000 | redact_stream >> "$out"
  else
    printf '[No se localizaron eventos en los logs accesibles para la ventana.]\n' >> "$out"
  fi
  if [[ -r /var/log/apt/history.log ]]; then
    printf '\n===== APT HISTORY RECIENTE (limitado) =====\n' >> "$out"
    tail -n 800 /var/log/apt/history.log 2>/dev/null | redact_stream >> "$out" || true
  fi
}

find_local_origin_packages() {
  local out="$1" package policy installed block local_only checked=0 start local_list="$TMP_DIR/local_origin_packages.txt"
  : > "$local_list"
  have_cmd apt-cache && have_cmd apt-mark || { add_limitation "apt-cache/apt-mark no disponibles; no se estimaron paquetes sin origen."; return 0; }
  start="$(date +%s 2>/dev/null || printf '0')"
  while IFS= read -r package; do
    [[ -n "$package" ]] || continue
    checked=$((checked + 1))
    ((checked <= 800)) || { add_limitation "Comprobación de origen limitada a 800 paquetes manuales."; break; }
    policy="$(apt-cache policy "$package" 2>/dev/null | head -n 120)"
    installed="$(awk -F': ' '/^[[:space:]]+Installed:/ {print $2; exit}' <<< "$policy")"
    [[ -n "$installed" && "$installed" != "(none)" ]] || continue
    block="$(awk -v v="$installed" '
      $0 ~ "^[[:space:]]*\\*\\*\\*[[:space:]]+" v "([[:space:]]|$)" {inblock=1; print; next}
      inblock && $0 ~ "^[[:space:]]+[0-9]" && $0 !~ "^[[:space:]]+[0-9]+[[:space:]]+/ {exit}
      inblock {print}
    ' <<< "$policy")"
    local_only=0
    if grep -q '/var/lib/dpkg/status' <<< "$block" && ! grep -Eq '(https?://|ftp://|file:|cdrom:)' <<< "$block"; then
      local_only=1
    fi
    ((local_only == 1)) && printf '%s\t%s\n' "$package" "$installed" >> "$local_list"
    if is_uint "$start" && (( $(date +%s 2>/dev/null || printf '%s' "$start") - start > COMMAND_TIMEOUT * 4 )); then
      add_limitation "Comprobación de origen de paquetes detenida por límite global de tiempo."
      break
    fi
  done < <(apt-mark showmanual 2>/dev/null)
  printf '\n===== PAQUETES MANUALES SIN ORIGEN DE REPOSITORIO VISIBLE (estimación) =====\n' >> "$out"
  if [[ -s "$local_list" ]]; then
    head -n 800 "$local_list" >> "$out"
    add_finding "PKG" "APT" "BAJO" \
      "Paquetes instalados manualmente sin origen de repositorio visible" \
      "$(head -n 30 "$local_list" | tr '\n' '; ')" \
      "Un paquete local debe atribuirse, pero puede ser completamente legítimo; la heurística solo cubre una muestra manual." \
      "Paquetes internos, software comercial, builds propios y repositorios retirados producen este estado." \
      "Conservar .deb si existe, verificar firma/hash/proveedor, fecha de instalación y aprobación." "media"
  else
    printf '[Ninguno en la muestra o no determinable.]\n' >> "$out"
  fi
}

verify_important_commands() {
  local out="$1" name path real owner hash meta evidence=""
  printf '\n===== COMANDOS BÁSICOS: RUTA, PAQUETE Y SHA-256 =====\n' >> "$out"
  for name in bash sh sudo su ssh sshd ss ip ps ls find stat sha256sum dpkg apt systemctl journalctl login passwd; do
    path="$(command -v "$name" 2>/dev/null || true)"
    if [[ -z "$path" ]]; then
      printf '%s: no encontrado\n' "$name" >> "$out"
      continue
    fi
    real="$(readlink -f "$path" 2>/dev/null || printf '%s' "$path")"
    owner="$(package_owner "$real")"
    hash="$(sha256sum -- "$real" 2>/dev/null | awk '{print $1}')"
    meta="$(file_metadata "$real")"
    printf 'comando=%s ruta=%s real=%s paquete=%s sha256=%s %s\n' "$name" "$(safe_path "$path")" "$(safe_path "$real")" "$owner" "${hash:-no_disponible}" "$meta" >> "$out"
    if [[ "$owner" == "sin-paquete-dpkg" && ( "$real" == /usr/bin/* || "$real" == /usr/sbin/* || "$real" == /bin/* || "$real" == /sbin/* ) ]]; then
      add_finding_once "basic-unowned-$name" "PKG" "Integridad" "ALTO" \
        "Comando básico en ruta del sistema no pertenece a un paquete dpkg visible" "comando=$name real=$(safe_path "$real") sha256=$hash $meta" \
        "El reemplazo de herramientas básicas puede ocultar actividad o alterar resultados del triage." \
        "Binarios locales, diversiones de dpkg, usrmerge o imágenes personalizadas pueden confundir la consulta." \
        "Comparar desde medio confiable, revisar dpkg-query por rutas alternativas y validar contra paquete oficial sin reinstalar aún." "alta"
      record_signal "path:$real" "critical_binary_unowned" "$name"
    fi
    if [[ "$path" != /* ]]; then
      evidence+="$name=$path; "
    fi
  done
  if [[ -n "$evidence" ]]; then
    add_finding "PKG" "Integridad" "MEDIO" \
      "Comando básico resuelto mediante una ruta no absoluta" "$evidence" \
      "Aliases, funciones o PATH manipulados pueden desviar comandos; este caso requiere confirmar el tipo de resolución." \
      "Funciones de shell o wrappers administrativos pueden ser intencionales." \
      "Ejecutar type -a en un shell confiable y revisar PATH/perfiles." "media"
  fi
}

collect_package_integrity() {
  local out="$OUTPUT_DIR/integridad_paquetes.txt" verify="$TMP_DIR/dpkg_verify.raw" audit="$TMP_DIR/dpkg_audit.raw" anomalies="$TMP_DIR/dpkg_anomalies.txt"
  printf 'Modo=%s no_package_verify=%s\n' "$MODE" "$NO_PACKAGE_VERIFY" >> "$out"
  if have_cmd dpkg; then
    capture_bounded "$audit" "dpkg --audit" 120 dpkg --audit
    printf '\n===== DPKG AUDIT =====\n' >> "$out"
    redact_stream < "$audit" | head -n 2000 >> "$out"
    if [[ -s "$audit" ]]; then
      add_finding "PKG" "Paquetes" "MEDIO" \
        "dpkg informa paquetes en estado anómalo" "$(redact_stream < "$audit" | head -n 30 | tr '\n' '; ')" \
        "Estados incompletos pueden deberse a fallos o manipulación y reducen la confianza en la integridad." \
        "Actualizaciones interrumpidas, falta de espacio o dependencias rotas son causas comunes." \
        "Revisar logs de dpkg/APT y causa antes de reparar o reinstalar." "alta"
    fi
    dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}\t${Version}\n' 2>/dev/null \
      | awk '$1 !~ /^ii/ {print}' | head -n 3000 > "$anomalies" || true
    printf '\n===== ESTADOS DPKG DISTINTOS DE ii =====\n' >> "$out"
    cat "$anomalies" >> "$out"
  else
    : > "$audit"; : > "$anomalies"
    add_limitation "dpkg no disponible; integridad de paquetes no comprobada."
  fi

  collect_recent_packages "$out"
  collect_apt_repositories "$out"
  verify_important_commands "$out"

  if [[ "$MODE" == "full" && "$NO_PACKAGE_VERIFY" == "0" ]] && have_cmd dpkg; then
    capture_bounded "$verify" "dpkg --verify" 900 dpkg --verify
    printf '\n===== DPKG --VERIFY (salida limitada) =====\n' >> "$out"
    redact_stream < "$verify" | head -n 8000 >> "$out"
    if [[ -s "$verify" ]]; then
      add_finding "PKG" "Integridad" "MEDIO" \
        "dpkg --verify reporta diferencias locales" \
        "cantidad_aprox=$(wc -l < "$verify" | tr -d ' '); muestra=$(redact_stream < "$verify" | head -n 20 | tr '\n' '; ')" \
        "Diferencias pueden revelar archivos de paquete alterados, pero configuraciones y metadatos cambian legítimamente." \
        "Conffiles administrados, permisos locales y actualizaciones pueden producir diferencias esperadas." \
        "Clasificar cada línea, identificar paquete, comparar con cambio aprobado y obtener copia confiable para contraste." "media"
    fi
    if have_cmd debsums; then
      local debsum="$TMP_DIR/debsums.raw"
      capture_bounded "$debsum" "debsums -s" 900 debsums -s
      printf '\n===== DEBSUMS -s =====\n' >> "$out"
      redact_stream < "$debsum" | head -n 8000 >> "$out"
      if [[ -s "$debsum" ]]; then
        add_finding "PKG" "Integridad" "MEDIO" \
          "debsums informa archivos con suma ausente o distinta" "$(redact_stream < "$debsum" | head -n 25 | tr '\n' '; ')" \
          "Puede señalar modificación, aunque debsums no cubre todos los archivos y conffiles pueden cambiar." \
          "Cambios administrativos y paquetes sin sumas generan resultados legítimos." \
          "Verificar paquete, tipo de archivo, logs y baseline confiable antes de concluir manipulación." "media"
      fi
    else
      printf '[debsums no instalado; opcional y no descargado por el script]\n' >> "$out"
    fi
    find_local_origin_packages "$out"
  else
    printf '\n[Verificación exhaustiva de paquetes omitida por modo/opción.]\n' >> "$out"
    add_limitation "La verificación exhaustiva dpkg/debsums y el muestreo de origen requieren --full sin --no-package-verify."
  fi

  if have_cmd apt-cache; then
    run_limited "$out" "Política general APT" 2000 120 apt-cache policy
  fi
  if have_cmd apt-mark; then
    run_limited "$out" "Paquetes retenidos" 1000 60 apt-mark showhold
  fi
}

sanitize_web_log_stream() {
  sed -E 's#([?&][A-Za-z0-9_.-]+=)[^&[:space:]\"]+#\1[VALOR_REDACTADO]#g' | redact_stream
}

collect_logs() {
  local out="$OUTPUT_DIR/logs_relevantes.txt" journal="$TMP_DIR/journal_recent.raw" relevant="$TMP_DIR/journal_relevant.txt"
  printf 'Ventana principal desde: %s | máximo habitual por sección: %s líneas\n' "$CUTOFF_TEXT" "$MAX_LOG_LINES" >> "$out"
  prepare_auth_events

  if have_cmd journalctl; then
    if ((SINCE_BOOT == 1)); then
      capture_bounded "$journal" "journalctl desde boot" 300 journalctl -b --no-pager -o short-iso
    else
      capture_bounded "$journal" "journalctl reciente" 300 journalctl --since "$DAYS days ago" --no-pager -o short-iso
    fi
    grep -Eai 'sshd|sudo|su:|useradd|adduser|authentication failure|Failed password|Invalid user|Accepted (password|publickey)|apparmor|DENIED|audit|ufw|firewall|segfault|core dump|oom-kill|Out of memory|module|taint|signature|verification failed|journal.*(corrupt|rotate|vacuum)|log.*(clear|truncate)|systemd.*(Started|Stopped|Failed)|cron|CRON|atd' "$journal" 2>/dev/null \
      | tail -n "$MAX_LOG_LINES" > "$relevant" || true
    printf '\n===== JOURNAL: EVENTOS SELECCIONADOS =====\n' >> "$out"
    redact_stream < "$relevant" >> "$out"
    run_limited "$out" "Journal: boots conocidos" 500 60 journalctl --list-boots --no-pager
    run_limited "$out" "Journal: uso de disco" 100 30 journalctl --disk-usage
    run_limited "$out" "Journal kernel reciente" "$MAX_LOG_LINES" 120 journalctl -k -n "$MAX_LOG_LINES" --no-pager
    run_limited "$out" "Journal SSH" "$MAX_LOG_LINES" 120 journalctl -u ssh -u sshd -n "$MAX_LOG_LINES" --no-pager
  else
    : > "$journal"; : > "$relevant"
    add_limitation "journalctl no está disponible; se usaron solo logs de texto accesibles."
  fi

  printf '\n===== AUTH.LOG / EVENTOS DE AUTENTICACIÓN SELECCIONADOS =====\n' >> "$out"
  tail -n "$MAX_LOG_LINES" "$TMP_DIR/auth_events.raw" 2>/dev/null | redact_stream >> "$out" || true
  printf '\n===== RESUMEN DE AUTENTICACIÓN =====\n' >> "$out"
  printf 'SSH aceptados: %s\n' "$(grep -Eic 'sshd.*Accepted (password|publickey|keyboard-interactive)' "$TMP_DIR/auth_events.raw" 2>/dev/null || true)" >> "$out"
  printf 'SSH fallidos/usuarios inválidos: %s\n' "$(grep -Eic 'sshd.*(Failed password|Invalid user|authentication failure)' "$TMP_DIR/auth_events.raw" 2>/dev/null || true)" >> "$out"
  printf 'sudo/su: %s\n' "$(grep -Eic 'sudo|su:' "$TMP_DIR/auth_events.raw" 2>/dev/null || true)" >> "$out"
  printf 'creación/modificación de usuarios: %s\n' "$(grep -Eic 'useradd|adduser|new user|usermod' "$TMP_DIR/auth_events.raw" 2>/dev/null || true)" >> "$out"

  run_optional "$out" "Reinicios, apagados y runlevel" 500 60 last -x -F -n 150

  printf '\n===== METADATOS Y POSIBLE TRUNCADO DE LOGS =====\n' >> "$out"
  local log size zero_logs="" mtime
  for log in /var/log/auth.log /var/log/syslog /var/log/kern.log /var/log/ufw.log /var/log/dpkg.log /var/log/apt/history.log /var/log/audit/audit.log /var/log/wtmp /var/log/btmp /var/log/lastlog; do
    [[ -e "$log" ]] || continue
    file_metadata "$log" >> "$out"
    size="$(stat -c '%s' -- "$log" 2>/dev/null || printf '0')"
    mtime="$(stat -c '%Y' -- "$log" 2>/dev/null || printf '0')"
    if [[ "$size" == "0" ]] && is_uint "$mtime" && ((mtime >= CUTOFF_EPOCH)); then
      zero_logs+="$(safe_path "$log"); "
    fi
  done
  if [[ -n "$zero_logs" ]]; then
    add_finding "LOG" "Logs" "BAJO" \
      "Archivos de log relevantes están vacíos y tienen metadatos recientes" "$zero_logs" \
      "El truncado puede borrar evidencia, pero archivos vacíos aparecen tras rotación, configuración o inactividad." \
      "journald exclusivo, logrotate y servicios no activos son explicaciones habituales." \
      "Correlacionar con rotaciones, journal persistente, uptime, tamaño de rotados y configuración rsyslog." "baja"
  fi

  local clearing="$TMP_DIR/log_clearing.txt"
  {
    grep -Eai 'journalctl[[:space:]]+--(vacuum|rotate)|truncate[[:space:]].*(/var/log|auth.log|syslog)|rm[[:space:]].*/var/log|(:|cat /dev/null)[[:space:]]*>[[:space:]]*/var/log|history[[:space:]]+-c|unset[[:space:]]+HISTFILE|shred[[:space:]].*(log|history)' "$journal" "$TMP_DIR/auth_events.raw" 2>/dev/null || true
  } | head -n 100 > "$clearing"
  if [[ -s "$clearing" ]]; then
    printf '\n===== POSIBLES INDICIOS DE LIMPIEZA/ROTACIÓN MANUAL =====\n' >> "$out"
    redact_stream < "$clearing" >> "$out"
    add_finding "LOG" "Logs" "ALTO" \
      "Hay texto compatible con limpieza o truncado explícito de logs/historial" "$(redact_stream < "$clearing" | tr '\n' '; ')" \
      "La eliminación deliberada puede ser antiforense, pero la coincidencia textual no demuestra ejecución ni intención." \
      "Mantenimiento, privacidad, pruebas y rotación manual pueden justificar comandos similares." \
      "Confirmar si fue ejecutado, usuario/TTY, ticket, timestamps, logs remotos y evidencia rotada." "media"
    record_signal "logs:clearing" "anti_forensic" "posible limpieza de logs"
  fi

  # Huecos grandes en el journal del boot actual: señal de baja confianza.
  if have_cmd journalctl; then
    local epochs="$TMP_DIR/journal_epochs.txt" gaps="$TMP_DIR/journal_gaps.txt"
    capture_bounded "$epochs" "timestamps de journal" 180 journalctl -b --no-pager -o short-unix
    awk '
      match($0,/^[0-9]+\.[0-9]+/) {t=substr($0,RSTART,RLENGTH)+0; if(prev>0 && t-prev>21600) print "gap_seconds=" int(t-prev) " desde_epoch=" int(prev) " hasta_epoch=" int(t); prev=t}
    ' "$epochs" 2>/dev/null | head -n 30 > "$gaps"
    if [[ -s "$gaps" ]]; then
      printf '\n===== HUECOS >6H EN EVENTOS DEL BOOT ACTUAL =====\n' >> "$out"
      cat "$gaps" >> "$out"
      add_finding "LOG" "Logs" "BAJO" \
        "Se observan huecos temporales amplios en el journal del arranque actual" "$(tr '\n' '; ' < "$gaps")" \
        "Un hueco podría deberse a pérdida/limpieza de logs, pero no es específico y solo compara eventos presentes." \
        "Suspensión, equipo inactivo, reloj corregido, rate limiting o journal volátil son causas normales." \
        "Comparar con suspend/resume, boots, NTP, logs rotados/remotos y actividad esperada." "baja"
    fi
  fi

  printf '\n===== APPARMOR/UFW/AUDIT RELEVANTE =====\n' >> "$out"
  grep -Eai 'apparmor.*(DENIED|ALLOWED)|audit.*(AVC|USER_AUTH|USER_ACCT)|UFW (BLOCK|AUDIT|ALLOW)' "$journal" 2>/dev/null \
    | tail -n "$MAX_LOG_LINES" | redact_stream >> "$out" || true
  if grep -Eai 'apparmor.*DENIED.*(/tmp/|/var/tmp/|/dev/shm/)' "$journal" 2>/dev/null | head -n 30 > "$TMP_DIR/apparmor_temp.txt" && [[ -s "$TMP_DIR/apparmor_temp.txt" ]]; then
    add_finding "LOG" "AppArmor" "MEDIO" \
      "AppArmor denegó actividad relacionada con rutas temporales" "$(redact_stream < "$TMP_DIR/apparmor_temp.txt" | tr '\n' '; ')" \
      "Puede reflejar una carga anómala bloqueada o una aplicación legítima mal perfilada." \
      "Actualizaciones, software nuevo y perfiles estrictos generan denegaciones benignas." \
      "Identificar perfil, ejecutable, operación, frecuencia y cambio reciente; preservar eventos completos." "media"
  fi

  printf '\n===== LOGS APT/DPKG =====\n' >> "$out"
  for log in /var/log/apt/history.log /var/log/apt/term.log /var/log/dpkg.log; do
    [[ -r "$log" ]] || continue
    printf -- '-- %s --\n' "$(safe_path "$log")" >> "$out"
    tail -n "$MAX_LOG_LINES" "$log" 2>/dev/null | redact_stream >> "$out" || true
  done

  printf '\n===== LOGS WEB: SOLICITUDES DE INTERÉS (queries redactadas) =====\n' >> "$out"
  local webdir webfile webhits="$TMP_DIR/web_log_hits.txt"
  : > "$webhits"
  for webdir in /var/log/nginx /var/log/apache2; do
    [[ -d "$webdir" ]] || continue
    find "$webdir" -xdev -maxdepth 2 -type f -printf '%M %u:%g %s %TY-%Tm-%Td %TH:%TM:%TS %p\n' 2>/dev/null \
      | head -n 300 >> "$out" || true
    while IFS= read -r -d '' webfile; do
      tail -n 5000 "$webfile" 2>/dev/null \
        | grep -Eai '(\.php\?.*(cmd|exec|shell|passthru|system)=|/\.env|/wp-config\.php|/etc/passwd|\.\./|%2e%2e|/cgi-bin/|/vendor/phpunit|/actuator|/server-status|[[:space:]](401|403|404|500|502|503)[[:space:]])' \
        | tail -n 300 >> "$webhits" || true
    done < <(find "$webdir" -xdev -maxdepth 2 -type f \( -name '*access*.log' -o -name '*error*.log' -o -name 'access.log' -o -name 'error.log' \) -print0 2>/dev/null)
  done
  sanitize_web_log_stream < "$webhits" | tail -n "$MAX_LOG_LINES" >> "$out"
  if grep -Eai '(\.php\?.*(cmd|exec|shell|passthru|system)=|/vendor/phpunit|/\.env|/etc/passwd|\.\./|%2e%2e)' "$webhits" >/dev/null 2>&1; then
    add_finding "LOG" "Web" "MEDIO" \
      "Logs web contienen solicitudes compatibles con explotación o búsqueda de archivos sensibles" \
      "$(sanitize_web_log_stream < "$webhits" | head -n 20 | tr '\n' '; ')" \
      "Indica intentos observados, no éxito; debe correlacionarse con respuestas, procesos y archivos." \
      "Escaneo automatizado de Internet es común en servidores públicos y suele fallar." \
      "Revisar código de estado/tamaño, IP, timestamps, errores, procesos y archivos creados en la misma ventana." "media"
  fi
}

decode_taint() {
  local value="$1" bit label result=""
  local -a labels=(
    "0:PROPRIETARY_MODULE" "1:FORCED_MODULE" "2:CPU_OUT_OF_SPEC" "3:FORCED_RMMOD"
    "4:MACHINE_CHECK" "5:BAD_PAGE" "6:USER_TAINT" "7:DIE" "8:ACPI_OVERRIDE"
    "9:WARN" "10:CRAP" "11:FIRMWARE_WORKAROUND" "12:OUT_OF_TREE_MODULE"
    "13:UNSIGNED_MODULE" "14:SOFTLOCKUP" "15:LIVEPATCH" "16:AUX"
    "17:STRUCT_RANDOMIZED" "18:TEST"
  )
  for label in "${labels[@]}"; do
    bit="${label%%:*}"
    if (( (value & (1 << bit)) != 0 )); then result+="${label#*:},"; fi
  done
  printf '%s' "${result%,}"
}

collect_kernel() {
  local out="$OUTPUT_DIR/kernel.txt" taint="0" taint_desc="" secure_boot="desconocido"
  run_optional "$out" "Módulos cargados" 5000 120 lsmod
  if [[ -r /proc/sys/kernel/tainted ]]; then
    taint="$(tr -cd '0-9' < /proc/sys/kernel/tainted)"
    [[ -n "$taint" ]] || taint=0
    taint_desc="$(decode_taint "$taint")"
    printf '\n===== KERNEL TAINT =====\nvalor=%s flags=%s\n' "$taint" "${taint_desc:-ninguna}" >> "$out"
    if ((taint != 0)); then
      local sev="BAJO"
      [[ "$taint_desc" == *UNSIGNED_MODULE* || "$taint_desc" == *OUT_OF_TREE_MODULE* || "$taint_desc" == *PROPRIETARY_MODULE* ]] && sev="MEDIO"
      add_finding "KERN" "Kernel" "$sev" \
        "Kernel marcado como tainted" "valor=$taint flags=${taint_desc:-no_decodificadas}" \
        "Taint afecta soporte y puede señalar módulos no estándar o errores; no implica rootkit." \
        "Drivers propietarios, módulos DKMS, advertencias y fallos de hardware son causas frecuentes." \
        "Correlacionar flags con dmesg/journal, módulos, DKMS, Secure Boot y cambios de kernel." "alta"
    fi
  fi

  printf '\n===== PARÁMETROS SYSCTL SENSIBLES =====\n' >> "$out"
  local key value
  if have_cmd sysctl; then
    for key in kernel.kptr_restrict kernel.dmesg_restrict kernel.unprivileged_bpf_disabled kernel.yama.ptrace_scope kernel.perf_event_paranoid kernel.randomize_va_space kernel.modules_disabled fs.protected_hardlinks fs.protected_symlinks fs.protected_fifos fs.protected_regular net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.all.rp_filter; do
      value="$(sysctl -n "$key" 2>/dev/null || printf 'no_disponible')"
      printf '%s = %s\n' "$key" "$(sanitize_inline "$value")" >> "$out"
      case "$key:$value" in
        kernel.kptr_restrict:0|kernel.dmesg_restrict:0|kernel.randomize_va_space:0|fs.protected_hardlinks:0|fs.protected_symlinks:0)
          add_finding_once "weak-sysctl-$key" "KERN" "Endurecimiento" "BAJO" \
            "Parámetro sysctl sensible tiene un valor permisivo" "$key=$value" \
            "Puede facilitar ciertas técnicas pos-explotación, pero no es evidencia de que hayan ocurrido." \
            "Compatibilidad, depuración, contenedores o política local pueden requerirlo." \
            "Comparar con baseline de seguridad y archivos sysctl; no cambiar durante la adquisición." "alta" ;;
        net.ipv4.ip_forward:1|net.ipv6.conf.all.forwarding:1)
          add_finding_once "forwarding-$key" "KERN" "Red" "BAJO" \
            "Reenvío IP habilitado" "$key=$value" \
            "Permite función de router/túnel y merece contexto, pero es común en hosts de contenedores/VPN." \
            "Docker, Kubernetes, LXD, VPN o routers lo habilitan legítimamente." \
            "Correlacionar con interfaces, namespaces, reglas NAT y función esperada del host." "alta" ;;
      esac
    done
  else
    printf '[sysctl no disponible]\n' >> "$out"
    add_limitation "sysctl no disponible; no se consultaron parámetros sensibles."
  fi

  run_optional "$out" "Montajes" 8000 120 findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS
  run_optional "$out" "Dispositivos de bloque" 2000 60 lsblk -a -o NAME,KNAME,TYPE,FSTYPE,SIZE,RO,RM,MOUNTPOINTS,MODEL,SERIAL
  run_optional "$out" "Espacio y tipos de filesystem" 1000 60 df -hPT

  local mounts="$TMP_DIR/mounts.txt"
  if have_cmd findmnt; then
    findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS > "$mounts" 2>/dev/null || : > "$mounts"
  else
    cat /proc/mounts > "$mounts" 2>/dev/null || : > "$mounts"
  fi
  local target source fstype options
  while read -r target source fstype options; do
    case "$target" in
      /etc|/bin|/sbin|/usr/bin|/usr/sbin|/lib|/lib64|/boot)
        add_finding_once "mounted-over-$target" "KERN" "Montajes" "ALTO" \
          "Hay un montaje independiente sobre una ruta crítica" "target=$(safe_path "$target") source=$(safe_path "$source") fstype=$fstype options=$(sanitize_inline "$options")" \
          "Un bind/overlay puede sustituir archivos del sistema y alterar lo que ve el análisis." \
          "Contenedores, sistemas inmutables, /boot separado y diseños administrados pueden ser legítimos." \
          "Verificar fstab, unidad mount, namespace, origen y baseline del host." "media" ;;
    esac
    case "$fstype" in
      nfs|nfs4|cifs|smb3|sshfs|fuse.sshfs|9p)
        printf 'filesystem_remoto target=%s source=%s tipo=%s\n' "$(safe_path "$target")" "$(safe_path "$source")" "$fstype" >> "$out" ;;
      overlay|aufs|fuse.*|squashfs)
        printf 'filesystem_especial target=%s source=%s tipo=%s (frecuente en contenedores/Snap)\n' "$(safe_path "$target")" "$(safe_path "$source")" "$fstype" >> "$out" ;;
    esac
    if [[ "$source" == /tmp/* || "$source" == /var/tmp/* || "$source" == /dev/shm/* ]]; then
      add_finding_once "mount-temp-source-$target" "KERN" "Montajes" "ALTO" \
        "Montaje utiliza como origen una ruta temporal" "target=$(safe_path "$target") source=$(safe_path "$source") fstype=$fstype options=$(sanitize_inline "$options")" \
        "Puede sustituir contenido mediante una fuente escribible; requiere atribución inmediata." \
        "Imágenes temporales de pruebas o instaladores pueden montarse deliberadamente." \
        "Preservar origen, revisar proceso que montó, namespace, logs y contenido sin ejecutarlo." "media"
    fi
    if [[ "$target" == "/tmp" || "$target" == "/var/tmp" || "$target" == "/dev/shm" ]] \
       && { [[ ",$options," != *,nosuid,* ]] || [[ ",$options," != *,nodev,* ]]; }; then
      add_finding_once "mount-temp-options-$target" "KERN" "Endurecimiento" "BAJO" \
        "Montaje temporal separado carece de nosuid o nodev" "target=$target fstype=$fstype options=$(sanitize_inline "$options")" \
        "Opciones permisivas amplían impacto de archivos en un área escribible, pero no evidencian abuso." \
        "Compatibilidad de aplicaciones o herencia del filesystem puede justificar las opciones." \
        "Comparar con baseline/fstab y necesidades; no remontar durante triage." "alta"
    fi
    if [[ "$options" == *bind* && ( "$target" == /etc/* || "$target" == /usr/* || "$target" == /bin/* || "$target" == /sbin/* ) ]]; then
      add_finding_once "bind-critical-$target" "KERN" "Montajes" "MEDIO" \
        "Bind mount bajo una ruta crítica" "target=$(safe_path "$target") source=$(safe_path "$source") options=$(sanitize_inline "$options")" \
        "Puede reemplazar contenido y confundir comprobaciones de integridad." \
        "Contenedores, chroots y configuración declarativa usan bind mounts legítimos." \
        "Revisar namespace, fstab/unidad mount, origen y propósito." "media"
    fi
  done < "$mounts"

  printf '\n===== MÓDULOS: FIRMA Y ORIGEN (modo completo) =====\n' >> "$out"
  if [[ "$MODE" == "full" ]] && have_cmd modinfo && have_cmd lsmod; then
    local mod signer filename unsigned=0 total=0 outtree=0 sample=""
    while read -r mod _; do
      [[ "$mod" == "Module" || -z "$mod" ]] && continue
      total=$((total + 1))
      signer="$(modinfo -F signer "$mod" 2>/dev/null | head -n 1)"
      filename="$(modinfo -F filename "$mod" 2>/dev/null | head -n 1)"
      printf 'modulo=%s signer=%s archivo=%s paquete=%s\n' "$mod" "${signer:-sin_firma_visible}" "$(safe_path "$filename")" "$([[ -n "$filename" ]] && package_owner "$filename" || printf 'desconocido')" >> "$out"
      if [[ -z "$signer" ]]; then unsigned=$((unsigned + 1)); sample+="$mod,$(safe_path "$filename"); "; fi
      [[ "$filename" == */updates/dkms/* || "$filename" == */extra/* ]] && outtree=$((outtree + 1))
    done < <(lsmod 2>/dev/null)
    printf 'resumen_modulos total=%s sin_firma_visible=%s out_of_tree_estimados=%s\n' "$total" "$unsigned" "$outtree" >> "$out"
    if ((unsigned > 0)); then
      add_finding "KERN" "Kernel" "BAJO" \
        "Hay módulos cargados sin firmante visible para modinfo" "cantidad=$unsigned/$total muestra=$(sanitize_inline "$sample")" \
        "Puede ser relevante con Secure Boot, pero ausencia de campo signer no demuestra modificación o carga maliciosa." \
        "Módulos integrados, DKMS legítimo, kernels personalizados y Secure Boot desactivado pueden explicarlo." \
        "Comparar con mokutil, journal de carga, paquete/DKMS y baseline del kernel." "media"
    fi
  else
    printf '[Detalle de firmas omitido: requiere --full, modinfo y lsmod.]\n' >> "$out"
  fi

  local modroot="/lib/modules/$(uname -r 2>/dev/null)"
  printf '\n===== ARCHIVOS DE MÓDULO RECIENTES =====\n' >> "$out"
  if [[ -d "$modroot" ]]; then
    find "$modroot" -xdev -type f -newermt "$CUTOFF_TEXT" -printf '%M %u:%g %s %TY-%Tm-%Td %TH:%TM:%TS %p\n' 2>/dev/null \
      | head -n 2000 | redact_stream >> "$out" || true
  fi

  collect_containers "$out"
}

collect_containers() {
  local out="$1" ids id count=0 docker_socket=""
  printf '\n===== CONTENEDORES Y PROCESOS EN CGROUPS =====\n' >> "$out"
  if [[ -S /var/run/docker.sock ]]; then
    docker_socket="/var/run/docker.sock"
  elif [[ -S "/run/user/$(id -u 2>/dev/null)/docker.sock" ]]; then
    docker_socket="/run/user/$(id -u 2>/dev/null)/docker.sock"
  fi
  if have_cmd docker && [[ -n "$docker_socket" ]]; then
    # --host unix:// impide que DOCKER_HOST/contextos configurados contacten un daemon remoto.
    run_limited "$out" "Docker local: contenedores" 1000 90 docker --host "unix://$docker_socket" ps -a --no-trunc --format 'id={{.ID}} name={{.Names}} image={{.Image}} status={{.Status}} ports={{.Ports}}'
    ids="$(docker --host "unix://$docker_socket" ps -q 2>/dev/null | head -n 30)"
    while IFS= read -r id; do
      [[ -n "$id" ]] || continue
      count=$((count + 1))
      run_limited "$out" "Docker local top $id" 500 45 docker --host "unix://$docker_socket" top "$id" -eo pid,ppid,user,etimes,comm,args
    done <<< "$ids"
  else
    printf '[docker CLI o socket Unix local no disponible; no se usa DOCKER_HOST remoto]\n' >> "$out"
  fi
  printf '\n===== INVENTARIO LOCAL LXD/LXC/INCUS (sin contactar remotes) =====\n' >> "$out"
  local container_dir
  for container_dir in /var/lib/lxc /var/lib/lxd/containers /var/snap/lxd/common/lxd/containers /var/lib/incus/containers; do
    [[ -d "$container_dir" ]] || continue
    find "$container_dir" -xdev -mindepth 1 -maxdepth 2 -printf '%y %M %u:%g %TY-%Tm-%Td %TH:%TM:%TS %p\n' 2>/dev/null \
      | head -n 1500 | redact_stream >> "$out" || true
  done
  if have_cmd machinectl; then
    run_limited "$out" "systemd-machined" 500 45 machinectl list --no-pager
  fi
  printf '\n===== PIDS CON CGROUPS DE CONTENEDOR =====\n' >> "$out"
  local procdir pid cgroup comm
  for procdir in /proc/[0-9]*; do
    [[ -r "$procdir/cgroup" ]] || continue
    cgroup="$(grep -E 'docker|containerd|kubepods|lxc|libpod|podman|machine.slice' "$procdir/cgroup" 2>/dev/null | head -n 3)"
    [[ -n "$cgroup" ]] || continue
    pid="${procdir##*/}"
    comm="$(tr '\000\n' '  ' < "$procdir/comm" 2>/dev/null | cut -c1-100)"
    printf 'pid=%s comm=%s cgroup=%s\n' "$pid" "$(sanitize_inline "$comm")" "$(sanitize_inline "$cgroup")" >> "$out"
  done
}

history_pattern() {
  printf '%s' '(curl|wget).*(\|[[:space:]]*(sh|bash)|-o[[:space:]]+/tmp|--output[[:space:]]+/tmp)|(^|[;|&[:space:]])(useradd|adduser|usermod|groupadd)[[:space:]]|chmod[[:space:]]+([0-7]*7[0-7]{2}|u\+s|[0-7]*4[0-7]{3})|chown[[:space:]]+root|ufw[[:space:]]+(disable|reset)|systemctl[[:space:]]+(stop|disable|mask)[[:space:]]+(ufw|apparmor|auditd|rsyslog)|truncate.*(/var/log|auth\.log|syslog)|rm.*(/var/log|auth\.log|syslog)|history[[:space:]]+-c|unset[[:space:]]+HISTFILE|sed.*sshd_config|PermitRootLogin|PasswordAuthentication|authorized_keys|ssh[[:space:]].*-[A-Za-z]*[LRD]|(^|[;|&[:space:]])(nc|ncat|netcat|socat|chisel|ngrok|cloudflared|frpc|ligolo-agent)([[:space:]]|$)|(/tmp/|/var/tmp/|/dev/shm/).*(chmod|bash|sh|python|perl|php)|base64[[:space:]]+(-d|--decode)|\/dev\/tcp\/|bash[[:space:]]+-i|python[0-9.]*[[:space:]]+-c|perl[[:space:]]+-e|php[[:space:]]+-r'
}

scan_histories() {
  local out="$1" user uid home shell hist matches count=0 total_matches=0 strong=0
  if ((NO_HISTORY == 1)); then
    printf '\n[Análisis de historiales omitido por --no-history.]\n' >> "$out"
    add_limitation "Historiales de shell omitidos por --no-history."
    return 0
  fi
  printf '\n===== HISTORIALES: SOLO COINCIDENCIAS RELEVANTES Y REDACTADAS =====\n' >> "$out"
  while IFS=: read -r user _ uid _ _ home shell; do
    [[ -d "$home" ]] || continue
    for hist in "$home/.bash_history" "$home/.zsh_history" "$home/.history" "$home/.local/share/fish/fish_history"; do
      [[ -f "$hist" && -r "$hist" ]] || continue
      count=$((count + 1)); ((count <= 1000)) || { add_limitation "Historiales limitados a 1000 archivos."; return 0; }
      matches="$(grep -Ein "$(history_pattern)" "$hist" 2>/dev/null | tail -n 120 || true)"
      [[ -n "$matches" ]] || continue
      local n
      n="$(printf '%s\n' "$matches" | wc -l | tr -d ' ')"; total_matches=$((total_matches + n))
      printf -- '-- usuario=%s archivo=%s coincidencias=%s --\n' "$user" "$(safe_path "$hist")" "$n" >> "$out"
      printf '%s\n' "$matches" | redact_stream | cut -c1-1200 >> "$out"
      if grep -Eqi '(curl|wget).*\|[[:space:]]*(sh|bash)|/dev/tcp/|bash[[:space:]]+-i|nc.*-e|socat.*exec|truncate.*(/var/log|auth\.log)|rm.*(/var/log|auth\.log)|history[[:space:]]+-c' <<< "$matches"; then
        strong=$((strong + 1))
        add_finding_once "history-strong-$hist" "MAL" "Historial" "ALTO" \
          "Historial contiene patrón de descarga-ejecución, reverse shell o limpieza de evidencia" \
          "usuario=$user archivo=$(safe_path "$hist") muestra=$(printf '%s' "$matches" | redact_stream | head -n 12 | tr '\n' '; ')" \
          "El texto es compatible con acciones de alto riesgo, pero un historial no demuestra ejecución exitosa ni intención." \
          "Laboratorios, respuesta a incidentes, documentación pegada y administración pueden generar comandos similares." \
          "Construir línea temporal con audit/journal, archivos creados, procesos, red y contexto del usuario." "media"
        record_signal "history:$hist" "dangerous_command" "usuario=$user"
      else
        add_finding_once "history-interest-$hist" "HIST" "Historial" "MEDIO" \
          "Historial contiene comandos relevantes para seguridad" \
          "usuario=$user archivo=$(safe_path "$hist") coincidencias=$n muestra=$(printf '%s' "$matches" | redact_stream | head -n 10 | tr '\n' '; ')" \
          "Puede orientar hacia cambios de acceso, permisos, túneles o ejecución temporal; requiere corroboración." \
          "Administración legítima y solución de problemas usan los mismos comandos." \
          "Correlacionar timestamp cuando exista, sudo/audit, cambios de archivos y ticket de mantenimiento." "media"
      fi
    done
  done < /etc/passwd
  printf 'Resumen historiales: archivos_con_coincidencias=%s coincidencias_limitadas=%s patrones_fuertes=%s\n' "$count" "$total_matches" "$strong" >> "$out"
}

scan_recent_scripts_for_patterns() {
  local out="$1" file size desc matches scanned=0 max=8000
  printf '\n===== SCRIPTS RECIENTES: REVERSE SHELL, DESCARGA Y OFUSCACIÓN =====\n' >> "$out"
  [[ -f "$TMP_DIR/recent_paths.nul" ]] || return 0
  while IFS= read -r -d '' file; do
    [[ -f "$file" && -r "$file" && ! -L "$file" ]] || continue
    scanned=$((scanned + 1)); ((scanned <= max)) || { add_limitation "Análisis de scripts truncado a $max archivos recientes."; break; }
    size="$(stat -c '%s' -- "$file" 2>/dev/null || printf '0')"
    is_uint "$size" && ((size <= 2 * 1024 * 1024)) || continue
    desc="$(describe_file "$file" 300)"
    [[ "$desc" =~ (script|text|JSON|XML|PHP|Python|Perl|shell|ASCII|UTF-8) ]] || [[ "$(head -c 2 -- "$file" 2>/dev/null || true)" == '#!' ]] || continue
    matches="$(grep -IEn '(/dev/(tcp|udp)/|bash[[:space:]]+-i|sh[[:space:]]+-i|nc(at|)[[:space:]].*(-e|--exec)|socat.*(EXEC|SYSTEM):|mkfifo.*(nc|socat)|socket\.(socket|create_connection)|subprocess\.(Popen|call).*socket|curl.*\|.*(sh|bash)|wget.*\|.*(sh|bash)|base64[[:space:]]+(-d|--decode)|eval[[:space:]]*\(|exec[[:space:]]*\(|[A-Za-z0-9+/]{200,}={0,2}|\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}|\$\{IFS\})' "$file" 2>/dev/null | head -n 30 || true)"
    [[ -n "$matches" ]] || continue
    printf -- '-- %s tipo=%s --\n%s\n' "$(safe_path "$file")" "$(sanitize_inline "$desc")" "$(printf '%s' "$matches" | redact_stream)" >> "$out"
    local sev="MEDIO"
    grep -Eqi '(/dev/(tcp|udp)/|bash[[:space:]]+-i|nc(at|).* -e|socat.*(EXEC|SYSTEM)|curl.*\|.*(sh|bash)|wget.*\|.*(sh|bash))' <<< "$matches" && sev="ALTO"
    add_finding_once "script-pattern-$file" "MAL" "Malware/Scripts" "$sev" \
      "Script reciente contiene patrón de reverse shell, descarga-ejecución u ofuscación" \
      "ruta=$(safe_path "$file") tipo=$(sanitize_inline "$desc") coincidencias=$(printf '%s' "$matches" | redact_stream | tr '\n' '; ')" \
      "Los patrones pueden ejecutar código remoto u ocultar intención, pero también aparecen en herramientas defensivas y pruebas." \
      "Scripts de laboratorio, instaladores, empaquetado y datos incrustados pueden coincidir legítimamente." \
      "Revisar el archivo completo de forma estática, autor/origen, hash, llamadas, proceso y red; no ejecutarlo." "media"
    record_signal "path:$file" "suspicious_script" "$matches"
    hash_candidate "$file" "patron_script_sospechoso" "$OUTPUT_DIR/archivos_recientes.txt"
  done < "$TMP_DIR/recent_paths.nul"
}

scan_tool_and_miner_names() {
  local out="$1" root file count=0 evidence="$TMP_DIR/tool_name_hits.txt"
  : > "$evidence"
  printf '\n===== NOMBRES DE MINERÍA, TÚNEL Y MALWARE CONOCIDO (heurística) =====\n' >> "$out"
  for root in /usr/local/bin /usr/local/sbin /opt /tmp /var/tmp /dev/shm; do
    [[ -d "$root" ]] || continue
    while IFS= read -r -d '' file; do
      count=$((count + 1)); ((count <= 3000)) || break
      printf '%s\t%s\n' "$(safe_path "$file")" "$(describe_file "$file" 250)" >> "$evidence"
    done < <(find "$root" -xdev -maxdepth "$MAX_DEPTH" \( -path "$OUTPUT_FIND_PATTERN" -o -path "$OUTPUT_FIND_PATTERN/*" \) -prune -o -type f \( -iname 'xmrig*' -o -iname 'minerd*' -o -iname 'cpuminer*' -o -iname 'ethminer*' -o -iname 'kinsing*' -o -iname 'chisel*' -o -iname 'ngrok*' -o -iname 'frpc*' -o -iname 'frps*' -o -iname 'ligolo*' -o -iname 'gost*' \) -print0 2>/dev/null)
  done
  if ((INCLUDE_HOME == 1)); then
    while IFS=: read -r _ _ _ _ _ root _; do
      [[ -d "$root" ]] || continue
      while IFS= read -r -d '' file; do
        count=$((count + 1)); ((count <= 3000)) || break 2
        printf '%s\t%s\n' "$(safe_path "$file")" "$(describe_file "$file" 250)" >> "$evidence"
      done < <(find "$root" -xdev -maxdepth "$MAX_DEPTH" \( -path "$OUTPUT_FIND_PATTERN" -o -path "$OUTPUT_FIND_PATTERN/*" \) -prune -o -type f \( -iname 'xmrig*' -o -iname 'minerd*' -o -iname 'cpuminer*' -o -iname 'ethminer*' -o -iname 'kinsing*' -o -iname 'chisel*' -o -iname 'ngrok*' -o -iname 'frpc*' -o -iname 'ligolo*' \) -print0 2>/dev/null)
    done < /etc/passwd
  fi
  redact_stream < "$evidence" | head -n 3000 >> "$out"
  if grep -Eai '(xmrig|minerd|cpuminer|ethminer|kinsing)' "$evidence" >/dev/null 2>&1; then
    add_finding "MAL" "Malware/Minería" "MEDIO" \
      "Archivos tienen nombres asociados a minería o familias conocidas" "$(grep -Eai '(xmrig|minerd|cpuminer|ethminer|kinsing)' "$evidence" | head -n 30 | redact_stream | tr '\n' '; ')" \
      "El nombre orienta la búsqueda, pero puede cambiarse y también corresponder a software instalado conscientemente o muestras." \
      "Minería autorizada, laboratorios, repositorios y muestras inertes son explicaciones posibles." \
      "Verificar tipo, hash, ejecución, proceso padre, persistencia, consumo y autorización sin abrir/ejecutar el archivo." "media"
  fi

  local psminers="$TMP_DIR/miner_processes.txt"
  : > "$psminers"
  if have_cmd ps; then
    ps -eo pid=,user=,pcpu=,pmem=,comm=,args= --width 1000 2>/dev/null \
      | grep -Eai '(^|[[:space:]/])(xmrig|minerd|cpuminer|ethminer|kinsing)([[:space:]]|$)' \
      | grep -v '[g]rep' | head -n 100 > "$psminers" || true
  fi
  if [[ -s "$psminers" ]]; then
    add_finding "MAL" "Malware/Minería" "ALTO" \
      "Proceso en ejecución coincide con nombres de minería o malware conocido" "$(redact_stream < "$psminers" | tr '\n' '; ')" \
      "La ejecución es más relevante que la mera presencia, pero el nombre sigue sin demostrar autorización o identidad del binario." \
      "Minería autorizada o análisis de una muestra pueden explicar el proceso." \
      "Preservar memoria/binario, hash, cgroup, usuario, padre, sockets y autorización antes de contener." "media"
  fi
}

collect_malware_and_history() {
  local out="$OUTPUT_DIR/logs_relevantes.txt"
  printf '\n########## INDICADORES LOCALES DE MALWARE/HERRAMIENTAS ##########\n' >> "$out"
  scan_histories "$out"
  scan_recent_scripts_for_patterns "$out"
  scan_tool_and_miner_names "$out"
}

correlate_findings() {
  local entity evidence count=0 sev
  for entity in "${!SIGNAL_ENTITIES[@]}"; do
    ((count < 200)) || { add_limitation "Correlaciones limitadas a 200 entidades con señales."; break; }
    if [[ "$entity" == pid:* ]] && has_signal "$entity" temp_exec && has_signal "$entity" remote_connection && has_signal "$entity" root_exec; then
      count=$((count + 1))
      evidence="entidad=$entity; temp=$(signal_evidence "$entity" temp_exec); red=$(signal_evidence "$entity" remote_connection); root=$(signal_evidence "$entity" root_exec)"
      add_finding_once "corr-root-temp-net-$entity" "CORR" "Correlación" "CRÍTICO" \
        "Mismo proceso: root + ejecución temporal + conexión remota" "$evidence" \
        "La coincidencia por PID concentra privilegio, ubicación escribible y comunicación; es una combinación de prioridad máxima." \
        "Actualizadores, instaladores o respuesta a incidentes pueden producirla legítimamente." \
        "Preservar memoria, ejecutable, hash, árbol, sockets, logs y usuario; iniciar procedimiento formal de incidente." "alta"
    elif [[ "$entity" == pid:* ]] && has_signal "$entity" deleted_exec && has_signal "$entity" remote_connection; then
      count=$((count + 1))
      sev="ALTO"; has_signal "$entity" root_exec && sev="CRÍTICO"
      evidence="entidad=$entity; eliminado=$(signal_evidence "$entity" deleted_exec); red=$(signal_evidence "$entity" remote_connection)"
      add_finding_once "corr-deleted-net-$entity" "CORR" "Correlación" "$sev" \
        "Mismo proceso: ejecutable eliminado + conexión remota" "$evidence" \
        "El código sigue activo sin archivo enlazado y mantiene comunicación, lo que dificulta atribución y preservación." \
        "Un daemon actualizado puede conservar conexiones hasta reiniciarse." \
        "Adquirir mapas/memoria y contexto de paquete/actualización antes de reiniciar o terminar el proceso." "alta"
    elif [[ "$entity" == pid:* ]] && has_signal "$entity" unknown_listener && has_signal "$entity" no_package && has_signal "$entity" wildcard_listener; then
      count=$((count + 1))
      evidence="entidad=$entity; escucha=$(signal_evidence "$entity" unknown_listener); paquete=$(signal_evidence "$entity" no_package); wildcard=$(signal_evidence "$entity" wildcard_listener)"
      add_finding_once "corr-unknown-listener-$entity" "CORR" "Correlación" "ALTO" \
        "Mismo proceso: escucha amplia + binario sin paquete + servicio no atribuido" "$evidence" \
        "La combinación reduce trazabilidad y aumenta exposición, aunque software local legítimo puede cumplirla." \
        "Aplicaciones internas, productos comerciales, contenedores y binarios compilados localmente." \
        "Identificar propietario/servicio, hash, origen, firewall, clientes y cambio autorizado." "alta"
    fi

    if [[ "$entity" == path:* ]] && has_signal "$entity" persistence && has_signal "$entity" recent_file \
       && { has_signal "$entity" temp_exec || has_signal "$entity" home_exec || has_signal "$entity" no_package || has_signal "$entity" suspicious_script; }; then
      count=$((count + 1))
      sev="ALTO"
      has_signal "$entity" temp_exec && has_signal "$entity" root_exec && sev="CRÍTICO"
      evidence="entidad=$entity; persistencia=$(signal_evidence "$entity" persistence); reciente=$(signal_evidence "$entity" recent_file)"
      has_signal "$entity" temp_exec && evidence+="; temporal=$(signal_evidence "$entity" temp_exec)"
      has_signal "$entity" no_package && evidence+="; sin_paquete=$(signal_evidence "$entity" no_package)"
      has_signal "$entity" suspicious_script && evidence+="; script=$(signal_evidence "$entity" suspicious_script)"
      add_finding_once "corr-persist-recent-$entity" "CORR" "Correlación" "$sev" \
        "Misma ruta: persistencia + cambio reciente + indicador adicional" "$evidence" \
        "La correlación por ruta es más específica que cada señal aislada y merece revisión prioritaria." \
        "Un despliegue o instalación reciente y autorizada puede crear exactamente esta combinación." \
        "Validar cambio, paquete/proveedor, contenido estático, hash, usuario efectivo y logs de primera ejecución." "alta"
    fi

    if [[ "$entity" == ip:* ]] && has_signal "$entity" auth_fail_success && has_signal "$entity" remote_connection; then
      count=$((count + 1))
      evidence="entidad=$entity; auth=$(signal_evidence "$entity" auth_fail_success); conexión=$(signal_evidence "$entity" remote_connection)"
      add_finding_once "corr-auth-net-$entity" "CORR" "Correlación" "ALTO" \
        "Misma IP: fallos, acceso aceptado y conexión actualmente visible" "$evidence" \
        "Puede representar acceso interactivo tras tanteo, pero la conexión actual podría ser legítima y de otro proceso." \
        "Un administrador puede fallar credenciales y mantener una sesión autorizada." \
        "Ordenar eventos, identificar usuario/método/PID, validar la IP con el propietario y revisar actividad de sesión." "media"
    fi

    if [[ "$entity" == path:* ]] && has_signal "$entity" webshell_pattern && has_signal "$entity" persistence; then
      count=$((count + 1))
      add_finding_once "corr-web-persist-$entity" "CORR" "Correlación" "CRÍTICO" \
        "Misma ruta: patrón de web shell y mecanismo de persistencia" \
        "entidad=$entity; web=$(signal_evidence "$entity" webshell_pattern); persistencia=$(signal_evidence "$entity" persistence)" \
        "Combina ejecución web potencial con reactivación automática y requiere respuesta prioritaria." \
        "Herramientas administrativas web o pruebas pueden activar ambas heurísticas." \
        "Preservar archivo, logs web, proceso, memoria y timeline; activar respuesta formal antes de modificar." "alta"
    fi
  done
  printf '%s\n' "$count" > "$TMP_DIR/correlation_count"
}

risk_level() {
  local score="$1"
  if ((score >= 70)); then printf 'CRÍTICO'
  elif ((score >= 45)); then printf 'ALTO'
  elif ((score >= 20)); then printf 'MEDIO'
  elif ((score >= 5)); then printf 'BAJO'
  else printf 'INFORMATIVO'
  fi
}

generate_summary() {
  local out="$OUTPUT_DIR/resumen.txt" score level duration errors correlations topfile="$TMP_DIR/top_findings.txt"
  local n_low n_medium n_high n_critical c_low c_medium c_high c_critical
  n_low="${SEVERITY_COUNT[BAJO]:-0}"; n_medium="${SEVERITY_COUNT[MEDIO]:-0}"
  n_high="${SEVERITY_COUNT[ALTO]:-0}"; n_critical="${SEVERITY_COUNT[CRÍTICO]:-0}"
  c_low="$n_low"; ((c_low > 10)) && c_low=10
  c_medium="$n_medium"; ((c_medium > 8)) && c_medium=8
  c_high="$n_high"; ((c_high > 5)) && c_high=5
  c_critical="$n_critical"; ((c_critical > 3)) && c_critical=3
  # Rendimiento decreciente evita que decenas de variantes de una misma señal
  # débil dominen la puntuación. Un hallazgo crítico fija un suelo crítico.
  score=$((c_low + c_medium * 3 + c_high * 10 + c_critical * 25))
  if ((n_critical > 0 && score < 70)); then score=70
  elif ((n_high > 0 && score < 45)); then score=45
  elif ((n_medium > 0 && score < 20)); then score=20
  elif ((n_low > 0 && score < 5)); then score=5
  fi
  ((score > 100)) && score=100
  level="$(risk_level "$score")"
  duration=$(( $(date +%s 2>/dev/null || printf '%s' "$START_EPOCH") - START_EPOCH ))
  errors="$(wc -l < "$OUTPUT_DIR/errores.txt" 2>/dev/null | tr -d ' ')"
  correlations="$(cat "$TMP_DIR/correlation_count" 2>/dev/null || printf '0')"

  awk -F'\t' 'NR>1 {rank=0; if($3=="BAJO")rank=1; else if($3=="MEDIO")rank=2; else if($3=="ALTO")rank=3; else if($3=="CRÍTICO")rank=4; print rank "\t" $1 "\t" $3 "\t" $2 "\t" $5}' "$OUTPUT_DIR/hallazgos.tsv" \
    | sort -t$'\t' -k1,1nr -k2,2 | head -n 15 > "$topfile" || true

  {
    printf 'RESUMEN EJECUTIVO - UBUNTU SECURITY TRIAGE %s\n' "$SCRIPT_VERSION"
    printf '=======================================================\n'
    printf 'Inicio: %s\n' "$(date -d "@$START_EPOCH" --iso-8601=seconds 2>/dev/null || printf '%s' "$START_EPOCH")"
    printf 'Fin: %s\n' "$(iso_now)"
    printf 'Duración observada: %s segundos (no es una promesa de rendimiento)\n' "$duration"
    printf 'Modo: %s | root: %s | ventana desde: %s\n' "$MODE" "$ROOT_AVAILABLE" "$CUTOFF_TEXT"
    printf '\nPUNTUACIÓN ORIENTATIVA: %s/100\n' "$score"
    printf 'NIVEL DE RIESGO ESTIMADO: %s\n' "$level"
    printf 'Suma bruta informativa: %s | correlaciones añadidas: %s\n' "$SCORE_RAW" "$correlations"
    printf 'IMPORTANTE: la puntuación prioriza revisión; no confirma que el equipo esté comprometido ni limpio.\n'
    printf 'Pesos base: INFORMATIVO=0, BAJO=1, MEDIO=3, ALTO=10, CRÍTICO=25; máximo mostrado=100.\n'
    printf 'Se aplican topes por severidad (10/8/5/3) y un suelo coherente con la severidad máxima observada.\n'
    printf 'Las correlaciones se registran como hallazgos propios y reciben más peso que señales aisladas.\n'

    printf '\nHALLAZGOS POR SEVERIDAD\n'
    printf '  CRÍTICO: %s\n' "${SEVERITY_COUNT[CRÍTICO]:-0}"
    printf '  ALTO: %s\n' "${SEVERITY_COUNT[ALTO]:-0}"
    printf '  MEDIO: %s\n' "${SEVERITY_COUNT[MEDIO]:-0}"
    printf '  BAJO: %s\n' "${SEVERITY_COUNT[BAJO]:-0}"
    printf '  INFORMATIVO: %s\n' "${SEVERITY_COUNT[INFORMATIVO]:-0}"

    printf '\nPRINCIPALES INDICADORES\n'
    if [[ -s "$topfile" ]]; then
      awk -F'\t' '{printf "  - [%s] %s %s: %s\n",$3,$2,$4,$5}' "$topfile"
    else
      printf '  - No se generaron hallazgos por encima de informativo. Esto no demuestra ausencia de compromiso.\n'
    fi

    printf '\nDIRECCIONES IP REMOTAS RELEVANTES\n'
    if [[ -s "$TMP_DIR/remote_ips.txt" || -s "$TMP_DIR/auth_ips.tsv" ]]; then
      { cat "$TMP_DIR/remote_ips.txt" 2>/dev/null; cut -f1 "$TMP_DIR/auth_ips.tsv" 2>/dev/null; } | sort -u | head -n 100 | sed 's/^/  - /'
    else
      printf '  - Ninguna visible en las fuentes accesibles.\n'
    fi

    printf '\nPUERTOS EN ESCUCHA\n'
    if [[ -s "$TMP_DIR/listeners.tsv" ]]; then
      awk -F'\t' '{printf "  - %s %s:%s pid=%s proceso=%s paquete=%s wildcard=%s\n",$1,$2,$3,$4,$5,$8,$9}' "$TMP_DIR/listeners.tsv" | head -n 150 | redact_stream
    else
      printf '  - No enumerados o ninguno visible.\n'
    fi

    printf '\nARCHIVOS MÁS SOSPECHOSOS\n'
    if [[ -s "$TMP_DIR/suspicious_files.tsv" ]]; then
      awk -F'\t' '!seen[$1]++ {printf "  - ruta=%s motivo=%s sha256=%s tamaño=%s\n",$1,$2,($3==""?"no_calculado":$3),$4}' "$TMP_DIR/suspicious_files.tsv" | head -n 30 | redact_stream
    else
      printf '  - Ningún candidato por las heurísticas ejecutadas.\n'
    fi

    printf '\nPERSISTENCIA MÁS RELEVANTE\n'
    if [[ -s "$TMP_DIR/persistence_candidates.tsv" ]]; then
      head -n 30 "$TMP_DIR/persistence_candidates.tsv" | sed 's/^/  - /' | redact_stream
    else
      printf '  - Sin candidatos systemd normalizados; revise persistencia.txt para cron, perfiles y autostart.\n'
    fi

    printf '\nLIMITACIONES\n'
    printf '  - Triage en vivo: el sistema cambia durante la adquisición y un rootkit puede engañar herramientas locales.\n'
    printf '  - Las heurísticas generan falsos positivos/falsos negativos; "desconocido" no significa "malicioso".\n'
    printf '  - La red es una instantánea; conexiones cortas o procesos terminados pueden no aparecer.\n'
    printf '  - La redacción de secretos es heurística; proteja el directorio como información sensible.\n'
    printf '  - find usa -xdev, límites de profundidad/tiempo/volumen y no atraviesa de forma global /proc, /sys, /dev ni filesystems remotos.\n'
    printf '  - Verificación dpkg compara estado local y metadatos disponibles, no una fuente externa independiente.\n'
    local limitation
    for limitation in "${LIMITATIONS[@]}"; do printf '  - %s\n' "$limitation"; done
    printf '  - Comandos/capturas con error: %s; consulte errores.txt.\n' "${errors:-0}"

    printf '\nPRÓXIMOS PASOS RECOMENDADOS\n'
    printf '  1. Validar primero correlaciones CRÍTICO/ALTO contra inventario, cambios y propietarios.\n'
    printf '  2. Preservar informes, logs y candidatos con hashes; registrar zona horaria y cadena de custodia.\n'
    printf '  3. Si los indicios son sólidos, evitar borrar/modificar evidencia y contener la red de forma coordinada.\n'
    printf '  4. No usar esta máquina para cuentas sensibles; cambiar credenciales desde un dispositivo confiable.\n'
    printf '  5. Considerar memoria/imagen forense y análisis profesional antes de reinstalar desde medios confiables.\n'
  } > "$out"
  chmod 600 -- "$out" 2>/dev/null || true
}

generate_manifest() {
  local manifest="$OUTPUT_DIR/manifest_sha256.txt" report
  : > "$manifest"
  if ! have_cmd sha256sum; then
    log_error "manifest" "127" "sha256sum no disponible"
    printf 'sha256sum no disponible; manifiesto no generado.\n' > "$manifest"
    return 0
  fi
  (
    cd -- "$OUTPUT_DIR" || exit 1
    for report in "${REPORT_FILES[@]}"; do
      [[ -f "$report" ]] || continue
      sha256sum -- "$report"
    done
  ) > "$manifest" 2>> "$OUTPUT_DIR/errores.txt" || log_error "manifest" "1" "falló sha256sum"
  chmod 600 -- "$manifest" 2>/dev/null || true
}

main() {
  printf 'Ubuntu Security Triage %s: iniciando modo %s.\n' "$SCRIPT_VERSION" "$MODE"
  printf 'Resultados: %s\n' "$OUTPUT_DIR"
  collect_system_info
  printf '[1/10] Sistema y contexto completados.\n'
  collect_users
  printf '[2/10] Usuarios y privilegios completados.\n'
  collect_ssh
  printf '[3/10] SSH completado.\n'
  collect_network
  printf '[4/10] Red completada.\n'
  collect_processes
  printf '[5/10] Procesos completados.\n'
  collect_persistence
  printf '[6/10] Persistencia completada.\n'
  collect_files
  printf '[7/10] Archivos completados.\n'
  collect_package_integrity
  printf '[8/10] Paquetes e integridad completados.\n'
  collect_logs
  collect_kernel
  printf '[9/10] Logs, kernel y contenedores completados.\n'
  collect_malware_and_history
  correlate_findings
  # Algunas sustituciones de proceso pueden terminar una fracción después de
  # que el consumidor alcance su límite; esperar evita hashear informes aún abiertos.
  wait 2>/dev/null || true
  generate_summary
  chmod 700 -- "$OUTPUT_DIR" 2>/dev/null || true
  find "$OUTPUT_DIR" -maxdepth 1 -type f -exec chmod 600 '{}' + 2>/dev/null || true
  generate_manifest
  printf '[10/10] Análisis finalizado. Revise %s/resumen.txt\n' "$OUTPUT_DIR"
}

main
