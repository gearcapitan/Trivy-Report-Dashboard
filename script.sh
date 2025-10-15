#!/bin/bash
# Script v3.0 (Final y Autosuficiente) con comprobación e instalación de dependencias.

# --- Función para comprobar e instalar dependencias ---
check_and_install_deps() {
    echo "Verificando dependencias necesarias..."
    local missing_deps=false

    # 1. Requisitos Críticos (Docker y Python)
    if ! command -v docker &> /dev/null; then
        echo "❌ ERROR: Docker no está instalado. Por favor, instala Docker y vuelve a ejecutar el script."
        missing_deps=true
    fi
    if ! command -v python3 &> /dev/null; then
        echo "❌ ERROR: Python 3 no está instalado. Por favor, instálalo y vuelve a ejecutar el script."
        missing_deps=true
    fi
    if $missing_deps; then
        exit 1
    fi

    # 2. Herramientas de soporte (jq y curl)
    if ! command -v jq &> /dev/null; then
        echo "⚠️  'jq' no encontrado. Intentando instalar..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y jq
        elif command -v yum &> /dev/null; then
            sudo yum install -y jq
        elif command -v brew &> /dev/null; then
            brew install jq
        else
            echo "❌ No se pudo instalar 'jq' automáticamente. Por favor, instálalo manualmente."
            exit 1
        fi
    fi
    if ! command -v curl &> /dev/null; then
        echo "❌ 'curl' no está instalado, es necesario para descargar Trivy. Por favor, instálalo manualmente."
        exit 1
    fi

    # 3. Herramienta principal (Trivy)
    if ! command -v trivy &> /dev/null; then
        echo "⚠️  'trivy' no encontrado. Intentando instalar la última versión..."
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
        if ! command -v trivy &> /dev/null; then
            echo "❌ La instalación de 'trivy' falló. Por favor, intenta instalarlo manualmente."
            exit 1
        fi
    fi
    echo "✅ Todas las dependencias están satisfechas."
    echo "------------------------------------------------------------------------"
}

# --- Ejecutar la comprobación de dependencias al inicio ---
check_and_install_deps

# --- Parámetros por defecto ---
TARGET_IMAGE=""
SEVERITY_FILTER="UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
MODE="INDIVIDUAL_ALL"

# --- Parseo de argumentos de línea de comandos ---
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --imagen) TARGET_IMAGE="$2"; shift ;;
        --severidad) SEVERITY_FILTER="$2"; shift ;;
        --consolidado) MODE="CONSOLIDATED" ;;
        *) echo "Parámetro desconocido: $1"; exit 1 ;;
    esac
    shift
done

if [[ "$MODE" == "CONSOLIDATED" && -n "$TARGET_IMAGE" ]]; then echo "Error: --consolidado y --imagen no se pueden usar al mismo tiempo."; exit 1; fi
if [[ -n "$TARGET_IMAGE" ]]; then MODE="INDIVIDUAL_TARGET"; fi

JSON_DIR="trivy_reports_json"
HTML_DIR="trivy_reports_html"

cleanup() {
    if [ -d "$JSON_DIR" ] || [ -d "$HTML_DIR" ]; then
        read -p "¿Deseas borrar los reportes anteriores? (s/n): " response
        if [[ "$response" =~ ^[sS]$ ]]; then
            echo "Borrando directorios de reportes anteriores..."; rm -rf "$JSON_DIR" "$HTML_DIR";
        fi
    fi
}
cleanup

LOGO_PARAM=""
read -p "¿Deseas incluir un logo en el reporte? (s/n): " response
if [[ "$response" =~ ^[sS]$ ]]; then
    mkdir -p assets
    LOGO_FILE=$(find assets -maxdepth 1 -type f \( -iname "*.png" -o -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.svg" \) | head -n 1)
    if [ -z "$LOGO_FILE" ]; then
        echo "⚠️  ACCIÓN REQUERIDA: Logo no encontrado. Por favor, coloca un archivo de imagen en la carpeta 'assets' y vuelve a ejecutar."
        exit 1
    else
        LOGO_PARAM="--logo-path $LOGO_FILE"; echo "✅ Logo encontrado: '$LOGO_FILE'.";
    fi
fi

mkdir -p "$JSON_DIR" "$HTML_DIR"
TRIVY_FLAGS="--scanners vuln,secret,misconfig --dependency-tree --severity $SEVERITY_FILTER"

# ========================================================================
# Lógica de escaneo (sin cambios)
# ========================================================================
if [ "$MODE" == "CONSOLIDATED" ]; then
    echo "MODO CONSOLIDADO: Escaneando imágenes secuencialmente..."
    trivy image --download-db-only
    echo "------------------------------------------------------------------------"
    for img in $(docker images --format "{{.Repository}}:{{.Tag}}"); do
        safe_filename=$(echo "$img" | sed 's|/|-|g; s|:|-|g')
        json_output_file="${JSON_DIR}/reporte-${safe_filename}.json"
        echo "-> Analizando imagen: $img"
        trivy image --skip-db-update $TRIVY_FLAGS --format json -o "$json_output_file" "$img"
        echo "<- Finalizado escaneo para: $img"
    done
    echo "Uniendo reportes JSON..."
    MASTER_JSON="master_report.json"
    MASTER_HTML="${HTML_DIR}/reporte_maestro_consolidado.html"
    jq -s '{"ArtifactName": "Reporte Maestro Consolidado", "Reports": [ .[] ]}' ${JSON_DIR}/*.json > "$MASTER_JSON"
    echo "Generando reporte HTML maestro..."
    python3 json_to_html.py "$MASTER_JSON" "$MASTER_HTML" $LOGO_PARAM
    rm "$MASTER_JSON"
elif [ "$MODE" == "INDIVIDUAL_TARGET" ]; then
    echo "MODO IMAGEN ÚNICA: Escaneando $TARGET_IMAGE..."
    safe_filename=$(echo "$TARGET_IMAGE" | sed 's|/|-|g; s|:|-|g')
    json_output_file="${JSON_DIR}/reporte-${safe_filename}.json"
    html_output_file="${HTML_DIR}/reporte-${safe_filename}.html"
    trivy image $TRIVY_FLAGS --format json -o "$json_output_file" "$TARGET_IMAGE"
    if [ -s "$json_output_file" ]; then echo "Generando reporte HTML..."; python3 json_to_html.py "$json_output_file" "$html_output_file" $LOGO_PARAM; fi
else
    echo "MODO INDIVIDUAL: Escaneando todas las imágenes..."
    for img in $(docker images --format "{{.Repository}}:{{.Tag}}"); do
        safe_filename=$(echo "$img" | sed 's|/|-|g; s|:|-|g')
        json_output_file="${JSON_DIR}/reporte-${safe_filename}.json"
        html_output_file="${HTML_DIR}/reporte-${safe_filename}.html"
        echo "-> Analizando imagen: $img"
        trivy image $TRIVY_FLAGS --format json -o "$json_output_file" "$img"
        if [ -s "$json_output_file" ]; then python3 json_to_html.py "$json_output_file" "$html_output_file" $LOGO_PARAM; fi
        echo "------------------------------------------------------------------------"
    done
fi

echo "✅ ¡Proceso completado!"
