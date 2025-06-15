#!/bin/bash

# Directorio fuente (por defecto ./src)
SOURCE_DIR=${1:-"./src"}
# Archivo de salida (por defecto all-sources.txt)
OUTPUT_FILE=${2:-"all-sources.txt"}

# Verificar que el directorio existe
if [ ! -d "$SOURCE_DIR" ]; then
    echo "❌ El directorio $SOURCE_DIR no existe"
    exit 1
fi

echo "🔍 Buscando archivos .ts, .json en src/ y .bat en deploy/"

# Limpiar archivo de salida
> "$OUTPUT_FILE"

# Contador de archivos
count=0

# Función para procesar archivos
process_files() {
    local pattern="$1"
    local search_dir="$2"
    local description="$3"
    
    if [ -d "$search_dir" ]; then
        echo "📁 Procesando $description en: $search_dir"
        find "$search_dir" -name "$pattern" -type f | sort | while read -r file; do
            # Obtener ruta relativa desde el directorio raíz del proyecto
            relative_path=$(realpath --relative-to="." "$file")
            
            # Escribir comentario con la ruta
            echo "// $relative_path" >> "$OUTPUT_FILE"
            
            # Escribir contenido del archivo
            cat "$file" >> "$OUTPUT_FILE"
            
            # Línea en blanco para separar archivos
            echo "" >> "$OUTPUT_FILE"
            
            echo "  📄 $relative_path"
        done
        
        # Contar archivos para este patrón
        local file_count=$(find "$search_dir" -name "$pattern" -type f | wc -l)
        count=$((count + file_count))
        echo "  ✨ $file_count archivos $description encontrados"
    else
        echo "⚠️  Directorio $search_dir no existe, saltando $description"
    fi
}

# Procesar archivos TypeScript en src/
process_files "*.ts" "$SOURCE_DIR" "TypeScript"

# Procesar archivos JSON en src/
process_files "*.json" "$SOURCE_DIR" "JSON"

# Procesar archivos BAT en deploy/
process_files "*.bat" "./deploy" "batch scripts"

echo ""
echo "✅ Total: $count archivos recopilados en: $OUTPUT_FILE"
echo "📊 Tamaño del archivo: $(du -h "$OUTPUT_FILE" | cut -f1)"