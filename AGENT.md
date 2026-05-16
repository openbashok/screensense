## REGLA OBLIGATORIA DE EJECUCIÓN

Cuando ejecutes ScreenSense, SIEMPRE usá el flag --stream-log para escribir el stream a /tmp/screensense.log. Esto es obligatorio, no opcional:

python3 screensense.py <dir> -t <threshold> -o <salida.json> --stream-log /tmp/screensense.log

NO uses pipes a tail, head, ni captura silenciosa. El --stream-log /tmp/screensense.log debe estar presente SIEMPRE.

# AGENT.md — Guía de integración para agentes autónomos

Sos un agente de pentesting y tenés acceso a ScreenSense para clasificar screenshots de scans web. Este documento te explica cómo usarlo.

## Qué es ScreenSense

Es un clasificador local de imágenes que analiza screenshots de páginas web y te dice qué tipo de página es. Corre offline, no necesita internet ni API keys.

## Cómo ejecutarlo

```bash
python3 screensense.py <dir> -t <threshold> -o <salida.json> --stream-log /tmp/screensense.log
```

Parámetros:
- `<directorio_screenshots>`: carpeta con archivos `.png`, `.jpg` o `.jpeg`
- `-t <threshold>`: umbral de confianza entre 0 y 1 (recomendado: 0.8 para alta precisión, 0.5 para mayor cobertura)
- `-o <salida.json>`: ruta del archivo JSON de salida
- `--stream-log <ruta>`: escribe el stream por imagen a este archivo (para hacer `tail -f` desde otra terminal)
- `-q`: modo silencioso, no imprime nada a stdout (el stream-log sigue funcionando si se pasa)
- `--model <ruta>`: ruta al archivo model.tflite si no está en `model/model.tflite`

## Formato de salida

```json
{
  "metadata": {
    "total_images": 886,
    "unique_images": 250,
    "detections": 48,
    "processing_time_seconds": 8.1,
    "threshold": 0.8,
    "target_categories": ["login", "directory_listing", "stack_trace", "oldlooking"]
  },
  "counts": {
    "login": 44,
    "directory_listing": 1,
    "stack_trace": 0,
    "oldlooking": 3
  },
  "detections": [
    { "id": "ddf01f71acd25b40", "category": "login", "score": 0.9531 },
    { "id": "a1b2c3d4e5f67890", "category": "directory_listing", "score": 0.8712 }
  ]
}
```

### Campos de cada detección

- `id`: hash de contenido de la imagen. Permite correlacionar con el archivo original: el screenshot se llama `*_<id>.png` en el directorio de entrada.
- `category`: categoría detectada (`login`, `directory_listing`, `stack_trace` u `oldlooking` por default; otras si se usó `--all` o `-c`).
- `score`: confianza entre 0 y 1. Mayor score = mayor certeza.

### Cómo encontrar el archivo original a partir del id

Los screenshots siguen el formato `<prefijo>_<id>.png`. Para encontrar el archivo:

```bash
ls screenshots/*_ddf01f71acd25b40.png
```

Si hay múltiples archivos con el mismo id, son duplicados (misma página en distintos subdominios/puertos). Usá cualquiera.

## Qué hacer con cada categoría

### login (páginas de autenticación)
- Intentar credenciales por defecto (admin/admin, admin/password, etc.)
- Verificar si el formulario envía por HTTP (sin TLS)
- Buscar bypass de autenticación
- Verificar si hay rate limiting o lockout
- Buscar páginas de registro o reset de password asociadas

### directory_listing (índice de directorios expuesto)
- Buscar archivos sensibles: `.env`, `.bak`, `.sql`, `.zip`, `.tar.gz`, `config.*`, `credentials.*`
- Buscar backups de código fuente
- Buscar archivos de configuración con credenciales
- Navegar subdirectorios recursivamente
- Verificar si hay archivos de base de datos expuestos

### stack_trace (errores y stack traces)
- Extraer versiones de software (framework, lenguaje, servidor)
- Extraer paths internos del servidor
- Identificar la tecnología (Java/Spring, Python/Django, PHP, .NET, Node.js)
- Buscar información de conexión a bases de datos en el error
- Verificar si el modo debug está habilitado en producción

### oldlooking (sitios legacy / desactualizados)
- Indicador de stack viejo (PHP/ASP sin patches, jQuery viejo, frames, etc.)
- Probar vulnerabilidades clásicas: XSS reflejado, SQLi, LFI, CSRF sin token
- Correr `nikto`/`nuclei` con templates legacy
- Buscar paneles administrativos sin auth (`/admin`, `/manager`, `/phpmyadmin`)
- Verificar headers de seguridad (probablemente ausentes)

## Ejemplo de integración en Python

```python
import json
import subprocess

def run_screensense(screenshots_dir, threshold=0.8):
    """Ejecuta ScreenSense y retorna las detecciones."""
    result = subprocess.run(
        ["python3", "screensense.py", screenshots_dir,
         "-t", str(threshold), "-o", "/tmp/ss_out.json", "-q"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return {"error": result.stderr}

    with open("/tmp/ss_out.json") as f:
        return json.load(f)


def prioritize_targets(detections_json):
    """Prioriza targets por categoría y score."""
    priority_order = {
        "directory_listing": 1,  # acceso directo a archivos
        "stack_trace": 2,        # info disclosure
        "login": 3,              # superficie de autenticación
    }

    detections = detections_json.get("detections", [])
    detections.sort(key=lambda d: (
        priority_order.get(d["category"], 99),
        -d["score"]
    ))
    return detections


# Uso
data = run_screensense("/path/to/screenshots/", threshold=0.8)
targets = prioritize_targets(data)

for t in targets:
    print(f"[{t['category']}] {t['id']} (score: {t['score']})")
```

## Ejemplo de integración en pipeline bash

```bash
#!/bin/bash
SCAN_DIR="$1"
OUTPUT="$2"

# Clasificar
python3 screensense.py "$SCAN_DIR" -t 0.8 -o "$OUTPUT" -q

# Extraer IDs de logins para procesamiento posterior
cat "$OUTPUT" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for d in data['detections']:
    if d['category'] == 'login':
        print(d['id'])
" > login_ids.txt
```

## Notas importantes

- **Performance**: ~30 img/s en CPU. Un scan de 1000 screenshots se procesa en ~30 segundos.
- **Deduplicación**: Si hay 1000 screenshots pero 700 son duplicados (mismo hash), solo se clasifican 300. Esto es común en scans con muchos subdominios apuntando al mismo servidor.
- **Threshold**: Usá 0.8 si preferís precisión (pocos falsos positivos). Usá 0.5 si preferís cobertura (más detecciones pero posibles falsos positivos).
- **Offline**: No hace ninguna conexión de red. Todo corre local con un modelo TFLite de 3.1MB.
- **Sin dependencias pesadas**: Solo necesita `tensorflow` (o `ai_edge_litert` / `tflite-runtime` como fallback), `Pillow` y `numpy`.
