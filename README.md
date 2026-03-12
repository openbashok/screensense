# ScreenSense

Diagnóstico por imágenes para pentesting. Analiza screenshots de scans web y detecta automáticamente logins, directory listings, stack traces y más.

Como una radiografía de tu recon: le pasás un directorio con miles de screenshots y te dice cuáles son interesantes.

## Qué detecta

| Categoría | Descripción |
|---|---|
| `login` | Páginas de login/autenticación |
| `directory_listing` | Directory indexes (Apache, Nginx, IIS, Tomcat) |
| `stack_trace` | Stack traces y errores (Java, Python, PHP, .NET, Node.js) |
| `webapp` | Aplicaciones web con superficie de ataque |
| `custom404` | Páginas 404 custom |
| `oldlooking` | Sitios con aspecto legacy/desactualizado |
| `parked` | Dominios estacionados |
| `api_response` | Respuestas JSON/XML de APIs expuestas |
| `database_exposed` | phpMyAdmin, Adminer, MongoDB Express |
| `printer_iot` | Impresoras, cámaras IP, routers, IoT |
| `cms_admin` | Paneles de WordPress, Joomla, Drupal, cPanel |
| `logs` | Logs expuestos (access, error, syslog) |

## Instalación

```bash
git clone https://github.com/YOUR_USER/screensense.git
cd screensense
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Uso

```bash
# Uso básico
.venv/bin/python screensense.py /path/to/screenshots/

# Mayor precisión con threshold alto
.venv/bin/python screensense.py /path/to/screenshots/ -t 0.8

# Especificar salida
.venv/bin/python screensense.py /path/to/screenshots/ -t 0.8 -o results.json

# Modo silencioso (solo genera el JSON)
.venv/bin/python screensense.py /path/to/screenshots/ -t 0.8 -o results.json -q
```

## Salida

Genera un JSON con las detecciones positivas:

```json
{
  "metadata": {
    "total_images": 886,
    "unique_images": 250,
    "detections": 48,
    "processing_time_seconds": 8.1,
    "images_per_second": 31.0,
    "threshold": 0.8
  },
  "detections": [
    { "id": "abc123def456", "category": "login", "score": 0.9531 },
    { "id": "ff0099aabb11", "category": "directory_listing", "score": 0.8712 }
  ]
}
```

El `id` es el hash de contenido de la imagen (último segmento del nombre de archivo). Las imágenes duplicadas (mismo hash, distinto subdominio) se procesan una sola vez.

## Deploy en servidor remoto

Solo necesitás 2 archivos:

```bash
scp screensense.py model/model.tflite user@server:~/screensense/
```

En el server:

```bash
pip install tensorflow Pillow numpy
python3 screensense.py /screenshots/ -t 0.8 -o results.json --model model.tflite
```

No requiere internet, API keys ni credenciales. Corre 100% offline.

## Integración con agentes de pentesting

ScreenSense está diseñado para alimentar agentes autónomos que procesan resultados de escaneos web. En vez de que un agente reciba miles de screenshots sin contexto, ScreenSense le da un mapa de qué hay en cada imagen antes de mirarla.

### Flujo típico con agentes

```
Scan (GoWitness/EyeWitness/etc)
  → screenshots/
    → ScreenSense (classify)
      → detections.json
        → Agente consume el JSON y prioriza targets
```

### Cómo lo usa un agente

1. **Priorización automática**: El agente recibe el JSON y sabe inmediatamente cuáles son los targets de alto valor sin necesidad de procesar visualmente cada screenshot:
   - `login` → Intentar credenciales default, buscar vulnerabilidades de autenticación
   - `directory_listing` → Buscar archivos sensibles (.env, backups, configs)
   - `stack_trace` → Extraer versiones, paths internos, info de debug
   - `database_exposed` → Acceso directo a datos, verificar autenticación
   - `api_response` → Endpoints para enumerar, posible data leakage
   - `cms_admin` → Verificar versiones vulnerables, plugins, credenciales default

2. **Reducción de ruido**: De 1000 screenshots, típicamente 70%+ son duplicados y la mayoría son páginas irrelevantes (parked, 404, etc). ScreenSense filtra el ruido y le entrega al agente solo lo accionable.

3. **Correlación por hash**: El campo `id` (hash de contenido) permite correlacionar la misma página apareciendo en múltiples subdominios. Si `login` aparece con el mismo `id` en 50 subdominios, el agente sabe que es el mismo formulario detrás de todos.

### Ejemplo de consumo desde un agente

```python
import json

with open("detections.json") as f:
    data = json.load(f)

# Obtener todos los logins detectados
logins = [d for d in data["detections"] if d["category"] == "login"]

# Obtener los IDs únicos de directory listings con alta confianza
dirlist_ids = [d["id"] for d in data["detections"]
               if d["category"] == "directory_listing" and d["score"] > 0.8]

# Mapear IDs a archivos de screenshot para inspección visual
# El archivo original es: *_<id>.png en el directorio de screenshots
```

### Integración en pipelines

```bash
# Paso 1: Scan
gowitness scan -f urls.txt -o screenshots/

# Paso 2: Clasificar
python3 screensense.py screenshots/ -t 0.8 -o detections.json -q

# Paso 3: El agente consume detections.json y actúa
python3 agent.py --input detections.json --screenshots screenshots/
```

El flag `-q` (quiet) es ideal para pipelines: no imprime nada a stdout, solo genera el JSON.

## Performance

- ~30 imágenes/segundo en CPU
- Modelo TFLite de 3.1MB
- Deduplica automáticamente por hash (en un scan típico, 70%+ son duplicados)

## Licencia

MIT
