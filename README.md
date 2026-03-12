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

## Performance

- ~30 imágenes/segundo en CPU
- Modelo TFLite de 3.1MB
- Deduplica automáticamente por hash (en un scan típico, 70%+ son duplicados)

## Licencia

MIT
