# ScreenSense

Visual triage for pentesting screenshots. Analyzes web scan screenshots and automatically detects logins, directory listings, stack traces and more.

Like an X-ray for your recon: feed it a directory with thousands of screenshots and it tells you which ones are interesting.

## What it detects

| Category | Description |
|---|---|
| `login` | Login/authentication pages |
| `directory_listing` | Directory indexes (Apache, Nginx, IIS, Tomcat) |
| `stack_trace` | Stack traces and errors (Java, Python, PHP, .NET, Node.js) |
| `webapp` | Web applications with attack surface |
| `custom404` | Custom 404 error pages |
| `oldlooking` | Legacy/outdated-looking sites |
| `parked` | Parked/placeholder domains |
| `api_response` | Raw JSON/XML API responses, Swagger UI |
| `database_exposed` | phpMyAdmin, Adminer, MongoDB Express |
| `printer_iot` | Printers, IP cameras, routers, IoT devices |
| `cms_admin` | WordPress, Joomla, Drupal, cPanel admin panels |
| `logs` | Exposed log files (access, error, syslog) |

## Installation

```bash
git clone https://github.com/lostsurface/screensense.git
cd screensense
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Usage

```bash
# Basic usage (default threshold: 0.5)
python3 screensense.py /path/to/screenshots/

# Higher precision with strict threshold
python3 screensense.py /path/to/screenshots/ -t 0.8

# Custom output path
python3 screensense.py /path/to/screenshots/ -t 0.8 -o results.json

# Quiet mode (only generates JSON, no stdout)
python3 screensense.py /path/to/screenshots/ -t 0.8 -o results.json -q

# Custom model path (for remote deployments)
python3 screensense.py /path/to/screenshots/ --model /path/to/model.tflite
```

## Output

Generates a JSON file with positive detections only:

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
  "counts": {
    "login": 44,
    "directory_listing": 1,
    "stack_trace": 0
  },
  "detections": [
    { "id": "abc123def456", "category": "login", "score": 0.9531 },
    { "id": "ff0099aabb11", "category": "directory_listing", "score": 0.8712 }
  ]
}
```

### Screenshot filename format

ScreenSense expects screenshots to follow the naming convention used by tools like GoWitness, EyeWitness, or OpenBash, where the filename contains a content hash separated by `_` at the end:

```
<prefix>_<content_hash>.png
```

Examples:
```
http__ventas_example_com__ddf01f71acd25b40.png
https__admin_example_com__443__a1b2c3d4e5f67890.png
http__192_168_1_1__8080__ff00aa11bb22cc33.png
```

The `id` field in the JSON output is that final hash (`ddf01f71acd25b40`). This is how deduplication works: if two different URLs render the same page, they share the same hash and ScreenSense classifies them only once.

**If filenames don't follow this format** (e.g., `screenshot_001.png`), ScreenSense uses the full filename (without extension) as the `id`. Classification works the same, but there's no deduplication.

Supported formats: `.png`, `.jpg`, `.jpeg`.

## Remote deployment

Only 2 files needed:

```bash
scp screensense.py model/model.tflite user@server:~/screensense/
```

On the server:

```bash
pip install tensorflow Pillow numpy
python3 screensense.py /screenshots/ -t 0.8 -o results.json --model model.tflite
```

No internet, API keys or credentials required. Runs 100% offline.

## Agent integration

ScreenSense is designed to feed autonomous pentesting agents. Instead of an agent receiving thousands of screenshots with no context, ScreenSense provides a map of what each image contains before looking at it.

See [AGENT.md](AGENT.md) for full integration guide including:
- How to execute and parse output
- What to do with each detected category
- Python and bash integration examples
- Target prioritization logic

### Typical pipeline

```
Web scan (GoWitness/EyeWitness/etc)
  → screenshots/
    → ScreenSense (classify)
      → detections.json
        → Agent consumes JSON and prioritizes targets
```

### Quick integration example

```python
import json, subprocess

subprocess.run(["python3", "screensense.py", "/screenshots/",
                "-t", "0.8", "-o", "out.json", "-q"])

with open("out.json") as f:
    data = json.load(f)

logins = [d for d in data["detections"] if d["category"] == "login"]
print(f"Found {len(logins)} login pages to test")
```

## Performance

- ~30 images/second on CPU
- 3.1MB TFLite model
- Automatic hash-based deduplication (in a typical scan, 70%+ are duplicates)

## License

MIT
