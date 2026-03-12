#!/usr/bin/env python3
"""
ScreenSense — Diagnóstico por imágenes para pentesting.

Analiza screenshots de scans web y detecta automáticamente logins,
directory listings, stack traces y más. Como una radiografía de tu recon.

Uso:
  screensense.py /path/to/screenshots/
  screensense.py /path/to/screenshots/ -t 0.8
  screensense.py /path/to/screenshots/ -t 0.8 -o results.json
  screensense.py /path/to/screenshots/ --model model.tflite

Salida JSON:
  {
    "metadata": { ... },
    "detections": [
      { "id": "abc123def456", "category": "login", "score": 0.9531 },
      { "id": "ff0099aabb11", "category": "directory_listing", "score": 0.8712 }
    ]
  }

Deploy en server remoto:
  Solo se necesitan 2 archivos: screensense.py + model.tflite (~3.1MB)
  pip install tensorflow Pillow numpy
  No requiere internet, API keys ni credenciales.
"""

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
from PIL import Image as PILImage

# ── Configuración ─────────────────────────────────────────────────
MODEL_PATH = Path(__file__).parent / "model" / "model.tflite"

# Orden exacto de labels en el modelo TFLite (no cambiar)
ALL_LABELS = [
    "custom404", "directory_listing", "logs", "login", "cms_admin",
    "parked", "stack_trace", "database_exposed", "webapp", "printer_iot",
    "api_response", "oldlooking",
]

# Categorías de interés para producción
TARGET_LABELS = ["login", "directory_listing", "stack_trace"]

INPUT_SIZE = 224


def load_model(model_path):
    try:
        import tensorflow as tf
        interpreter = tf.lite.Interpreter(model_path=str(model_path))
    except ImportError:
        from tflite_runtime.interpreter import Interpreter
        interpreter = Interpreter(model_path=str(model_path))
    interpreter.allocate_tensors()
    return interpreter


def preprocess(img_path):
    img = PILImage.open(img_path).convert("RGB")
    img = img.resize((INPUT_SIZE, INPUT_SIZE))
    return np.array(img, dtype=np.uint8)


def predict(interpreter, image_array):
    input_details = interpreter.get_input_details()
    output_details = interpreter.get_output_details()
    input_data = np.expand_dims(image_array, axis=0)
    interpreter.set_tensor(input_details[0]["index"], input_data)
    interpreter.invoke()
    output = interpreter.get_tensor(output_details[0]["index"])[0]
    scores = output.astype(np.float32) / 256.0
    return {label: float(score) for label, score in zip(ALL_LABELS, scores)}


def collect_and_dedup(input_path):
    image_paths = sorted(
        list(input_path.glob("*.png")) +
        list(input_path.glob("*.jpg")) +
        list(input_path.glob("*.jpeg"))
    )
    if not image_paths:
        print(f"Error: no se encontraron imágenes en {input_path}", file=sys.stderr)
        sys.exit(1)

    hash_to_paths = {}
    for p in image_paths:
        parts = p.stem.rsplit("_", 1)
        img_hash = parts[-1] if len(parts) > 1 else p.stem
        if img_hash not in hash_to_paths:
            hash_to_paths[img_hash] = []
        hash_to_paths[img_hash].append(p)

    return image_paths, hash_to_paths


def main():
    parser = argparse.ArgumentParser(
        prog="screensense",
        description="ScreenSense — Diagnóstico por imágenes para pentesting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ejemplos:
  %(prog)s /path/to/screenshots/
  %(prog)s /path/to/screenshots/ -t 0.8
  %(prog)s /path/to/screenshots/ -t 0.8 -o results.json
  %(prog)s /path/to/screenshots/ --model model.tflite
        """,
    )
    parser.add_argument("input", help="directorio con screenshots")
    parser.add_argument("-t", "--threshold", type=float, default=0.5,
                        help="umbral de confianza mínimo (default: 0.5)")
    parser.add_argument("-o", "--output", default="classification.json",
                        help="ruta del JSON de salida (default: classification.json)")
    parser.add_argument("--model", default=str(MODEL_PATH),
                        help="ruta al archivo .tflite")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="solo mostrar errores")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.is_dir():
        print(f"Error: {args.input} no es un directorio.", file=sys.stderr)
        sys.exit(1)

    model_path = Path(args.model)
    if not model_path.exists():
        print(f"Error: modelo no encontrado en {args.model}", file=sys.stderr)
        sys.exit(1)

    log = (lambda *a, **k: None) if args.quiet else print

    # Cargar modelo
    log("Cargando modelo...")
    t0 = time.time()
    interpreter = load_model(args.model)
    log(f"Modelo cargado en {time.time()-t0:.1f}s")

    # Recopilar y deduplicar
    all_paths, hash_to_paths = collect_and_dedup(input_path)
    total = len(all_paths)
    unique = len(hash_to_paths)
    log(f"Imágenes: {total} total, {unique} únicas, {total - unique} duplicadas")
    log(f"Clasificando {unique} imágenes...")

    t0 = time.time()
    detections = []
    counts = {l: 0 for l in TARGET_LABELS}
    done = 0

    for img_hash, paths in hash_to_paths.items():
        representative = paths[0]
        scores = predict(interpreter, preprocess(representative))

        active = {l: round(scores[l], 4) for l in TARGET_LABELS if scores[l] >= args.threshold}

        if active:
            for label, score in active.items():
                detections.append({
                    "id": img_hash,
                    "category": label,
                    "score": score,
                })
                counts[label] += 1

        done += 1
        if not args.quiet and done % 50 == 0:
            log(f"  {done}/{unique} ({100*done//unique}%)")

    elapsed = time.time() - t0
    detections.sort(key=lambda x: (x["id"], x["category"]))

    output = {
        "metadata": {
            "total_images": total,
            "unique_images": unique,
            "duplicates_skipped": total - unique,
            "detections": len(detections),
            "processing_time_seconds": round(elapsed, 1),
            "images_per_second": round(unique / elapsed, 1),
            "threshold": args.threshold,
            "target_categories": TARGET_LABELS,
            "source_directory": str(input_path),
        },
        "counts": counts,
        "detections": detections,
    }

    output_path = Path(args.output)
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    # Resumen
    log(f"\n{'='*50}")
    log(f"{len(detections)} detecciones en {elapsed:.1f}s ({unique/elapsed:.1f} img/s)")
    log(f"{'='*50}")
    for label, count in sorted(counts.items(), key=lambda x: -x[1]):
        bar = "█" * min(count, 40)
        log(f"  {label:<20} {count:>4}  {bar}")
    log(f"\nJSON: {output_path}")


if __name__ == "__main__":
    main()
