#!/usr/bin/env python3
"""
ScreenSense — Visual triage for pentesting screenshots.

Analyzes web scan screenshots and automatically detects logins,
directory listings, stack traces and more. Like an X-ray for your recon.

Usage:
  screensense.py /path/to/screenshots/
  screensense.py /path/to/screenshots/ -t 0.8
  screensense.py /path/to/screenshots/ -t 0.8 -o results.json
  screensense.py /path/to/screenshots/ --model model.tflite

JSON output:
  {
    "metadata": { ... },
    "detections": [
      { "id": "abc123def456", "category": "login", "score": 0.9531 },
      { "id": "ff0099aabb11", "category": "directory_listing", "score": 0.8712 }
    ]
  }

Remote deploy:
  Only 2 files needed: screensense.py + model.tflite (~3.1MB)
  pip install tensorflow Pillow numpy
  No internet, API keys or credentials required.
"""

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
from PIL import Image as PILImage

# ── Configuration ─────────────────────────────────────────────────
MODEL_PATH = Path(__file__).parent / "model" / "model.tflite"

# Exact label order in the TFLite model (do not change)
ALL_LABELS = [
    "custom404", "directory_listing", "logs", "login", "cms_admin",
    "parked", "stack_trace", "database_exposed", "webapp", "printer_iot",
    "api_response", "oldlooking",
]

# Default target categories
DEFAULT_LABELS = ["login", "directory_listing", "stack_trace", "oldlooking"]

INPUT_SIZE = 224


def load_model(model_path):
    try:
        import tensorflow as tf
        interpreter = tf.lite.Interpreter(model_path=str(model_path))
    except ImportError:
        try:
            from ai_edge_litert.interpreter import Interpreter
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
        print(f"Error: no images found in {input_path}", file=sys.stderr)
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
        description="ScreenSense — Visual triage for pentesting screenshots",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
available categories:
  login              Login/authentication pages
  directory_listing  Directory indexes (Apache, Nginx, IIS, Tomcat)
  stack_trace        Stack traces and errors (Java, Python, PHP, .NET, Node.js)
  oldlooking         Legacy/outdated-looking sites
  custom404          Custom 404 error pages
  webapp             Web applications with attack surface
  parked             Parked/placeholder domains
  api_response       Raw JSON/XML API responses, Swagger UI
  database_exposed   phpMyAdmin, Adminer, MongoDB Express
  printer_iot        Printers, IP cameras, routers, IoT devices
  cms_admin          WordPress, Joomla, Drupal, cPanel admin panels
  logs               Exposed log files (access, error, syslog)

examples:
  %(prog)s /path/to/screenshots/
  %(prog)s /path/to/screenshots/ -t 0.8
  %(prog)s /path/to/screenshots/ -t 0.8 -o results.json
  %(prog)s /path/to/screenshots/ --all
  %(prog)s /path/to/screenshots/ -c login,directory_listing,database_exposed
        """,
    )
    parser.add_argument("input", help="directory containing screenshots")
    parser.add_argument("-t", "--threshold", type=float, default=0.5,
                        help="minimum confidence threshold (default: 0.5)")
    parser.add_argument("-o", "--output", default="classification.json",
                        help="JSON output path (default: classification.json)")
    parser.add_argument("--model", default=str(MODEL_PATH),
                        help="path to .tflite model file")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="suppress all output except errors")
    parser.add_argument("--stream-log", metavar="PATH", default=None,
                        help="write per-image stream to this file (for tail -f)")
    parser.add_argument("--all", action="store_true",
                        help="detect all 12 categories (overrides -c)")
    parser.add_argument("-c", "--categories", type=str, default=None,
                        help="comma-separated list of categories to detect (default: login,directory_listing,stack_trace,oldlooking)")
    args = parser.parse_args()

    if args.all:
        target_labels = list(ALL_LABELS)
    elif args.categories:
        target_labels = [c.strip() for c in args.categories.split(",")]
        invalid = [c for c in target_labels if c not in ALL_LABELS]
        if invalid:
            print(f"Error: unknown categories: {', '.join(invalid)}", file=sys.stderr)
            print(f"Valid categories: {', '.join(ALL_LABELS)}", file=sys.stderr)
            sys.exit(1)
    else:
        target_labels = list(DEFAULT_LABELS)

    input_path = Path(args.input)
    if not input_path.is_dir():
        print(f"Error: {args.input} is not a directory.", file=sys.stderr)
        sys.exit(1)

    model_path = Path(args.model)
    if not model_path.exists():
        print(f"Error: model not found at {args.model}", file=sys.stderr)
        sys.exit(1)

    # Mirror of stdout: quiet flag + optional log file
    stream_log_file = open(args.stream_log, "w", buffering=1) if args.stream_log else None

    def emit(line):
        if not args.quiet:
            print(line, flush=True)
        if stream_log_file:
            stream_log_file.write(line + "\n")
            stream_log_file.flush()

    emit("Loading model...")
    t0 = time.time()
    interpreter = load_model(args.model)
    emit(f"Model loaded in {time.time()-t0:.1f}s")

    all_paths, hash_to_paths = collect_and_dedup(input_path)
    total = len(all_paths)
    unique = len(hash_to_paths)
    emit(f"Images: {total} total, {unique} unique, {total - unique} duplicates")
    emit(f"Classifying {unique} images...")

    t0 = time.time()
    detections = []
    counts = {l: 0 for l in target_labels}
    done = 0
    idx_width = len(str(unique))

    for img_hash, paths in hash_to_paths.items():
        representative = paths[0]
        scores = predict(interpreter, preprocess(representative))

        active = {l: round(scores[l], 4) for l in target_labels if scores[l] >= args.threshold}

        if active:
            for label, score in active.items():
                detections.append({
                    "id": img_hash,
                    "category": label,
                    "score": score,
                })
                counts[label] += 1

        done += 1
        filename = representative.name
        if active:
            best_label = max(active, key=active.get)
            best_score = active[best_label]
            emit(f"[{done:0{idx_width}}/{unique}] {filename:<52}  →  {best_label:<18}  ({best_score:.2f})")
        else:
            emit(f"[{done:0{idx_width}}/{unique}] {filename:<52}  →  {'─':<18}  (skip)")

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
            "target_categories": target_labels,
            "source_directory": str(input_path),
        },
        "counts": counts,
        "detections": detections,
    }

    output_path = Path(args.output)
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    emit(f"\n{'='*50}")
    emit(f"{len(detections)} detections in {elapsed:.1f}s ({unique/elapsed:.1f} img/s)")
    emit(f"{'='*50}")
    for label, count in sorted(counts.items(), key=lambda x: -x[1]):
        bar = "█" * min(count, 40)
        emit(f"  {label:<20} {count:>4}  {bar}")
    emit(f"\nJSON: {output_path}")
    if stream_log_file:
        stream_log_file.close()


if __name__ == "__main__":
    main()
