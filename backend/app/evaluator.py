import json
import os
import re
import unicodedata
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Set

from app.pii_redactor import PIIRedactor

BENCHMARK_PATH = os.path.join(
    os.path.dirname(__file__), "..", "tests", "red_herring_ground_truth.json"
)

ENTITY_KEY_MAP = {
    "full_name": "PERSON",
    "company_name": "ORGANIZATION",
    "email": "EMAIL_ADDRESS",
    "phone": "PHONE_NUMBER",
    "address": "LOCATION",
    "dob": "DATE_TIME",
    "date": "DATE_TIME",
    "cin_pan": "GOVT_ID",
    "reg_no": "GOVT_ID",
    "ssn": "GOVT_ID",
    "credit_card": "GOVT_ID",
    "ip_address": "IP_ADDRESS",
}


def _normalize_text(value: str, entity_type: str = "") -> str:
    """Normalize entity strings so equivalent representations compare cleanly."""
    if value is None:
        return ""

    text = unicodedata.normalize("NFKC", str(value)).strip()
    text = text.replace("\u2013", "-").replace("\u2014", "-")
    # Strip trailing punctuation that detectors may include
    text = text.rstrip(".,;:!?")
    text = re.sub(r"\s+", " ", text)

    if entity_type in {"PHONE_NUMBER", "GOVT_ID"}:
        text = re.sub(r"[^A-Za-z0-9]", "", text).upper()
    elif entity_type == "EMAIL_ADDRESS":
        text = text.lower()
    else:
        text = text.lower()

    return text.strip()


def _iter_detected_entities(redactor: PIIRedactor, text: str) -> Dict[str, Set[str]]:
    """Convert raw detector output into canonical entity-type buckets."""
    raw = redactor.detect_pii(text)
    canonical = defaultdict(set)

    for red_key, values in raw.items():
        entity_type = ENTITY_KEY_MAP.get(red_key, red_key.upper())
        for value in values:
            canonical[entity_type].add(_normalize_text(value, entity_type))

    return dict(canonical)


def _safe_divide(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 1.0 if numerator == 0 else 0.0
    return numerator / denominator


def evaluate_redaction_engine() -> Dict[str, Any]:
    """Compare detector output against the benchmark ground truth and return precision/recall/F1 metrics."""
    with open(BENCHMARK_PATH, "r", encoding="utf-8") as benchmark_file:
        benchmark = json.load(benchmark_file)

    redactor = PIIRedactor()

    total_gt = 0
    total_tp = 0
    total_fp = 0
    total_fn = 0
    by_entity_type: Dict[str, Dict[str, Any]] = {}

    # Track detailed entity lists for reporting
    matched_entities: Dict[str, List[str]] = defaultdict(list)
    missed_entities: Dict[str, List[str]] = defaultdict(list)
    extra_entities: Dict[str, List[str]] = defaultdict(list)

    for entry in benchmark:
        section_text = entry.get("text", "")
        gt_entities = entry.get("ground_truth_entities", [])

        detected = _iter_detected_entities(redactor, section_text)
        matched_gt_values = defaultdict(set)

        for gt in gt_entities:
            entity_type = gt.get("entity_type", "UNKNOWN")
            gt_value = _normalize_text(gt.get("text", ""), entity_type)
            if not gt_value:
                continue

            total_gt += 1
            if entity_type not in by_entity_type:
                by_entity_type[entity_type] = {
                    "true_positives": 0,
                    "false_positives": 0,
                    "false_negatives": 0,
                    "ground_truth_count": 0,
                    "detected_count": 0,
                    "precision": 0.0,
                    "recall": 0.0,
                    "f1_score": 0.0,
                }

            by_entity_type[entity_type]["ground_truth_count"] += 1

            d_values = detected.get(entity_type, set())
            if gt_value in d_values:
                total_tp += 1
                by_entity_type[entity_type]["true_positives"] += 1
                matched_gt_values[entity_type].add(gt_value)
                matched_entities[entity_type].append(gt.get("text", ""))
            else:
                total_fn += 1
                by_entity_type[entity_type]["false_negatives"] += 1
                missed_entities[entity_type].append(gt.get("text", ""))

        for entity_type, values in detected.items():
            if entity_type not in by_entity_type:
                by_entity_type[entity_type] = {
                    "true_positives": 0,
                    "false_positives": 0,
                    "false_negatives": 0,
                    "ground_truth_count": 0,
                    "detected_count": 0,
                    "precision": 0.0,
                    "recall": 0.0,
                    "f1_score": 0.0,
                }

            by_entity_type[entity_type]["detected_count"] += len(values)

            for value in values:
                if value in matched_gt_values.get(entity_type, set()):
                    continue
                if entity_type == "GOVT_ID" and value == "":
                    continue
                total_fp += 1
                by_entity_type[entity_type]["false_positives"] += 1
                extra_entities[entity_type].append(value)

    for entity_type, metrics in by_entity_type.items():
        tp = float(metrics["true_positives"])
        fp = float(metrics["false_positives"])
        fn = float(metrics["false_negatives"])

        precision = _safe_divide(tp, tp + fp)
        recall = _safe_divide(tp, tp + fn)
        f1 = _safe_divide(2 * precision * recall, precision + recall)

        metrics["precision"] = precision
        metrics["recall"] = recall
        metrics["f1_score"] = f1

    overall_precision = _safe_divide(float(total_tp), float(total_tp + total_fp))
    overall_recall = _safe_divide(float(total_tp), float(total_tp + total_fn))
    overall_f1 = _safe_divide(2 * overall_precision * overall_recall, overall_precision + overall_recall)

    total_detected = total_tp + total_fp

    return {
        "overall": {
            "precision": overall_precision,
            "recall": overall_recall,
            "f1_score": overall_f1,
            "true_positives": total_tp,
            "false_positives": total_fp,
            "false_negatives": total_fn,
            "total_ground_truth_entities": total_gt,
            "total_detected_entities": total_detected,
        },
        "by_entity_type": by_entity_type,
        "entity_counts": {
            entity_type: {
                "ground_truth": metrics.get("ground_truth_count", 0),
                "detected": metrics.get("detected_count", 0),
                "matched": metrics["true_positives"],
                "missed": metrics["false_negatives"],
                "extra": metrics["false_positives"],
            }
            for entity_type, metrics in by_entity_type.items()
        },
        "details": {
            "matched": dict(matched_entities),
            "missed": dict(missed_entities),
            "extra": dict(extra_entities),
        },
        "ground_truth_size": total_gt,
    }
