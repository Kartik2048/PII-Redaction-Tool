"""
Evaluation Engine (evaluator.py)

Evaluates the PII Redaction Engine (backend/app/redactor.py) against a benchmark
ground truth dataset (red_herring_ground_truth.json) and calculates Precision,
Recall, and F1 Score (overall and per-entity breakdown).
"""

import json
import os
import sys
from typing import Dict, Any, List, Tuple

# Ensure parent backend directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.redactor import PIIRedactor


# Canonical mapping for entity type unification across Redactor & Ground Truth
CANONICAL_ENTITY_MAP = {
    "PERSON": "PERSON",
    "FULL_NAMES": "PERSON",
    "EMAIL": "EMAIL_ADDRESS",
    "EMAIL_ADDRESS": "EMAIL_ADDRESS",
    "PHONE": "PHONE_NUMBER",
    "PHONE_NUMBER": "PHONE_NUMBER",
    "ORGANIZATION": "ORGANIZATION",
    "COMPANY_NAMES": "ORGANIZATION",
    "LOCATION": "LOCATION",
    "ADDRESSES": "LOCATION",
    "SSN_GOVT_ID": "GOVT_ID",
    "GOVT_ID": "GOVT_ID",
    "DATE_OF_BIRTH": "DATE_TIME",
    "DATE_TIME": "DATE_TIME",
}


def _clean_str(s: str) -> str:
    """Normalize string by lowering and stripping whitespace/punctuation."""
    return "".join(c.lower() for c in s if c.isalnum())


def evaluate_redaction_engine(
    ground_truth_path: str = "backend/tests/red_herring_ground_truth.json",
    spacy_model: str = "en_core_web_sm",
) -> Dict[str, Any]:
    """
    Evaluates the core PII redaction engine against ground truth annotations.

    Returns:
        Dict[str, Any]: Overall metrics (precision, recall, f1_score, tp, fp, fn)
                        and per-entity metrics breakdown.
    """
    # Fallback path resolution if file is relative
    if not os.path.exists(ground_truth_path):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        alt_path = os.path.join(base_dir, "tests", "red_herring_ground_truth.json")
        if os.path.exists(alt_path):
            ground_truth_path = alt_path

    with open(ground_truth_path, "r", encoding="utf-8") as f:
        ground_truth_data = json.load(f)

    redactor = PIIRedactor(spacy_model=spacy_model)

    entity_metrics: Dict[str, Dict[str, int]] = {}

    for sample in ground_truth_data:
        text = sample.get("text", "")
        gt_items = sample.get("ground_truth_entities", [])

        # Analyze sample text with PIIRedactor
        presidio_results = redactor.analyze_text(text)
        resolved_results = redactor._resolve_overlapping_entities(presidio_results)

        # Extract detected entities
        detected_entities: List[Tuple[str, str]] = []
        for r in resolved_results:
            raw_type = redactor.entity_type_map.get(r.entity_type, r.entity_type)
            canonical_type = CANONICAL_ENTITY_MAP.get(raw_type, raw_type)
            ent_text = text[r.start : r.end]
            detected_entities.append((canonical_type, ent_text))

        # Ground truth entities
        gt_entities: List[Tuple[str, str]] = [
            (
                CANONICAL_ENTITY_MAP.get(item["entity_type"], item["entity_type"]),
                item["text"],
            )
            for item in gt_items
        ]

        # Match detected vs ground truth per entity type
        matched_gt_indices = set()
        matched_det_indices = set()

        for det_idx, (det_type, det_text) in enumerate(detected_entities):
            det_clean = _clean_str(det_text)
            for gt_idx, (gt_type, gt_text) in enumerate(gt_entities):
                if gt_idx in matched_gt_indices:
                    continue
                if det_type == gt_type:
                    gt_clean = _clean_str(gt_text)
                    if (
                        det_clean == gt_clean
                        or det_clean in gt_clean
                        or gt_clean in det_clean
                    ):
                        matched_gt_indices.add(gt_idx)
                        matched_det_indices.add(det_idx)
                        break

        # Calculate TP, FP, FN for this sample
        for gt_idx, (gt_type, _) in enumerate(gt_entities):
            if gt_type not in entity_metrics:
                entity_metrics[gt_type] = {"tp": 0, "fp": 0, "fn": 0}

            if gt_idx in matched_gt_indices:
                entity_metrics[gt_type]["tp"] += 1
            else:
                entity_metrics[gt_type]["fn"] += 1

        for det_idx, (det_type, _) in enumerate(detected_entities):
            if det_type not in entity_metrics:
                entity_metrics[det_type] = {"tp": 0, "fp": 0, "fn": 0}

            if det_idx not in matched_det_indices:
                entity_metrics[det_type]["fp"] += 1

    # Aggregate Overall and Per-Entity Metrics
    total_tp = sum(m["tp"] for m in entity_metrics.values())
    total_fp = sum(m["fp"] for m in entity_metrics.values())
    total_fn = sum(m["fn"] for m in entity_metrics.values())

    def calc_stats(tp: int, fp: int, fn: int) -> Tuple[float, float, float]:
        precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if fn == 0 else 0.0)
        recall = tp / (tp + fn) if (tp + fn) > 0 else (1.0 if fp == 0 else 0.0)
        f1 = (
            (2 * precision * recall) / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )
        return round(precision, 4), round(recall, 4), round(f1, 4)

    overall_p, overall_r, overall_f1 = calc_stats(total_tp, total_fp, total_fn)

    by_entity_type = {}
    for etype, m in entity_metrics.items():
        p, r, f1 = calc_stats(m["tp"], m["fp"], m["fn"])
        by_entity_type[etype] = {
            "precision": p,
            "recall": r,
            "f1_score": f1,
            "tp": m["tp"],
            "fp": m["fp"],
            "fn": m["fn"],
        }

    return {
        "overall": {
            "precision": overall_p,
            "recall": overall_r,
            "f1_score": overall_f1,
            "tp": total_tp,
            "fp": total_fp,
            "fn": total_fn,
        },
        "by_entity_type": by_entity_type,
    }


if __name__ == "__main__":
    report = evaluate_redaction_engine()
    print(json.dumps(report, indent=2))
