"""
eval_harness.py
----------------
Runs scanners.scan_text against every payload in eval_payloads.json and
scores it for precision/recall/F1 -- the number that turns "I built a
security tool" into a defensible claim.

This evaluates the detection logic directly (the thing that's actually
under test) rather than round-tripping every payload through the full
stdio MCP stack, which v1 already proved works. gateway.py calls this
exact same scan_text() function at all three hook points, so these
numbers describe the gateway's real behavior.

Run:
    python eval_harness.py

Writes eval_results.json (full per-case predictions) and prints a
summary table, overall and broken down by category.
"""

import json
import os
from pathlib import Path

from scanners import scan_text

PAYLOADS_FILE = Path(__file__).parent / "eval_payloads.json"
RESULTS_FILE = Path(__file__).parent / "eval_results.json"


def load_payloads() -> list:
    with open(PAYLOADS_FILE, encoding="utf-8") as f:
        return json.load(f)


def score(cases: list) -> dict:
    tp = fp = tn = fn = 0
    per_category = {}

    for case in cases:
        expected_malicious = case["label"] == "malicious"
        result = scan_text(case["text"])
        predicted_malicious = result.suspicious

        if expected_malicious and predicted_malicious:
            outcome = "TP"
            tp += 1
        elif not expected_malicious and predicted_malicious:
            outcome = "FP"
            fp += 1
        elif not expected_malicious and not predicted_malicious:
            outcome = "TN"
            tn += 1
        else:
            outcome = "FN"
            fn += 1

        case["_predicted"] = predicted_malicious
        case["_outcome"] = outcome
        case["_scan"] = result.to_dict()

        cat = case["category"]
        per_category.setdefault(cat, {"TP": 0, "FP": 0, "TN": 0, "FN": 0})
        per_category[cat][outcome] += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = (tp + tn) / len(cases) if cases else 0.0

    return {
        "overall": {
            "n": len(cases),
            "TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
            "accuracy": round(accuracy, 3),
        },
        "per_category": per_category,
        "cases": cases,
    }


def print_report(results: dict) -> None:
    o = results["overall"]
    llm_active = bool(os.environ.get("GROQ_API_KEY"))

    print("=" * 60)
    print("MCP Security Gateway -- Scanner Eval")
    print("=" * 60)
    print(f"LLM escalation tier: {'ACTIVE (GROQ_API_KEY set)' if llm_active else 'INACTIVE (regex-only mode)'}")
    print(f"Cases: {o['n']}   TP={o['TP']}  FP={o['FP']}  TN={o['TN']}  FN={o['FN']}")
    print(f"Precision: {o['precision']}   Recall: {o['recall']}   F1: {o['f1']}   Accuracy: {o['accuracy']}")
    print()
    print(f"{'Category':<22}{'TP':>4}{'FP':>4}{'TN':>4}{'FN':>4}")
    for cat, c in results["per_category"].items():
        print(f"{cat:<22}{c['TP']:>4}{c['FP']:>4}{c['TN']:>4}{c['FN']:>4}")
    print()

    misses = [c for c in results["cases"] if c["_outcome"] in ("FP", "FN")]
    if misses:
        print("--- Misses (for the README's honest-limitations section) ---")
        for c in misses:
            print(f"  [{c['_outcome']}] {c['id']} ({c['category']}): {c['note']}")
    print("=" * 60)


if __name__ == "__main__":
    payloads = load_payloads()
    results = score(payloads)
    with open(RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print_report(results)
