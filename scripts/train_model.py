#!/usr/bin/env python
"""
Train the NebulaShield ML threat classifier.

Usage:
    python scripts/train_model.py [--csv data/training_data.csv] [--model models/threat_classifier.pkl]

Trains from the CSV, prints classification report + confusion matrix, and
saves the artifacts to the models/ directory.
"""

import argparse
import os
import sys

# Ensure project root is on the path regardless of where the script is invoked from
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.analyzer.ml_classifier import MLThreatClassifier


def main():
    parser = argparse.ArgumentParser(description="Train the NebulaShield ML classifier")
    parser.add_argument(
        "--csv",
        default="data/training_data.csv",
        help="Path to labeled training CSV (default: data/training_data.csv)",
    )
    parser.add_argument(
        "--model",
        default="models/threat_classifier.pkl",
        help="Where to save the trained model (default: models/threat_classifier.pkl)",
    )
    args = parser.parse_args()

    if not os.path.exists(args.csv):
        print(f"ERROR: Training data not found at '{args.csv}'")
        sys.exit(1)

    print(f"Loading training data from: {args.csv}")
    classifier = MLThreatClassifier(model_path=args.model)

    print("Training model…")
    metrics = classifier.train(csv_path=args.csv)

    print("\n" + "=" * 60)
    print("BINARY CLASSIFIER (malicious vs benign)")
    print("=" * 60)
    print(metrics["binary_classification_report"])

    print("Confusion matrix (rows=actual, cols=predicted):")
    print("  [benign_correct  benign_as_malicious]")
    print("  [malicious_as_benign  malicious_correct]")
    for row in metrics["binary_confusion_matrix"]:
        print(" ", row)

    print("\n" + "=" * 60)
    print("ATTACK TYPE CLASSIFIER (multi-class)")
    print("=" * 60)
    print(metrics["attack_type_classification_report"])

    print(f"\nSamples trained on : {metrics['samples_trained']}")
    print(f"Total feature count: {metrics['feature_count']}")
    print(f"\nModel saved to: {args.model}")


if __name__ == "__main__":
    main()
