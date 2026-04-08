"""
ML-based threat classifier for NebulaShield WAF.

Uses TF-IDF character n-grams combined with heuristic numerical features
fed into a RandomForestClassifier for binary (benign/malicious) and
multi-class (attack type) prediction.
"""

import logging
import os
from typing import Any, Dict, Optional

import numpy as np

logger = logging.getLogger(__name__)

# Attack type display name mapping
_ATTACK_TYPE_LABELS = {
    "sqli": "SQL Injection",
    "xss": "XSS",
    "command_injection": "Command Injection",
    "path_traversal": "Path Traversal",
    "ssrf": "SSRF",
    "xxe": "XXE",
    "encoded": "Encoded Attack",
    "none": "None",
}


class MLThreatClassifier:
    """
    Machine-learning threat classifier that combines TF-IDF character n-gram
    features with numerical heuristic features extracted by ThreatAnalyzer.
    """

    def __init__(self, model_path: str = "models/threat_classifier.pkl"):
        self.model = None           # binary classifier (malicious vs benign)
        self.type_model = None      # multi-class attack-type classifier
        self.vectorizer = None      # TF-IDF vectorizer
        self.label_encoder = None   # LabelEncoder for attack_type classes
        self.model_path = model_path
        self._feature_count: Optional[int] = None

    # ---------------------------------------------------------------------- #
    # Training
    # ---------------------------------------------------------------------- #

    def train(self, csv_path: str = "data/training_data.csv") -> Dict[str, Any]:
        """
        Train the binary and multi-class models from a labeled CSV file.

        The CSV must have columns: payload, label, attack_type
          - label: 1 = malicious, 0 = benign
          - attack_type: e.g. "sqli", "xss", "none", …

        Returns a dict with classification_report and confusion_matrix strings.
        """
        try:
            import pandas as pd
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.metrics import classification_report, confusion_matrix
            from sklearn.model_selection import train_test_split
            from sklearn.preprocessing import LabelEncoder
            import scipy.sparse as sp
            import joblib
        except ImportError as exc:
            raise RuntimeError(
                "scikit-learn, joblib, and pandas are required for ML training. "
                "Install them with: pip install scikit-learn joblib pandas"
            ) from exc

        # 1. Load CSV
        df = pd.read_csv(csv_path)
        if not {"payload", "label", "attack_type"}.issubset(df.columns):
            raise ValueError("CSV must contain columns: payload, label, attack_type")

        df = df.dropna(subset=["payload"])
        df["payload"] = df["payload"].astype(str)
        df["label"] = df["label"].astype(int)
        df["attack_type"] = df["attack_type"].fillna("none").astype(str)

        payloads = df["payload"].tolist()
        labels = df["label"].tolist()
        attack_types = df["attack_type"].tolist()

        # 2. Feature extraction
        # 2a. TF-IDF on character n-grams (catches patterns like 'OR', <scr, ../)
        self.vectorizer = TfidfVectorizer(
            analyzer="char",
            ngram_range=(2, 5),
            max_features=5000,
            sublinear_tf=True,
        )
        tfidf_matrix = self.vectorizer.fit_transform(payloads)

        # 2b. Numerical features from ThreatAnalyzer
        numerical = self._extract_numerical_features(payloads)
        combined = sp.hstack([tfidf_matrix, sp.csr_matrix(numerical)])
        self._feature_count = combined.shape[1]

        # 3. Train binary classifier
        X_train, X_test, y_train, y_test = train_test_split(
            combined, labels, test_size=0.2, random_state=42, stratify=labels
        )
        self.model = RandomForestClassifier(
            n_estimators=200, random_state=42, n_jobs=-1
        )
        self.model.fit(X_train, y_train)

        y_pred = self.model.predict(X_test)
        binary_report = classification_report(
            y_test, y_pred, target_names=["benign", "malicious"]
        )
        binary_cm = confusion_matrix(y_test, y_pred).tolist()
        logger.info("Binary classifier report:\n%s", binary_report)

        # 4. Train multi-class attack-type classifier
        self.label_encoder = LabelEncoder()
        encoded_types = self.label_encoder.fit_transform(attack_types)

        Xt_train, Xt_test, yt_train, yt_test = train_test_split(
            combined, encoded_types, test_size=0.2, random_state=42
        )
        self.type_model = RandomForestClassifier(
            n_estimators=200, random_state=42, n_jobs=-1
        )
        self.type_model.fit(Xt_train, yt_train)

        yt_pred = self.type_model.predict(Xt_test)
        type_report = classification_report(
            yt_test, yt_pred, labels=list(range(len(self.label_encoder.classes_))),
            target_names=self.label_encoder.classes_, zero_division=0
        )
        logger.info("Attack-type classifier report:\n%s", type_report)

        # 5. Save artifacts
        os.makedirs(os.path.dirname(self.model_path) or ".", exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "type_model": self.type_model,
                "vectorizer": self.vectorizer,
                "label_encoder": self.label_encoder,
                "feature_count": self._feature_count,
            },
            self.model_path,
        )
        logger.info("ML model saved to %s", self.model_path)

        return {
            "binary_classification_report": binary_report,
            "binary_confusion_matrix": binary_cm,
            "attack_type_classification_report": type_report,
            "samples_trained": len(payloads),
            "feature_count": self._feature_count,
        }

    # ---------------------------------------------------------------------- #
    # Loading
    # ---------------------------------------------------------------------- #

    def load(self) -> bool:
        """Load a pre-trained model from disk. Returns True on success."""
        try:
            import joblib
        except ImportError:
            logger.warning("joblib not installed — cannot load ML model")
            return False

        if not os.path.exists(self.model_path):
            logger.info("ML model file not found at %s", self.model_path)
            return False

        try:
            artifacts = joblib.load(self.model_path)
            self.model = artifacts["model"]
            self.type_model = artifacts["type_model"]
            self.vectorizer = artifacts["vectorizer"]
            self.label_encoder = artifacts["label_encoder"]
            self._feature_count = artifacts.get("feature_count")
            logger.info(
                "ML model loaded from %s (features=%s)",
                self.model_path,
                self._feature_count,
            )
            return True
        except Exception as exc:
            logger.error("Failed to load ML model: %s", exc)
            self.model = None
            return False

    # ---------------------------------------------------------------------- #
    # Prediction
    # ---------------------------------------------------------------------- #

    def predict(self, payload: str, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict whether a payload is malicious.

        Returns:
            {
                "ml_prediction": "MALICIOUS" | "BENIGN",
                "ml_confidence": 0.95,
                "ml_score": 95,
                "ml_attack_type": "SQL Injection",
                "ml_probabilities": {"benign": 0.05, "malicious": 0.95},
            }
        """
        if not self.is_loaded():
            raise RuntimeError("ML model is not loaded. Call load() or train() first.")

        import scipy.sparse as sp

        tfidf_vec = self.vectorizer.transform([payload])
        num_features = self._build_numerical_row(features)
        combined = sp.hstack([tfidf_vec, sp.csr_matrix(num_features)])

        # Binary prediction
        proba = self.model.predict_proba(combined)[0]
        classes = self.model.classes_  # [0, 1] → [benign, malicious]
        malicious_idx = list(classes).index(1) if 1 in classes else 1
        benign_idx = list(classes).index(0) if 0 in classes else 0

        malicious_prob = float(proba[malicious_idx])
        benign_prob = float(proba[benign_idx])
        prediction = "MALICIOUS" if malicious_prob > 0.5 else "BENIGN"
        confidence = malicious_prob if prediction == "MALICIOUS" else benign_prob

        # Attack-type prediction
        type_pred_encoded = self.type_model.predict(combined)[0]
        raw_type = self.label_encoder.inverse_transform([type_pred_encoded])[0]
        attack_type_label = _ATTACK_TYPE_LABELS.get(raw_type, raw_type.replace("_", " ").title())

        return {
            "ml_prediction": prediction,
            "ml_confidence": round(confidence, 4),
            "ml_score": round(malicious_prob * 100),
            "ml_attack_type": attack_type_label,
            "ml_probabilities": {
                "benign": round(benign_prob, 4),
                "malicious": round(malicious_prob, 4),
            },
        }

    # ---------------------------------------------------------------------- #
    # Status
    # ---------------------------------------------------------------------- #

    def is_loaded(self) -> bool:
        """Check if the model is loaded and ready for prediction."""
        return self.model is not None

    @property
    def feature_count(self) -> Optional[int]:
        return self._feature_count

    # ---------------------------------------------------------------------- #
    # Internal helpers
    # ---------------------------------------------------------------------- #

    def _extract_numerical_features(self, payloads: list) -> np.ndarray:
        """Extract numerical heuristic features for a list of payload strings."""
        from src.analyzer.threat_analyzer import ThreatAnalyzer

        ta = ThreatAnalyzer()
        rows = []
        for payload in payloads:
            feats = ta.extract_features(payload)
            rows.append(self._feature_dict_to_row(feats))
        return np.array(rows, dtype=float)

    def _build_numerical_row(self, features: Dict[str, Any]) -> np.ndarray:
        """Convert a single features dict to a 1-row numerical numpy array."""
        return np.array([self._feature_dict_to_row(features)], dtype=float)

    @staticmethod
    def _feature_dict_to_row(feats: Dict[str, Any]) -> list:
        """Extract an ordered list of numerical values from a features dict."""
        return [
            float(feats.get("entropy", 0)),
            float(feats.get("entropy_anomaly", False)),
            float(feats.get("sql_keywords_count", 0)),
            float(feats.get("sql_comments", 0)),
            float(feats.get("suspicious_quotes", 0)),
            float(feats.get("script_tags", 0)),
            float(feats.get("html_entities", 0)),
            float(feats.get("path_traversal", 0)),
            float(feats.get("null_bytes", 0)),
            float(feats.get("internal_ips", 0)),
            float(feats.get("localhost_refs", 0)),
            float(feats.get("protocol_confusion", 0)),
            float(feats.get("url_encoding_ratio", 0)),
            float(feats.get("double_encoding", 0)),
            float(feats.get("unicode_escapes", 0)),
            float(feats.get("payload_length", 0)),
            float(feats.get("avg_token_length", 0)),
            float(feats.get("rare_char_ratio", 0)),
            float(feats.get("command_keywords", 0)),
            float(feats.get("xxe_indicators", 0)),
        ]
