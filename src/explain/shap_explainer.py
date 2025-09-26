import os
import numpy as np
import joblib

# Setup model path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.getenv(
    "MODEL_PATH",
    os.path.normpath(os.path.join(BASE_DIR, "..", "modals", "randomForestModel.pkl"))  # <- check filename
)

# Load the model
model = joblib.load(MODEL_PATH)


def explain_prediction(model, feature_vector, risk_score, predicted_class, probabilities):
    """Generate explanation for the prediction with safe fallbacks"""

    explanations = []

    try:
        # Ensure feature_vector is 1D
        if hasattr(feature_vector, "ndim") and feature_vector.ndim > 1:
            feature_vector = feature_vector[0]

        # === Risk score based explanation ===
        if risk_score < 0.3:
            explanations.append("This URL appears to be safe based on our analysis.")
        elif risk_score < 0.7:
            explanations.append("This URL shows some suspicious characteristics.")
        else:
            explanations.append("This URL displays multiple concerning characteristics.")

        # === Predicted class explanation ===
        if predicted_class is not None:
            if predicted_class == 1:  # defacement
                explanations.append("This URL shows characteristics of a defaced website.")
            elif predicted_class == 2:  # phishing
                explanations.append("This URL exhibits patterns commonly associated with phishing attempts.")
            elif predicted_class == 3:  # malware
                explanations.append("This URL is likely associated with malware distribution.")
            else:  # benign
                explanations.append("This URL appears to be legitimate and safe.")

        # === Feature-based explanation ===
        feature_names = [
            'use_of_ip', 'abnormal_url', 'count_dots', 'count_www', 'count_at',
            'count_dir', 'count_embed_domain', 'short_url', 'count_https',
            'count_http', 'count_percent', 'count_question', 'count_hyphen',
            'count_equal', 'url_length', 'hostname_length', 'suspicious_words',
            'fd_length', 'tld_length', 'digit_count', 'letter_count'
        ]

        if len(feature_vector) > 0 and feature_vector[0] == 1:
            explanations.append("The domain is an IP address, which is unusual for legitimate sites.")
        if len(feature_vector) > 1 and feature_vector[1] == 1:
            explanations.append("The URL structure appears abnormal.")
        if len(feature_vector) > 16 and feature_vector[16] == 1:
            explanations.append("Contains keywords commonly used in malicious URLs.")
        if len(feature_vector) > 7 and feature_vector[7] == 1:
            explanations.append("Uses a URL shortening service, which can hide the true destination.")
        if len(feature_vector) > 14 and feature_vector[14] > 100:
            explanations.append("URL is unusually long, which can be a sign of malicious intent.")

        # Positive indicators for safe sites
        if predicted_class == 0:  # benign
            if len(feature_vector) > 8 and feature_vector[8] > 0:
                explanations.append("Uses HTTPS for secure communication.")

        # === Probability-based explanation ===
        if probabilities is not None and len(probabilities) > predicted_class:
            class_labels = ["benign", "defacement", "phishing", "malware"]
            max_class = class_labels[predicted_class]
            confidence = probabilities[predicted_class] * 100
            explanations.append(f"Model is {confidence:.2f}% confident this URL is {max_class}.")
        else:
            explanations.append("Confidence could not be calculated due to missing probability data.")

        # === Feature importance explanation ===
        if hasattr(model, "feature_importances_"):
            try:
                top_features = np.argsort(model.feature_importances_)[-3:][::-1]
                top_feature_names = [feature_names[i] for i in top_features]
                explanations.append(f"Top contributing features: {', '.join(top_feature_names)}")
            except Exception:
                explanations.append("Top feature importance could not be determined.")

        # === Safety fallback ===
        if not explanations:
            explanations.append("No specific indicators found, but the model classified it as safe.")

    except Exception as e:
        explanations = [f"Error while generating explanation: {str(e)}"]

    return explanations
