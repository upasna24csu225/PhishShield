



import streamlit as st
import pandas as pd
import joblib
import os

from src.features import extract_features


st.set_page_config(
    page_title="Explainable AI | PhishShield X",
    page_icon="🧠",
    layout="wide"
)

st.title("🧠 Explainable AI")
st.caption("Understand machine learning predictions and email indicators.")


MODEL_PATH = "models/phishshield_models.pkl"
VECTORIZER_PATH = "models/tfidf_vectorizer.pkl"
FEATURES_PATH = "models/feature_names.pkl"


@st.cache_resource
def load_artifacts():

    if not all(os.path.exists(path) for path in [
        MODEL_PATH, VECTORIZER_PATH, FEATURES_PATH
    ]):
        return None, None, None

    models = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    feature_names = joblib.load(FEATURES_PATH)

    return models, vectorizer, feature_names


models, vectorizer, feature_names = load_artifacts()


if models is None:
    st.error("Model files are missing. Run python train.py first.")
    st.stop()


email = st.text_area(
    "Enter email content",
    height=220,
    placeholder="Paste the email content here..."
)


if st.button("Analyze Email", type="primary"):

    if not email.strip():

        st.warning("Please enter email content.")

    else:

        numeric_features = extract_features(email)

        numeric_input = pd.DataFrame(
            [[numeric_features.get(name, 0) for name in feature_names]],
            columns=feature_names
        ).fillna(0)

        tfidf_input = vectorizer.transform([email])

        results = []

        st.subheader("Machine Learning Predictions")

        for name, artifact in models.items():

            try:

                model = artifact["model"]
                input_type = artifact["input_type"]

                if input_type == "tfidf":
                    prediction = model.predict(tfidf_input)[0]

                else:
                    prediction = model.predict(numeric_input)[0]

                prediction = int(prediction)

                results.append({
                    "Model": name,
                    "Prediction": prediction,
                    "Classification": (
                        "Phishing Email" if prediction == 1
                        else "Safe Email"
                    )
                })

            except Exception as error:

                st.warning(
                    f"{name} could not analyze this email: {error}"
                )

        if results:

            result_df = pd.DataFrame(results)

            phishing_count = int(
                (result_df["Prediction"] == 1).sum()
            )

            safe_count = int(
                (result_df["Prediction"] == 0).sum()
            )

            total_predictions = len(results)

            phishing_percentage = (
                phishing_count / total_predictions
            ) * 100

            safe_percentage = (
                safe_count / total_predictions
            ) * 100

            # FINAL AI VERDICT

            st.divider()

            st.subheader("🚨 FINAL AI VERDICT")

            if phishing_count > safe_count:

                st.error("🚨 PHISHING EMAIL DETECTED")

                st.write(
                    f"Majority of the models ({phishing_count} out of "
                    f"{total_predictions}) classified this email as phishing. "
                    "Avoid clicking suspicious links or sharing sensitive information."
                )

            elif safe_count > phishing_count:

                st.success("✅ LIKELY LEGITIMATE EMAIL")

                st.write(
                    f"Majority of the models ({safe_count} out of "
                    f"{total_predictions}) classified this email as safe. "
                    "However, this does not guarantee that the email is harmless."
                )

            else:

                st.warning("⚠️ INCONCLUSIVE CLASSIFICATION")

                st.write(
                    "The models are equally divided. "
                    "Manual investigation is recommended."
                )

            # PREDICTION SUMMARY

            st.subheader("📊 Prediction Summary")

            col1, col2, col3 = st.columns(3)

            col1.metric(
                "Phishing Predictions",
                phishing_count
            )

            col2.metric(
                "Safe Predictions",
                safe_count
            )

            col3.metric(
                "Models Analyzed",
                total_predictions
            )

            st.write(
                f"Phishing Model Agreement: {phishing_percentage:.1f}%"
            )

            st.progress(phishing_percentage / 100)

            # MODEL COMPARISON

            st.divider()

            st.subheader("Individual Model Predictions")

            st.dataframe(
                result_df,
                use_container_width=True,
                hide_index=True
            )

            st.subheader("Model Prediction Distribution")

            prediction_chart = pd.DataFrame({
                "Classification": ["Phishing", "Safe"],
                "Number of Models": [
                    phishing_count,
                    safe_count
                ]
            })

            st.bar_chart(
                prediction_chart.set_index("Classification")
            )

        else:

            st.error(
                "No model could analyze this email. "
                "Please check your trained model files."
            )

        # EXPLAINABLE EMAIL INDICATORS

        st.divider()

        st.subheader("🔍 Explainable Email Indicators")

        feature_df = pd.DataFrame(
            list(numeric_features.items()),
            columns=["Feature", "Detected Value"]
        )

        st.dataframe(
            feature_df,
            use_container_width=True,
            hide_index=True
        )

        numeric_chart = feature_df.copy()

        numeric_chart["Detected Value"] = pd.to_numeric(
            numeric_chart["Detected Value"],
            errors="coerce"
        )

        numeric_chart = numeric_chart.dropna()

        if not numeric_chart.empty:

            st.subheader("Feature Analysis Graph")

            st.bar_chart(
                numeric_chart.set_index("Feature")
            )

        st.info(
            "These indicators show measurable email characteristics. "
            "They do not independently prove that an email is malicious."
        )


st.divider()

st.warning(
    "Predictions are automated model classifications, not guaranteed "
    "security verdicts or calibrated probabilities. "
    "The final AI verdict represents majority agreement among "
    "successfully executed models."
)
