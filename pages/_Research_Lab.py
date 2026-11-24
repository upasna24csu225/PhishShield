
import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path

st.set_page_config(
    page_title="Research Lab | PhishShield X",
    page_icon="🔬",
    layout="wide"
)

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "outputs"

MODEL_FILE = OUTPUT_DIR / "model_comparison.csv"
GROUP_FILE = OUTPUT_DIR / "feature_group_importance.csv"
FEATURE_FILE = OUTPUT_DIR / "individual_feature_importance.csv"
TRANSFORMER_FILE = OUTPUT_DIR / "transformer_metrics.csv"

st.title("🔬 Research Lab")
st.caption("MODEL EVALUATION • FEATURE ANALYSIS • RESEARCH INSIGHTS")

st.divider()

# Load files safely
def load_csv(path):
    if path.exists():
        try:
            return pd.read_csv(path)
        except Exception as e:
            st.error(f"Unable to read {path.name}: {e}")
    return None

results = load_csv(MODEL_FILE)
groups = load_csv(GROUP_FILE)
features = load_csv(FEATURE_FILE)
transformer = load_csv(TRANSFORMER_FILE)

# Overview
st.subheader("📊 Research Overview")

c1, c2, c3 = st.columns(3)

c1.metric(
    "ML Models Evaluated",
    len(results) if results is not None else 0
)

c2.metric(
    "Feature Groups",
    len(groups) if groups is not None else 0
)

c3.metric(
    "Individual Features",
    len(features) if features is not None else 0
)

st.divider()

# Model Comparison
st.subheader("🤖 Machine Learning Model Comparison")

if results is not None and not results.empty:
    st.dataframe(results, use_container_width=True)

    required = ["Model", "Accuracy", "Precision", "Recall", "F1 Score"]

    if all(col in results.columns for col in required):
        metric_data = results.melt(
            id_vars="Model",
            value_vars=["Accuracy", "Precision", "Recall", "F1 Score"],
            var_name="Metric",
            value_name="Score"
        )

        fig = px.bar(
            metric_data,
            x="Model",
            y="Score",
            color="Metric",
            barmode="group",
            title="Performance Comparison of ML Models",
            range_y=[0, 1]
        )

        st.plotly_chart(fig, use_container_width=True)
    else:
        st.warning("Model CSV is missing required metric columns.")
else:
    st.info("Model comparison data is not available yet. Run python train.py.")

st.divider()

# Feature Group Importance
st.subheader("🧠 Feature Group Importance")

if groups is not None and not groups.empty:
    st.dataframe(groups, use_container_width=True)

    if {"Feature Group", "Importance"}.issubset(groups.columns):
        fig = px.bar(
            groups,
            x="Feature Group",
            y="Importance",
            color="Feature Group",
            title="Linguistic vs Semantic vs Contextual Features"
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.warning("Feature group CSV has an incorrect column format.")
else:
    st.info("Feature group data is not available yet.")

st.divider()

# Individual Feature Importance
st.subheader("🔍 Individual Feature Importance")

if features is not None and not features.empty:
    st.dataframe(features, use_container_width=True)

    if {"Feature", "Importance"}.issubset(features.columns):
        fig = px.bar(
            features.head(15).sort_values("Importance"),
            x="Importance",
            y="Feature",
            orientation="h",
            title="Top 15 Important Features"
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.warning("Individual feature CSV has an incorrect column format.")
else:
    st.info("Individual feature data is not available yet.")

st.divider()

# Transformer
st.subheader("🧠 Transformer Model Evaluation")

if transformer is not None and not transformer.empty:
    st.dataframe(transformer, use_container_width=True)

    if "Model" in transformer.columns:
        transformer = transformer.drop(columns=["Model"])

    available_metrics = [
        col for col in ["Accuracy", "Precision", "Recall", "F1 Score"]
        if col in transformer.columns
    ]

    if available_metrics:
        chart_data = transformer[available_metrics].melt(
            var_name="Metric",
            value_name="Score"
        )

        fig = px.bar(
            chart_data,
            x="Metric",
            y="Score",
            title="DistilBERT Performance"
        )

        st.plotly_chart(fig, use_container_width=True)
else:
    st.info(
        "Transformer results will appear here after training "
        "the model in Advanced Model Lab."
    )

st.divider()

# Output status
st.subheader("📁 Research Output Files")

files = {
    "Model Comparison": MODEL_FILE,
    "Feature Group Importance": GROUP_FILE,
    "Individual Feature Importance": FEATURE_FILE,
    "Transformer Metrics": TRANSFORMER_FILE
}

for name, path in files.items():
    if path.exists():
        st.success(f"{name}: Available")
    else:
        st.warning(f"{name}: Not generated yet")

st.caption("PHISHSHIELD X | AI-POWERED EMAIL THREAT INVESTIGATION")

