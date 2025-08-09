import pandas as pd
import joblib

# Load model and vectorizer
clf = joblib.load('rf_model.pkl')
vectorizer = joblib.load('tfidf_vectorizer.pkl')

# Load new CVE data
df = pd.read_csv("parsed_nvd_2024.csv")

# Drop rows with missing descriptions
df = df[df['description'].notnull()]

# Vectorize descriptions
X_new = vectorizer.transform(df['description'])

# Predict criticality
df['predicted_label'] = clf.predict(X_new)
df['predicted_label'] = df['predicted_label'].map({1: "CRITICAL", 0: "Not Critical"})

# Save results
df.to_csv("nvd_2024_with_predictions.csv", index=False)

print("✅ Predictions saved to nvd_2024_with_predictions.csv")
