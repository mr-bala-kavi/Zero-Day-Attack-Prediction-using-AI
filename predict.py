import joblib

# Load model and vectorizer
clf = joblib.load('rf_model.pkl')
vectorizer = joblib.load('tfidf_vectorizer.pkl')

# Sample input (replace with any CVE description)
description = """An attacker could execute arbitrary code remotely by sending a specially crafted packet to the service running on port 445."""

# Vectorize input
X_new = vectorizer.transform([description])

# Predict
prediction = clf.predict(X_new)

# Output
print("🔥 Prediction:", "CRITICAL" if prediction[0] == 1 else "Not Critical")
