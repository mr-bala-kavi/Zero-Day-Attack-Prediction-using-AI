import joblib

# Load model and vectorizer
clf = joblib.load('rf_model.pkl')
vectorizer = joblib.load('tfidf_vectorizer.pkl')

# Get description from user
description = input("\n📝 Enter CVE description: ")

# Vectorize input
X_new = vectorizer.transform([description])

# Predict
prediction = clf.predict(X_new)

# Output
print("🔥 Prediction:", "CRITICAL" if prediction[0] == 1 else "Not Critical")
