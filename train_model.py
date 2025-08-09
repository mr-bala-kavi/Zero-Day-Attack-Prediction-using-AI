import pandas as pd
import numpy as np
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# 1. Load and clean
df = pd.read_csv("cve_data.csv", engine='python', quotechar='"', on_bad_lines='skip')
df.replace('?', np.nan, inplace=True)

# 2. Keep rows with both severity and details
df = df[df['Severity'].notnull() & df['details'].notnull()]

# 3. Normalize severity
df['Severity'] = df['Severity'].str.lower().str.strip()

# 4. Label: 1 for critical/high, 0 for others
df['label'] = df['Severity'].apply(lambda x: 1 if x in ['high', 'critical'] else 0)

# 5. TF-IDF vectorization
tfidf = TfidfVectorizer(max_features=1000, stop_words='english')
X = tfidf.fit_transform(df['details'])

# 6. Prepare data
y = df['label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 7. Train model
clf = RandomForestClassifier(n_estimators=100)
clf.fit(X_train, y_train)

# 8. Evaluate
y_pred = clf.predict(X_test)
print("\n📊 Classification Report:\n")
print(classification_report(y_test, y_pred))

# Save the model
joblib.dump(clf, 'rf_model.pkl')
print("✅ Model saved as rf_model.pkl")

# Save the TF-IDF vectorizer
joblib.dump(tfidf, 'tfidf_vectorizer.pkl')
print("✅ TF-IDF vectorizer saved as tfidf_vectorizer.pkl")
