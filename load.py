import pandas as pd
import numpy as np

df = pd.read_csv("cve_data.csv", engine='python', quotechar='"', on_bad_lines='skip')

df.replace('?', np.nan, inplace=True)

print("✅ Data loaded successfully.")
print("🔍 Columns:", df.columns)
print("\n📄 Sample rows:\n", df.head())
