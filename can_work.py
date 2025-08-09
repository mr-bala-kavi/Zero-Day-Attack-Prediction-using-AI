import pandas as pd
import numpy as np

# Step 1: Load and clean
df = pd.read_csv("cve_data.csv", engine='python', quotechar='"', on_bad_lines='skip')
df.replace('?', np.nan, inplace=True)

# Step 2: Show row count
print("\n🔢 Total Rows:", len(df))

# Step 3: Rows with usable 'Severity'
valid_severity_rows = df['Severity'].notnull().sum()
print("✅ Rows with Severity:", valid_severity_rows)

# Step 4: Show unique severity values
print("\n🎯 Unique Severity Levels:", df['Severity'].dropna().unique())
