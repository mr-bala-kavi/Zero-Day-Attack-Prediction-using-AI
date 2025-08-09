import pandas as pd
import numpy as np

df = pd.read_csv("cve_data.csv", low_memory=False)
df.replace('?', np.nan, inplace=True)
