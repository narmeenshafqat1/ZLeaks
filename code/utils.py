import pandas as pd

def checker(df: pd.DataFrame) -> bool:

    zr_alike = df[  (df['Source'].str.contains('0x00000001')) | (df['Destination'].str.contains('0x00000001')) |
                    (df['Source'].str.contains('0x00000002')) | (df['Destination'].str.contains('0x00000002')) |
                    (df['Source'].str.contains('0x00000003')) | (df['Destination'].str.contains('0x00000003')) |
                    (df['Source'].str.contains('0x00000004')) | (df['Destination'].str.contains('0x00000004')) |
                    (df['Source'].str.contains('0x00000005')) | (df['Destination'].str.contains('0x00000005'))]

    return True if len(zr_alike) else False
    

