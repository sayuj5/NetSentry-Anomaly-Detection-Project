import pandas as pd
from sklearn.model_selection import train_test_split
import numpy as np
import os

def load_data(data_path, categorical_cols, target_col):
    """
    Loads the KDD dataset from the given path, assigning column names.
    
    The KDD dataset typically has 41 features plus a label column (index 41) 
    and potentially a score column (index 42). We only load the 41 features and the label.
    """
    print(f"Loading data from calculated path: {data_path}")

    # Define the 41 feature names
    feature_names = [f'feature_{i}' for i in range(1, 42)]
    
    # Define the full column list (41 features + 1 label). 
    col_names = feature_names + [target_col]

    # Check for file existence robustly
    resolved_path = os.path.normpath(data_path)
    print(f"Checking data existence at resolved path: {resolved_path}")

    if not os.path.exists(resolved_path):
        print(f"\n❌ ERROR: File NOT found at the fully resolved path: {resolved_path}")
        raise FileNotFoundError(f"Dataset file not found at {data_path}. Please check the 'data/' directory and the file name.")

    # Load the data and handle potential extra columns by only using the first 42 columns
    try:
        # Read the file, forcing object (string) dtype for the target column initially
        df = pd.read_csv(resolved_path, header=None, usecols=range(42))
        
        # Rename the columns using our defined names
        df.columns = col_names

        return df
    except Exception as e:
        print(f"\n❌ ERROR: Could not read CSV file or assign columns correctly: {e}")
        raise

def preprocess_data(df, categorical_cols, target_col, normal_label):
    """
    Preprocesses the data by:
    1. Cleaning the target column labels.
    2. Converting categorical features using one-hot encoding.
    3. Binarizing the target column (Normal=0, Anomaly=1).

    Returns: X_processed (numpy array), y_binary (numpy array), processed_feature_names (list)
    """
    
    # CRITICAL FIX: Clean the Target Label column
    # KDD labels often contain trailing periods/spaces (e.g., 'normal.')
    # Use rstrip to remove only trailing periods rather than removing ALL dots from the label text.
    df[target_col] = df[target_col].astype(str).str.strip().str.rstrip('.')
    
    # 1. Separate features and target
    df_features = df.drop(columns=[target_col])
    
    # 2. One-Hot Encoding for Categorical Columns
    existing_categorical_cols = [col for col in categorical_cols if col in df_features.columns]
    
    # Apply One-Hot Encoding
    X_processed_df = pd.get_dummies(df_features, columns=existing_categorical_cols, prefix=existing_categorical_cols)
    
    # Ensure all columns are numerical after encoding
    X_processed_df = X_processed_df.select_dtypes(include=np.number)
    
    # 3. Target Binarization
    # Check what unique labels exist before binarization (for debugging purposes)
    unique_labels = df[target_col].unique()
    print(f"Unique labels found after cleaning: {unique_labels}")
    
    # FIX: Ensure 1 = Anomaly and 0 = Normal
    y_binary = (df[target_col] != normal_label).astype(int) # Anomaly is True (1), Normal is False (0)
    
    # 4. Get the list of processed feature names
    processed_feature_names = X_processed_df.columns.tolist()

    # Convert features to a numpy array for model compatibility
    X_processed = X_processed_df.values
    
    # Check final label balance before splitting
    normal_count = len(y_binary[y_binary == 0])
    anomaly_count = len(y_binary[y_binary == 1])
    print(f"Total Labels: Normal (0)={normal_count}, Anomaly (1)={anomaly_count}")

    # Return 3 values: X_processed (features), y_binary (labels), processed_feature_names (list of strings)
    return X_processed, y_binary.values, processed_feature_names

def split_data(X, y, test_size=0.2, random_state=42):
    """
    Splits the data into training and testing sets, stratifying on y.
    """
    # Use stratify=y to ensure the train/test split has the same proportion of anomalies
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
    except ValueError as e:
        # This can happen when one class is missing or too small for stratification
        print(f"Warning: Stratified split failed ({e}). Falling back to non-stratified split.")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=None
        )

    print(f"Data split: Train size={len(X_train)}, Test size={len(X_test)}")
    # Log the number of samples per class in the test set for verification
    test_normal = np.sum(y_test == 0)
    test_anomaly = np.sum(y_test == 1)
    print(f"Test set class balance: Normal (0): {test_normal}, Anomaly (1): {test_anomaly}")
    
    return X_train, X_test, y_train, y_test