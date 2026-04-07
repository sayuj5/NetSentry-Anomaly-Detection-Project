import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, Input
from tensorflow.keras.callbacks import EarlyStopping
import seaborn as sns
from sklearn.model_selection import RandomizedSearchCV

# --- Model Training Functions ---

def train_supervised_rf(X_train, y_train, random_state=42, optimize_hyperparameters=True):
    """Trains a Random Forest Classifier, optionally with Hyperparameter Optimization."""
    print(f"[Supervised Training] Starting Random Forest training (Hyperparameter Optimization: {optimize_hyperparameters})...")
    
    if optimize_hyperparameters:
        print("[Hyperparameter Optimization] Performing Randomized Search for Random Forest...")
        param_dist = {
            'n_estimators': [50, 100, 200],
            'max_depth': [10, 20, None],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4],
            'bootstrap': [True, False]
        }
        
        base_rf = RandomForestClassifier(random_state=random_state, n_jobs=-1, class_weight='balanced')
        
        rf_random = RandomizedSearchCV(estimator=base_rf, param_distributions=param_dist, 
                                       n_iter=5, cv=3, verbose=2, random_state=random_state, n_jobs=-1)
        
        rf_random.fit(X_train, y_train)
        
        print(f"[Hyperparameter Optimization] Best Parameters found: {rf_random.best_params_}")
        rf_model = rf_random.best_estimator_
    else:
        # Using a simple setup for the Random Forest
        rf_model = RandomForestClassifier(n_estimators=100, random_state=random_state, n_jobs=-1, class_weight='balanced')
        rf_model.fit(X_train, y_train)

    print("[Supervised Training] Random Forest training complete.")
    return rf_model
def train_deep_learning_mlp(X_train, y_train, epochs, batch_size, random_state=42):
    """Trains a Keras Multi-Layer Perceptron (MLP) model."""
    
    # Model Architecture
    input_dim = X_train.shape[1]
    mlp_model = Sequential([
        Input(shape=(input_dim,)),
        Dense(64, activation='relu'),
        Dropout(0.2),
        Dense(32, activation='relu'),
        Dense(1, activation='sigmoid') # Binary classification output
    ])

    # Compile the model
    mlp_model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

    # Implement Hyperparameter Optimization/Regularization through Early Stopping
    early_stop = EarlyStopping(monitor='val_loss', patience=3, restore_best_weights=True, verbose=1)

    print("[Supervised Training] Keras MLP training starting with Early Stopping...")
    # Train the model with validation split for early stopping
    mlp_model.fit(X_train, y_train, epochs=epochs, batch_size=batch_size, 
                  validation_split=0.2, callbacks=[early_stop], verbose=1)
    
    print("[Supervised Training] Keras MLP training complete.")
    return mlp_model

def train_unsupervised_iforest(X_train, contamination, random_state=42):
    """Trains an Unsupervised Isolation Forest model."""
    # Isolation Forest is fitted only on the features (X_train)
    iforest_model = IsolationForest(
        contamination=contamination, 
        random_state=random_state, 
        n_jobs=-1
    )
    # The fit method in Isolation Forest returns the model itself
    iforest_model.fit(X_train)
    print("[Unsupervised Training] Isolation Forest training complete.")
    return iforest_model

# --- Evaluation Function ---

def evaluate_model(model, X_test, y_test, model_name, is_unsupervised=False):
    """
    Evaluates the model and prints a classification report and confusion matrix.
    
    Includes robust prediction logic and explicit label passing to classification_report.
    """
    print(f"\n--- Evaluating {model_name} ---")

    # Define the labels for classification report and confusion matrix
    LABELS = [0, 1]
    TARGET_NAMES = ['Normal (0)', 'Anomaly (1)']

    if is_unsupervised:
        # For unsupervised models (Isolation Forest)
        y_pred = model.predict(X_test)
        # Convert IForest output: 1 (Normal) -> 0, -1 (Anomaly) -> 1
        y_pred_binary = np.where(y_pred == 1, 0, 1)
        y_prob = None # No standard probability/AUC calculation for IForest

    else:
        # For supervised models (Random Forest, MLP)
        # Get raw predictions (labels or probabilities depending on model)
        y_pred_raw = model.predict(X_test)
        
        y_prob = None
        y_pred_binary = None

        # If scikit-learn style classifier with predict_proba available
        if hasattr(model, 'predict_proba'):
            probabilities = model.predict_proba(X_test)
            # Try to select the probability column corresponding to the positive class (1)
            if hasattr(model, 'classes_'):
                try:
                    pos_idx = list(model.classes_).index(1)
                    y_prob = probabilities[:, pos_idx]
                except ValueError:
                    # fallback: use second column if present, otherwise first
                    y_prob = probabilities[:, 1] if probabilities.shape[1] > 1 else probabilities[:, 0]
            else:
                y_prob = probabilities[:, 1] if probabilities.shape[1] > 1 else probabilities[:, 0]

            # Predicted labels
            y_pred_binary = model.predict(X_test)

        else:
            # Try to detect Keras models explicitly rather than relying on a name string
            try:
                from tensorflow.keras.models import Model as KerasModel
                if isinstance(model, KerasModel):
                    y_prob = y_pred_raw.flatten()
                    y_pred_binary = (y_prob > 0.5).astype(int)
                else:
                    # Fallback for other models that only implement predict()
                    y_pred_binary = y_pred_raw
            except Exception:
                y_pred_binary = y_pred_raw

    # Print Classification Report
    print("Classification Report:")
    # FIX: Explicitly pass 'labels' to classification_report to force it to show both classes (0 and 1), 
    # even if one class is missing in y_test or y_pred_binary.
    print(classification_report(y_test, y_pred_binary, 
                                target_names=TARGET_NAMES, 
                                labels=LABELS))

    # Print Confusion Matrix
    cm = confusion_matrix(y_test, y_pred_binary, labels=LABELS) # Also explicitly set labels here
    plt.figure(figsize=(4, 3))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=TARGET_NAMES, 
                yticklabels=TARGET_NAMES)
    plt.title(f'Confusion Matrix - {model_name}')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    
    # Calculate and print AUC if probabilities are available
    if not is_unsupervised and y_prob is not None:
        try:
            # Check if both classes are present in the test labels for AUC calculation
            if len(np.unique(y_test)) > 1:
                auc = roc_auc_score(y_test, y_prob)
                print(f"AUC Score: {auc:.4f}")
            else:
                print("Warning: Only one class present in y_test. Skipping AUC calculation.")
        except ValueError as e:
            print(f"Warning: Could not calculate AUC score. {e}")


def plot_feature_importance(model, feature_names, n_top=15):
    """
    Plots the feature importance from a tree-based model (e.g., Random Forest).
    """
    if hasattr(model, 'feature_importances_'):
        importances = model.feature_importances_
        # Create a pandas Series for easy sorting and naming
        feature_importance_series = pd.Series(importances, index=feature_names)
        
        # Sort values and select top N features
        top_features = feature_importance_series.sort_values(ascending=False).head(n_top)
        
        # Plotting
        plt.figure(figsize=(10, 6))
        # Use matplotlib horizontal bar chart to avoid seaborn palette/hue deprecation warnings
        colors = plt.cm.viridis(np.linspace(0, 1, len(top_features)))
        plt.barh(top_features.index, top_features.values, color=colors)
        plt.title(f'Top {n_top} Feature Importances - Random Forest')
        plt.xlabel('Importance Score')
        plt.ylabel('Feature')
        plt.gca().invert_yaxis()
        plt.tight_layout()
    else:
        print("Feature importance plot skipped: Model does not have 'feature_importances_'.")
