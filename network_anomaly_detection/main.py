import time
import os
import webbrowser
import joblib
import pickle
from data_handler import load_data, preprocess_data, split_data
from model_trainer import (
    train_supervised_rf, 
    train_deep_learning_mlp, 
    train_unsupervised_iforest,
    evaluate_model,
    plot_feature_importance 
)
from config import (
    DATA_PATH, CATEGORICAL_COLS, TARGET_COL, NORMAL_LABEL,
    MLP_EPOCHS, MLP_BATCH_SIZE, IFOR_CONTAMINATION
)
import matplotlib.pyplot as plt # NEW: Import for final blocking show

# Modified run_project to accept the absolute data path
def run_project(absolute_data_path=None):
    """
    Main function to run the anomaly detection project pipeline.
    Optionally accepts an absolute_data_path to override DATA_PATH from config.
    """
    start_time = time.time()
    
    print("--- Network Anomaly Detection Project Start ---")

    # Determine which data path to use
    data_file_path = absolute_data_path if absolute_data_path else DATA_PATH

    try:
        # --- 1. Data Loading ---
        # Pass the dynamically determined path to load_data
        df = load_data(data_file_path, CATEGORICAL_COLS, TARGET_COL)
        
        # --- 2. Data Preprocessing ---
        # Note: preprocess_data now returns feature_names
        X_processed, y_binary, feature_names = preprocess_data(df, CATEGORICAL_COLS, TARGET_COL, NORMAL_LABEL)
        
        # --- 3. Data Splitting ---
        X_train, X_test, y_train, y_test = split_data(X_processed, y_binary)
        
        # --- 4. Model Training and Evaluation ---

        # A. Supervised Random Forest
        rf_model = train_supervised_rf(X_train, y_train)
        evaluate_model(rf_model, X_test, y_test, "Random Forest", is_unsupervised=False)
        
        # Feature Importance Analysis for RF (prepares plot)
        plot_feature_importance(rf_model, feature_names, n_top=15)

        # B. Supervised Keras MLP
        print("\n--- Training Supervised Keras MLP ---")
        mlp_model = train_deep_learning_mlp(X_train, y_train, MLP_EPOCHS, MLP_BATCH_SIZE)
        evaluate_model(mlp_model, X_test, y_test, "Keras MLP", is_unsupervised=False)

        # C. Unsupervised Isolation Forest
        print("\n--- Training Unsupervised Isolation Forest ---")
        iforest_model = train_unsupervised_iforest(X_train, IFOR_CONTAMINATION)
        evaluate_model(iforest_model, X_test, y_test, "Isolation Forest", is_unsupervised=True)
        
        # Skip interactive plots for automation - save to files instead
        # plt.show(block=True) 
        
        # ===== SAVE TRAINED MODELS =====
        print("\n--- Saving Trained Models for Live Detection ---")
        
        # Save Random Forest model
        joblib.dump(rf_model, 'trained_rf_model.pkl')
        print("[OK] Random Forest model saved: trained_rf_model.pkl")
        
        # Save Keras MLP model
        mlp_model.save('trained_mlp_model.h5')
        print("[OK] Keras MLP model saved: trained_mlp_model.h5")
        
        # Save Isolation Forest model
        joblib.dump(iforest_model, 'trained_iforest_model.pkl')
        print("[OK] Isolation Forest model saved: trained_iforest_model.pkl")
        
        # Save preprocessor info
        with open('feature_names.pkl', 'wb') as f:
            pickle.dump(feature_names, f)
        print("[OK] Feature names saved: feature_names.pkl")
        
        # Launch Dashboard in browser
        print("\n--- Launching Interactive Dashboard ---")
        dashboard_path = os.path.join(os.path.dirname(__file__), 'dashboard', 'index.html')
        dashboard_url = 'file://' + os.path.abspath(dashboard_path)
        
        try:
            webbrowser.open(dashboard_url)
            print(f"[OK] Dashboard launched: {dashboard_url}")
        except Exception as e:
            print(f"⚠️  Could not auto-launch dashboard: {e}")
            print(f"   Open manually: {dashboard_path}")
        
    except Exception as e:
        print(f"\nProject encountered a fatal error: {e}")
        return

    end_time = time.time()
    duration = end_time - start_time

    print(f"\n{'='*50}")
    print(f"Project completed in {duration:.2f} seconds.")
    print("Check the output above for model performance summaries (Classification Reports & Confusion Matrices).")
    print(f"{'='*50}")

if __name__ == '__main__': 
    # Load configuration parameters and print the data path for verification
    from config import DATA_PATH
    
    # Calculate the absolute path to the data file by resolving relative path 
    # from the location of main.py
    main_dir = os.path.dirname(os.path.abspath(__file__))
    absolute_data_path = os.path.join(main_dir, '..', 'data', os.path.basename(DATA_PATH))
    
    print(f"Configuration loaded. Data path: {absolute_data_path}")
    
    # Run the project using the calculated absolute path
    run_project(absolute_data_path=absolute_data_path)