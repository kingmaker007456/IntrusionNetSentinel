import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

# --- Constants for Feature Management ---
NUMERICAL_FEATURES = ['duration', 'src_bytes', 'dst_bytes']
CATEGORICAL_FEATURES = ['protocol_type', 'service']
TARGET_COLUMN = 'is_attack'
MODEL_FILENAME = 'intrusionnet_sentinel_model.pkl'
SCALER_FILENAME = 'sentinel_scaler.pkl'
FEATURES_FILENAME = 'sentinel_features.pkl'

class SentinelModel:
    """Manages the training, saving, and preprocessing of the IntrusionNet Sentinel ML model."""
    
    def __init__(self, n_estimators=100, random_state=42):
        self.model = RandomForestClassifier(
            n_estimators=n_estimators, 
            random_state=random_state, 
            class_weight='balanced'
        )
        self.scaler = StandardScaler()
        self.expected_features = []

    def load_data(self, file_path):
        """Loads and prepares a synthetic or actual NIDS dataset."""
        print(f"Loading data from: {file_path}")
        # NOTE: Using synthetic data for demonstration. Replace with your actual data loading logic.
        data = {
            'duration': [0, 0, 10, 0, 50, 0, 0, 15, 0, 0] * 50,
            'protocol_type': ['tcp', 'udp', 'tcp', 'icmp', 'tcp', 'udp', 'tcp', 'tcp', 'icmp', 'tcp'] * 50,
            'src_bytes': [491, 146, 0, 20, 1000, 10, 50, 0, 30, 80] * 50,
            'dst_bytes': [0, 0, 0, 0, 5000, 0, 200, 0, 0, 100] * 50,
            'service': ['ftp', 'other', 'private', 'eco_i', 'http', 'other', 'http', 'private', 'eco_i', 'ftp'] * 50,
            'logged_in': [0, 0, 0, 0, 1, 0, 1, 0, 0, 1] * 50,
            'is_attack': [0, 0, 1, 0, 1, 0, 0, 1, 0, 0] * 50
        }
        df = pd.DataFrame(data)
        return df

    def preprocess(self, df):
        """Applies One-Hot Encoding and Scaling to features."""
        X = df.drop(TARGET_COLUMN, axis=1)
        y = df[TARGET_COLUMN]

        # One-Hot Encoding for Categorical Features
        X_encoded = pd.get_dummies(X, columns=CATEGORICAL_FEATURES, drop_first=True)
        
        # Capture all feature column names *after* encoding
        self.expected_features = X_encoded.columns.tolist()

        # Scale Numerical Features
        X_encoded[NUMERICAL_FEATURES] = self.scaler.fit_transform(X_encoded[NUMERICAL_FEATURES])
        
        return X_encoded, y

    def train_and_evaluate(self, X, y):
        """Trains the Random Forest model and prints evaluation metrics."""
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )

        print(f"Training on {len(X_train)} samples, testing on {len(X_test)} samples...")

        self.model.fit(X_train, y_train)

        # Evaluation
        y_pred = self.model.predict(X_test)
        print("\n### IntrusionNet Sentinel Model Evaluation ###")
        print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
        print("\nClassification Report:")
        # The labels are [0, 1] for ['Normal', 'Attack']
        print(classification_report(y_test, y_pred, target_names=['Normal', 'Attack']))
        
        # Displaying the confusion matrix visually can also be very helpful. 
        # 

    def save_assets(self):
        """Saves the trained model, scaler, and feature list to disk."""
        joblib.dump(self.model, MODEL_FILENAME)
        joblib.dump(self.scaler, SCALER_FILENAME)
        joblib.dump(self.expected_features, FEATURES_FILENAME)
        print(f"\n✅ Training assets saved: {MODEL_FILENAME}, {SCALER_FILENAME}, {FEATURES_FILENAME}")


if __name__ == '__main__':
    sentinel = SentinelModel()
    
    # 1. Load Data
    data_path = 'nids_training_data.csv' # Placeholder
    df_raw = sentinel.load_data(data_path)
    
    # 2. Preprocess Data
    X_processed, y_labels = sentinel.preprocess(df_raw)
    
    # 3. Train and Evaluate
    sentinel.train_and_evaluate(X_processed, y_labels)
    
    # 4. Save Assets for Deployment
    sentinel.save_assets()
