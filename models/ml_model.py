import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os

class WebGuardMLModel:
    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=100, 
            random_state=42,
            class_weight='balanced'  # ✅ This handles imbalanced data
        )
        self.feature_columns = [
            'url_length', 'num_dots', 'num_hyphens', 'domain_length',
            'subdomain_count', 'has_https', 'has_ip', 'suspicious_keywords'
        ]
        self.is_trained = False
        
    def create_synthetic_training_data(self):
        """Create BALANCED synthetic training data"""
        print("📊 Creating balanced synthetic training data...")
        np.random.seed(42)
        
        # ✅ Create equal samples for each class (balanced dataset)
        samples_per_class = 400  # 400 each = 1200 total
        
        # Generate SAFE websites (class 0)
        safe_data = {
            'url_length': np.random.randint(10, 50, samples_per_class),  # Shorter URLs
            'num_dots': np.random.randint(1, 3, samples_per_class),      # Fewer dots
            'num_hyphens': np.random.randint(0, 1, samples_per_class),   # Fewer hyphens
            'domain_length': np.random.randint(5, 20, samples_per_class), # Normal domains
            'subdomain_count': np.random.randint(0, 2, samples_per_class), # Few subdomains
            'has_https': np.random.choice([1], samples_per_class),        # Always HTTPS
            'has_ip': np.random.choice([0], samples_per_class),           # Never IP
            'suspicious_keywords': np.random.randint(0, 1, samples_per_class), # Few keywords
            'label': np.full(samples_per_class, 0)  # SAFE
        }
        
        # Generate SUSPICIOUS websites (class 1)
        suspicious_data = {
            'url_length': np.random.randint(30, 100, samples_per_class),  # Medium URLs
            'num_dots': np.random.randint(2, 6, samples_per_class),       # More dots
            'num_hyphens': np.random.randint(1, 4, samples_per_class),    # More hyphens
            'domain_length': np.random.randint(15, 40, samples_per_class), # Longer domains
            'subdomain_count': np.random.randint(1, 4, samples_per_class), # More subdomains
            'has_https': np.random.choice([0, 1], samples_per_class, p=[0.6, 0.4]), # Often no HTTPS
            'has_ip': np.random.choice([0, 1], samples_per_class, p=[0.8, 0.2]),    # Sometimes IP
            'suspicious_keywords': np.random.randint(1, 3, samples_per_class), # Some keywords
            'label': np.full(samples_per_class, 1)  # SUSPICIOUS
        }
        
        # Generate HIGH RISK websites (class 2)
        risky_data = {
            'url_length': np.random.randint(80, 200, samples_per_class),  # Very long URLs
            'num_dots': np.random.randint(4, 10, samples_per_class),      # Many dots
            'num_hyphens': np.random.randint(2, 8, samples_per_class),    # Many hyphens
            'domain_length': np.random.randint(25, 60, samples_per_class), # Very long domains
            'subdomain_count': np.random.randint(3, 8, samples_per_class), # Many subdomains
            'has_https': np.random.choice([0, 1], samples_per_class, p=[0.8, 0.2]), # Mostly no HTTPS
            'has_ip': np.random.choice([0, 1], samples_per_class, p=[0.5, 0.5]),    # Often IP
            'suspicious_keywords': np.random.randint(2, 6, samples_per_class), # Many keywords
            'label': np.full(samples_per_class, 2)  # HIGH RISK
        }
        
        # ✅ Combine all data
        all_data = {}
        for key in safe_data.keys():
            all_data[key] = np.concatenate([
                safe_data[key], 
                suspicious_data[key], 
                risky_data[key]
            ])
        
        df = pd.DataFrame(all_data)
        
        # Shuffle the data
        df = df.sample(frac=1).reset_index(drop=True)
        
        print(f"📈 Created balanced dataset:")
        print(f"   Safe: {sum(df['label'] == 0)} samples")
        print(f"   Suspicious: {sum(df['label'] == 1)} samples") 
        print(f"   High Risk: {sum(df['label'] == 2)} samples")
        print(f"   Total: {len(df)} samples")
        
        return df
    
    def train_model(self):
        """Train the machine learning model with balanced data"""
        print("🎯 Starting balanced model training...")
        
        # Create balanced synthetic training data
        df = self.create_synthetic_training_data()
        
        X = df[self.feature_columns]
        y = df['label']
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train model
        print("🔄 Training Random Forest with balanced classes...")
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"📊 Model training completed!")
        print(f"✅ Accuracy: {accuracy:.3f}")
        
        # Print detailed classification report
        print("📋 Classification Report:")
        print(classification_report(y_test, y_pred, 
                                  target_names=['Safe', 'Suspicious', 'High Risk']))
        
        # Save model
        model_dir = 'models'
        if not os.path.exists(model_dir):
            os.makedirs(model_dir)
            
        model_path = os.path.join(model_dir, 'webguard_model.pkl')
        joblib.dump(self.model, model_path)
        print(f"💾 Model saved to: {model_path}")
        
        self.is_trained = True
        return accuracy
    
    def load_model(self):
        """Load pre-trained model"""
        model_path = os.path.join('models', 'webguard_model.pkl')
        if os.path.exists(model_path):
            try:
                self.model = joblib.load(model_path)
                self.is_trained = True
                print(f"📁 Model loaded from: {model_path}")
                return True
            except Exception as e:
                print(f"❌ Error loading model: {e}")
                return False
        return False
    
    def predict_risk(self, features):
        """Predict risk level for given features"""
        if not self.is_trained:
            print("⚠️ Model not trained. Training now...")
            if not self.load_model():
                self.train_model()
        
        # Prepare features for prediction
        feature_array = np.array([[features[col] for col in self.feature_columns]])
        
        # Get prediction and probability
        prediction = self.model.predict(feature_array)[0]
        probabilities = self.model.predict_proba(feature_array)[0]
        
        risk_labels = ['Safe', 'Suspicious', 'High Risk']
        confidence = max(probabilities) * 100
        
        # ✅ Add debug information
        print(f"🔍 Debug - Features: {[features[col] for col in self.feature_columns]}")
        print(f"🎯 Debug - Raw prediction: {prediction}")
        print(f"📊 Debug - Probabilities: Safe={probabilities[0]:.3f}, Suspicious={probabilities[1]:.3f}, High Risk={probabilities[2]:.3f}")
        
        return {
            'risk_level': risk_labels[prediction],
            'risk_score': prediction,
            'confidence': confidence,
            'probabilities': {
                'safe': probabilities[0] * 100,
                'suspicious': probabilities[1] * 100,
                'high_risk': probabilities[2] * 100
            }
        }
