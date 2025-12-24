"""
Machine Learning Model for Phishing Detection
"""

import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import os
import json

class PhishingDetector:
    """ML model for phishing detection"""
    
    def __init__(self, model_path='ml_model/phishing_model.pkl'):
        self.model_path = model_path
        self.scaler_path = 'ml_model/scaler.pkl'
        self.feature_names_path = 'ml_model/feature_names.json'
        self.model = None
        self.scaler = None
        self.feature_names = []
        
        self.load_or_train_model()
    
    def load_or_train_model(self):
        """Load existing model or train new one"""
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            try:
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                with open(self.scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                with open(self.feature_names_path, 'r') as f:
                    self.feature_names = json.load(f)
                print("Model loaded successfully")
                return
            except Exception as e:
                print(f"Error loading model: {e}")
        
        # Train new model if loading fails
        self.train_model()
    
    def generate_training_data(self):
        """Generate synthetic training data for demonstration"""
        # In a real project, you would use a real dataset like:
        # - Phishing URLs from PhishTank
        # - Legitimate URLs from Common Crawl
        
        np.random.seed(42)
        n_samples = 1000
        
        # Feature names (matching extractor)
        feature_names = [
            'url_length', 'domain_length', 'num_dots', 'num_hyphens',
            'num_underscores', 'num_slashes', 'num_question_marks',
            'num_equals', 'num_ampersands', 'num_percent',
            'is_ip_address', 'has_https', 'port_present', 'has_at_symbol',
            'has_redirect', 'suspicious_tld', 'num_params', 'param_length',
            'path_depth', 'file_extension', 'has_login_form',
            'has_suspicious_keywords', 'domain_age', 'has_whois'
        ]
        
        # Generate synthetic features
        X = np.zeros((n_samples, len(feature_names)))
        
        # Legitimate URLs (class 0)
        for i in range(n_samples // 2):
            # Shorter URLs
            X[i, 0] = np.random.randint(20, 60)  # url_length
            X[i, 1] = np.random.randint(5, 15)   # domain_length
            X[i, 2] = np.random.randint(1, 3)    # num_dots
            X[i, 3] = np.random.randint(0, 2)    # num_hyphens
            X[i, 4] = 0                          # num_underscores
            X[i, 5] = np.random.randint(1, 3)    # num_slashes
            X[i, 6] = np.random.randint(0, 2)    # num_question_marks
            X[i, 11] = 1                         # has_https
            X[i, 15] = 0                         # suspicious_tld
        
        # Phishing URLs (class 1)
        for i in range(n_samples // 2, n_samples):
            # Longer URLs with more special characters
            X[i, 0] = np.random.randint(60, 120)  # url_length
            X[i, 1] = np.random.randint(15, 30)   # domain_length
            X[i, 2] = np.random.randint(3, 6)     # num_dots
            X[i, 3] = np.random.randint(2, 5)     # num_hyphens
            X[i, 4] = np.random.randint(1, 3)     # num_underscores
            X[i, 5] = np.random.randint(3, 6)     # num_slashes
            X[i, 6] = np.random.randint(2, 5)     # num_question_marks
            X[i, 11] = np.random.choice([0, 1])   # has_https
            X[i, 15] = np.random.choice([0, 1], p=[0.7, 0.3])  # suspicious_tld
            X[i, 20] = 1                          # has_login_form
            X[i, 21] = np.random.uniform(0.5, 1)  # suspicious_keywords
        
        # Labels (0 = safe, 1 = phishing)
        y = np.concatenate([
            np.zeros(n_samples // 2),  # Legitimate
            np.ones(n_samples // 2)    # Phishing
        ])
        
        return X, y, feature_names
    
    def train_model(self):
        """Train the ML model"""
        print("Training new model...")
        
        # Generate training data
        X, y, feature_names = self.generate_training_data()
        self.feature_names = feature_names
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        # Scale features
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        
        # Train Random Forest
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            class_weight='balanced'
        )
        
        self.model.fit(X_train_scaled, y_train)
        
        # Test accuracy
        X_test_scaled = self.scaler.transform(X_test)
        accuracy = self.model.score(X_test_scaled, y_test)
        print(f"Model trained with accuracy: {accuracy:.2f}")
        
        # Save model and scaler
        os.makedirs('ml_model', exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)
        with open(self.scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
        with open(self.feature_names_path, 'w') as f:
            json.dump(feature_names, f)
        
        return accuracy
    
    def predict(self, features):
        """Predict if URL is phishing"""
        try:
            # Convert features to array in correct order
            feature_array = []
            for feature_name in self.feature_names:
                feature_array.append(features.get(feature_name, 0))
            
            feature_array = np.array(feature_array).reshape(1, -1)
            
            # Scale features
            scaled_features = self.scaler.transform(feature_array)
            
            # Predict
            prediction = self.model.predict(scaled_features)[0]
            probability = self.model.predict_proba(scaled_features)[0]
            
            confidence = probability[int(prediction)]
            
            # Get feature importance for explanation
            importances = self.model.feature_importances_
            top_features_idx = importances.argsort()[-3:][::-1]
            top_features = [
                (self.feature_names[i], importances[i]) 
                for i in top_features_idx
            ]
            
            # Generate explanation
            explanation = self.generate_explanation(
                features, prediction, confidence, top_features
            )
            
            return int(prediction), confidence, explanation
            
        except Exception as e:
            print(f"Prediction error: {e}")
            # Fallback to rule-based detection
            return self.rule_based_detection(features)
    
    def rule_based_detection(self, features):
        """Rule-based fallback detection"""
        score = 0
        
        # Scoring rules
        if features.get('url_length', 0) > 75:
            score += 1
        if features.get('num_dots', 0) > 3:
            score += 1
        if features.get('has_at_symbol', 0) == 1:
            score += 2
        if features.get('is_ip_address', 0) == 1:
            score += 2
        if features.get('suspicious_tld', 0) == 1:
            score += 1
        if features.get('has_login_form', 0) == 1:
            score += 1
        
        # Normalize score
        normalized_score = min(score / 8, 1)
        prediction = 1 if normalized_score > 0.5 else 0
        
        explanation = {
            'method': 'rule_based',
            'score': normalized_score,
            'rules_triggered': score,
            'message': 'Using rule-based detection (ML model unavailable)'
        }
        
        return prediction, normalized_score, explanation
    
    def generate_explanation(self, features, prediction, confidence, top_features):
        """Generate human-readable explanation"""
        risk_factors = []
        
        if features.get('url_length', 0) > 75:
            risk_factors.append("Long URL (common in phishing)")
        if features.get('num_dots', 0) > 3:
            risk_factors.append("Multiple dots in URL")
        if features.get('has_at_symbol', 0) == 1:
            risk_factors.append("Contains @ symbol (suspicious)")
        if features.get('is_ip_address', 0) == 1:
            risk_factors.append("Uses IP address instead of domain")
        if features.get('suspicious_tld', 0) == 1:
            risk_factors.append("Suspicious top-level domain")
        if features.get('has_login_form', 0) == 1:
            risk_factors.append("Contains login form elements")
        
        explanation = {
            'risk_level': 'High' if prediction == 1 else 'Low',
            'confidence': f"{confidence:.1%}",
            'risk_factors': risk_factors,
            'top_features': [
                {'name': name, 'importance': f"{imp:.1%}"}
                for name, imp in top_features
            ],
            'recommendation': (
                "Avoid this website" if prediction == 1 
                else "Website appears safe"
            )
        }
        
        return explanation