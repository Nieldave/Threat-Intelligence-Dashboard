import pandas as pd
import pickle
import os
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from main import Threat, Base
from pydantic import BaseModel
from collections import Counter
import re
import warnings
warnings.filterwarnings('ignore')

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

class ThreatAnalysisRequest(BaseModel):
    description: str

class ThreatAnalysisResponse(BaseModel):
    predicted_category: str
    confidence: float
    all_predictions: dict

class OptimizedThreatClassifier:
    def __init__(self):
        self.model = None
        self.label_encoder = LabelEncoder()
        self.model_path = "threat_classifier.pkl"
        
    def preprocess_text(self, text):
        """Enhanced text preprocessing with better normalization."""
        if not isinstance(text, str):
            return ""
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove extra whitespace and normalize
        text = re.sub(r'\s+', ' ', text).strip()
        
        # Keep alphanumeric, spaces, and important punctuation
        text = re.sub(r'[^a-zA-Z0-9\s@._-]', ' ', text)
        
        # Remove extra spaces again
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text
    
    def create_advanced_features(self, texts):
        """Create comprehensive threat-specific features."""
        features = []
        
        # Enhanced threat pattern dictionaries with more specific keywords
        threat_patterns = {
            'ddos_keywords': [
                'ddos', 'denial', 'service', 'attack', 'flood', 'botnet', 'amplification', 
                'overload', 'traffic', 'bandwidth', 'syn', 'udp', 'tcp', 'volumetric',
                'protocol', 'network', 'distributed', 'zombie', 'reflection', 'slowloris'
            ],
            'malware_keywords': [
                'malware', 'virus', 'trojan', 'executable', 'infected', 'payload', 
                'backdoor', 'suspicious', 'file', 'download', 'worm', 'rootkit',
                'keylogger', 'spyware', 'adware', 'bot', 'dropper', 'loader'
            ],
            'phishing_keywords': [
                'phishing', 'email', 'link', 'credential', 'fake', 'spoof', 'deceptive', 
                'login', 'password', 'click', 'bait', 'hook', 'social', 'engineering',
                'impersonation', 'verify', 'urgent', 'account', 'suspended'
            ],
            'ransomware_keywords': [
                'ransomware', 'encrypt', 'bitcoin', 'payment', 'locked', 'decrypt', 
                'crypto', 'ransom', 'files', 'restore', 'key', 'unlock', 'money',
                'cryptocurrency', 'wallet', 'extension', 'locked', 'recovery'
            ]
        }
        
        for text in texts:
            text_lower = text.lower()
            feature_vector = []
            
            # Basic text statistics
            words = text.split()
            feature_vector.extend([
                len(text),  # Character count
                len(words),  # Word count
                len(set(words)),  # Unique word count
                len(words) / len(set(words)) if len(set(words)) > 0 else 0,  # Repetition ratio
                sum(len(word) for word in words) / len(words) if len(words) > 0 else 0,  # Average word length
            ])
            
            # Special character counts
            feature_vector.extend([
                text.count('@'),  # Email indicators
                text.count('http'),  # URL indicators
                text.count('.'),  # Dot count
                text.count('/'),  # Slash count
                text.count('-'),  # Dash count
                text.count('_'),  # Underscore count
                sum(c.isdigit() for c in text),  # Digit count
                sum(c.isupper() for c in text if c.isalpha()) / len([c for c in text if c.isalpha()]) if any(c.isalpha() for c in text) else 0,  # Uppercase ratio
            ])
            
            # Threat-specific keyword counts and ratios
            for threat_type, keywords in threat_patterns.items():
                count = sum(1 for keyword in keywords if keyword in text_lower)
                # Normalized by text length
                normalized_count = count / len(words) if len(words) > 0 else 0
                feature_vector.extend([count, normalized_count])
            
            # Network and technical indicators
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            domain_pattern = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
            
            feature_vector.extend([
                len(re.findall(ip_pattern, text)),  # IP addresses
                len(re.findall(domain_pattern, text)),  # Domain names
                text.count('port'),  # Port references
                text.count('protocol'),  # Protocol references
                text.count('server'),  # Server references
                text.count('client'),  # Client references
            ])
            
            # Linguistic features
            feature_vector.extend([
                text.count(' '),  # Space count
                text.count('!'),  # Exclamation marks
                text.count('?'),  # Question marks
                len([word for word in words if word.isdigit()]),  # Number words
                len([word for word in words if len(word) > 10]),  # Long words
            ])
            
            features.append(feature_vector)
        
        return np.array(features)
    
    def create_enhanced_vectorizer(self):
        """Create a more sophisticated TF-IDF vectorizer."""
        return TfidfVectorizer(
            max_features=5000,  # Reduced but sufficient
            stop_words='english',
            ngram_range=(1, 3),  # Include trigrams for better context
            min_df=3,  # Minimum document frequency
            max_df=0.7,  # Maximum document frequency
            lowercase=True,
            strip_accents='unicode',
            sublinear_tf=True,  # Apply sublinear scaling
            norm='l2',
            use_idf=True,
            smooth_idf=True,
            token_pattern=r'\b\w+\b'  # Better token pattern
        )
    
    def create_best_model(self):
        """Create the best performing model based on the data characteristics."""
        # For this type of text classification, Random Forest often works well
        # with proper hyperparameters
        return RandomForestClassifier(
            n_estimators=200,
            max_depth=None,  # Allow deep trees
            min_samples_split=2,
            min_samples_leaf=1,
            max_features='sqrt',
            bootstrap=True,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        )
    
    def create_ensemble_model(self):
        """Create an optimized ensemble model."""
        classifiers = [
            ('rf', RandomForestClassifier(
                n_estimators=150,
                max_depth=None,
                min_samples_split=2,
                min_samples_leaf=1,
                max_features='sqrt',
                class_weight='balanced',
                random_state=42,
                n_jobs=-1
            )),
            ('lr', LogisticRegression(
                random_state=42,
                max_iter=2000,
                class_weight='balanced',
                C=1.0,
                solver='liblinear'
            )),
            ('svm', SVC(
                kernel='rbf',
                class_weight='balanced',
                probability=True,
                random_state=42,
                C=1.0,
                gamma='scale'
            ))
        ]
        
        if XGBOOST_AVAILABLE:
            classifiers.append(('xgb', xgb.XGBClassifier(
                n_estimators=150,
                max_depth=6,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42,
                eval_metric='mlogloss',
                objective='multi:softprob'
            )))
        
        return VotingClassifier(
            estimators=classifiers,
            voting='soft',
            n_jobs=-1
        )
    
    def train_model(self, model_type='best'):
        """Train the optimized threat classification model."""
        # Load data
        DATABASE_URL = "sqlite:///./threats.db"
        engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        
        db = SessionLocal()
        threats = db.query(Threat).all()
        db.close()
        
        if len(threats) == 0:
            raise ValueError("No threat data found in database.")
        
        # Prepare data
        descriptions = [self.preprocess_text(threat.description) for threat in threats]
        categories = [threat.category for threat in threats]
        
        print(f"Training {model_type} model with {len(descriptions)} samples...")
        
        # Remove empty descriptions
        valid_indices = [i for i, desc in enumerate(descriptions) if desc.strip()]
        descriptions = [descriptions[i] for i in valid_indices]
        categories = [categories[i] for i in valid_indices]
        
        # Analyze distribution
        class_counts = Counter(categories)
        print("Class distribution:")
        for category, count in class_counts.items():
            print(f"  {category}: {count} samples ({count/len(categories)*100:.1f}%)")
        
        # Create TF-IDF features
        vectorizer = self.create_enhanced_vectorizer()
        text_features = vectorizer.fit_transform(descriptions)
        
        # Create custom features
        custom_features = self.create_advanced_features(descriptions)
        
        # Scale custom features
        scaler = StandardScaler()
        custom_features_scaled = scaler.fit_transform(custom_features)
        
        # Combine features
        from scipy.sparse import hstack, csr_matrix
        X = hstack([text_features, csr_matrix(custom_features_scaled)])
        
        # Encode labels
        y = self.label_encoder.fit_transform(categories)
        
        # Split data with stratification
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"Training set: {X_train.shape[0]} samples with {X_train.shape[1]} features")
        print(f"Test set: {X_test.shape[0]} samples")
        
        # Choose and train model
        if model_type == 'best':
            classifier = self.create_best_model()
        elif model_type == 'ensemble':
            classifier = self.create_ensemble_model()
        elif model_type == 'xgboost' and XGBOOST_AVAILABLE:
            classifier = xgb.XGBClassifier(
                n_estimators=200,
                max_depth=8,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42,
                eval_metric='mlogloss',
                objective='multi:softprob'
            )
        else:
            # Default to Random Forest
            classifier = self.create_best_model()
        
        # Train model
        print("Training model...")
        classifier.fit(X_train, y_train)
        
        # Store model components
        self.model = {
            'classifier': classifier,
            'vectorizer': vectorizer,
            'scaler': scaler,
            'label_encoder': self.label_encoder,
            'model_type': model_type
        }
        
        # Evaluate on test set
        y_pred = classifier.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"\nModel training completed!")
        print(f"Test Accuracy: {accuracy:.4f}")
        
        # Convert back to original labels for report
        y_test_labels = self.label_encoder.inverse_transform(y_test)
        y_pred_labels = self.label_encoder.inverse_transform(y_pred)
        
        print("\nDetailed Classification Report:")
        print(classification_report(y_test_labels, y_pred_labels, zero_division=1))
        
        # Confusion Matrix
        cm = confusion_matrix(y_test_labels, y_pred_labels)
        print("\nConfusion Matrix:")
        print(cm)
        
        # Cross-validation on training data
        print("\nPerforming cross-validation...")
        cv_scores = cross_val_score(classifier, X_train, y_train, cv=5, scoring='accuracy')
        print(f"CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
        
        # Feature importance (if available)
        if hasattr(classifier, 'feature_importances_'):
            print(f"\nTop 10 most important features:")
            feature_names = vectorizer.get_feature_names_out().tolist() + [f'custom_feature_{i}' for i in range(custom_features.shape[1])]
            importances = classifier.feature_importances_
            top_features = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)[:10]
            for feature, importance in top_features:
                print(f"  {feature}: {importance:.4f}")
        
        self.save_model()
        return accuracy
    
    def save_model(self):
        """Save the trained model."""
        if self.model is None:
            raise ValueError("No model to save.")
        
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)
        
        print(f"Model saved to {self.model_path}")
    
    def load_model(self):
        """Load the trained model."""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Model file {self.model_path} not found.")
        
        with open(self.model_path, 'rb') as f:
            self.model = pickle.load(f)
        
        self.label_encoder = self.model['label_encoder']
        print(f"Model loaded from {self.model_path}")
    
    def predict(self, description: str):
        """Predict threat category with enhanced preprocessing."""
        if self.model is None:
            self.load_model()
        
        # Preprocess input
        processed_text = self.preprocess_text(description)
        
        if not processed_text.strip():
            return {
                "predicted_category": "Unknown",
                "confidence": 0.0,
                "all_predictions": {}
            }
        
        # Create TF-IDF features
        text_features = self.model['vectorizer'].transform([processed_text])
        
        # Create custom features
        custom_features = self.create_advanced_features([processed_text])
        custom_features_scaled = self.model['scaler'].transform(custom_features)
        
        # Combine features
        from scipy.sparse import hstack, csr_matrix
        X = hstack([text_features, csr_matrix(custom_features_scaled)])
        
        # Predict
        prediction = self.model['classifier'].predict(X)[0]
        probabilities = self.model['classifier'].predict_proba(X)[0]
        
        # Convert back to original labels
        predicted_label = self.label_encoder.inverse_transform([prediction])[0]
        all_labels = self.label_encoder.classes_
        all_predictions = dict(zip(all_labels, probabilities))
        
        return {
            "predicted_category": predicted_label,
            "confidence": float(max(probabilities)),
            "all_predictions": {k: float(v) for k, v in all_predictions.items()}
        }

# Global classifier instance
classifier = OptimizedThreatClassifier()

def add_ml_endpoints(app):
    """Add ML endpoints to FastAPI."""
    
    @app.post("/api/analyze-threat", response_model=ThreatAnalysisResponse)
    async def analyze_threat(request: ThreatAnalysisRequest):
        try:
            result = classifier.predict(request.description)
            return ThreatAnalysisResponse(**result)
        except Exception as e:
            from fastapi import HTTPException
            raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    
    @app.post("/api/train-model")
    async def train_model():
        try:
            accuracy = classifier.train_model('best')
            return {
                "status": "success",
                "message": "Model trained successfully",
                "accuracy": accuracy
            }
        except Exception as e:
            from fastapi import HTTPException
            raise HTTPException(status_code=500, detail=f"Training failed: {str(e)}")

def main():
    """Command-line interface."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python optimized_model.py <command>")
        print("Commands:")
        print("  best       - Train best performing model (recommended)")
        print("  ensemble   - Train ensemble model")
        print("  xgboost    - Train XGBoost model")
        print("  predict    - Interactive prediction")
        return
    
    command = sys.argv[1].lower()
    
    if command in ['best', 'ensemble', 'xgboost']:
        try:
            accuracy = classifier.train_model(command)
            print(f"\n{'='*50}")
            print(f"Training completed! Final Accuracy: {accuracy:.4f}")
            if accuracy > 0.9:
                print("🎉 Excellent! Achieved >90% accuracy!")
            elif accuracy > 0.8:
                print("👍 Good performance! Above 80% accuracy.")
            else:
                print("⚠️  Consider reviewing the data quality or trying different preprocessing.")
            print(f"{'='*50}")
        except Exception as e:
            print(f"Training failed: {e}")
    
    elif command == "predict":
        try:
            classifier.load_model()
            print("Prediction mode. Enter 'quit' to exit.")
            
            while True:
                description = input("\nEnter threat description: ")
                if description.lower() == 'quit':
                    break
                
                result = classifier.predict(description)
                print(f"\nPredicted Category: {result['predicted_category']}")
                print(f"Confidence: {result['confidence']:.4f}")
                
                print("\nAll predictions:")
                for cat, prob in sorted(result['all_predictions'].items(), 
                                      key=lambda x: x[1], reverse=True):
                    print(f"  {cat}: {prob:.4f}")
        
        except Exception as e:
            print(f"Prediction failed: {e}")
    
    else:
        print(f"Unknown command: {command}")

if __name__ == "__main__":
    main()