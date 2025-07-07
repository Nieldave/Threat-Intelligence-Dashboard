import pandas as pd
import pickle
import os
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import MultinomialNB
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.preprocessing import StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.feature_selection import SelectKBest, chi2
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from main import Threat, Base
from pydantic import BaseModel
from collections import Counter
import warnings
warnings.filterwarnings('ignore')

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    print("XGBoost not available. Install with: pip install xgboost")

class ThreatAnalysisRequest(BaseModel):
    description: str

class ThreatAnalysisResponse(BaseModel):
    predicted_category: str
    confidence: float
    all_predictions: dict

class AdvancedThreatClassifier:
    def __init__(self):
        self.model = None
        self.model_path = "advanced_threat_classifier.pkl"
        self.feature_engineering_enabled = True
        
    def create_advanced_features(self, texts):
        """
        Create advanced features from text data including length, keyword counts, and special patterns.
        """
        features = []
        
        # Define threat-specific keywords
        threat_keywords = {
            'ddos': ['ddos', 'denial', 'service', 'attack', 'flooding', 'amplification', 'botnet'],
            'malware': ['malware', 'virus', 'trojan', 'executable', 'infected', 'payload', 'backdoor'],
            'phishing': ['phishing', 'email', 'link', 'credential', 'fake', 'spoofing', 'deceptive'],
            'ransomware': ['ransomware', 'encrypt', 'bitcoin', 'payment', 'locked', 'decrypt', 'crypto']
        }
        
        for text in texts:
            text_lower = text.lower()
            feature_vector = []
            
            # Basic text statistics
            feature_vector.append(len(text))  # Text length
            feature_vector.append(len(text.split()))  # Word count
            feature_vector.append(text.count('.'))  # Sentence count approximation
            feature_vector.append(text.count('@'))  # Email indicators
            feature_vector.append(text.count('http'))  # URL indicators
            feature_vector.append(text.count('www'))  # Website indicators
            
            # Threat-specific keyword counts
            for threat_type, keywords in threat_keywords.items():
                keyword_count = sum(text_lower.count(keyword) for keyword in keywords)
                feature_vector.append(keyword_count)
            
            # Special character patterns
            feature_vector.append(sum(c.isdigit() for c in text))  # Number count
            feature_vector.append(sum(c.isupper() for c in text))  # Uppercase count
            feature_vector.append(text.count('!'))  # Exclamation marks
            feature_vector.append(text.count('?'))  # Question marks
            
            features.append(feature_vector)
        
        return np.array(features)
    
    def create_ensemble_model(self):
        """
        Create an ensemble model combining multiple classifiers.
        """
        # Define individual classifiers
        classifiers = []
        
        # Logistic Regression with balanced weights
        lr = LogisticRegression(
            random_state=42,
            max_iter=3000,
            class_weight='balanced',
            C=2.0,
            solver='liblinear'
        )
        classifiers.append(('lr', lr))
        
        # Random Forest
        rf = RandomForestClassifier(
            n_estimators=300,
            class_weight='balanced',
            random_state=42,
            max_depth=20,
            min_samples_split=3,
            min_samples_leaf=1,
            n_jobs=-1
        )
        classifiers.append(('rf', rf))
        
        # Gradient Boosting
        gb = GradientBoostingClassifier(
            n_estimators=200,
            learning_rate=0.1,
            max_depth=10,
            random_state=42
        )
        classifiers.append(('gb', gb))
        
        # Support Vector Machine
        svm = SVC(
            kernel='rbf',
            class_weight='balanced',
            probability=True,
            random_state=42,
            C=1.0,
            gamma='scale'
        )
        classifiers.append(('svm', svm))
        
        # Naive Bayes
        nb = MultinomialNB(alpha=0.1)
        classifiers.append(('nb', nb))
        
        # Neural Network
        mlp = MLPClassifier(
            hidden_layer_sizes=(200, 100, 50),
            max_iter=1000,
            random_state=42,
            alpha=0.01,
            learning_rate_init=0.001
        )
        classifiers.append(('mlp', mlp))
        
        # XGBoost if available
        if XGBOOST_AVAILABLE:
            xgb_classifier = xgb.XGBClassifier(
                n_estimators=200,
                max_depth=8,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42,
                eval_metric='mlogloss'
            )
            classifiers.append(('xgb', xgb_classifier))
        
        # Create voting classifier
        ensemble = VotingClassifier(
            estimators=classifiers,
            voting='soft',
            n_jobs=-1
        )
        
        return ensemble
    
    def train_model(self, model_type='ensemble'):
        """
        Train an advanced threat classification model.
        
        Args:
            model_type: 'ensemble', 'xgboost', 'neural', or 'svm'
        """
        # Database setup
        DATABASE_URL = "sqlite:///./threats.db"
        engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        
        db = SessionLocal()
        threats = db.query(Threat).all()
        db.close()
        
        if len(threats) == 0:
            raise ValueError("No threat data found in database. Please run data ingestion first.")
        
        # Prepare training data
        descriptions = [threat.description for threat in threats]
        categories = [threat.category for threat in threats]
        
        print(f"Training advanced model with {len(descriptions)} samples...")
        print(f"Model type: {model_type}")
        print(f"Number of unique categories: {len(set(categories))}")
        
        # Analyze class distribution
        class_counts = Counter(categories)
        print("\nClass distribution:")
        for category, count in class_counts.items():
            print(f"  {category}: {count} samples ({count/len(categories)*100:.1f}%)")
        
        # Advanced text vectorization with multiple approaches
        tfidf_word = TfidfVectorizer(
            max_features=25000,
            stop_words='english',
            ngram_range=(1, 3),
            min_df=1,
            max_df=0.95,
            lowercase=True,
            strip_accents='unicode',
            analyzer='word',
            sublinear_tf=True
        )
        
        tfidf_char = TfidfVectorizer(
            max_features=10000,
            analyzer='char',
            ngram_range=(2, 4),
            min_df=1,
            max_df=0.95,
            lowercase=True
        )
        
        # Create feature pipeline
        if self.feature_engineering_enabled:
            # Combine TF-IDF features with custom features
            word_features = tfidf_word.fit_transform(descriptions)
            char_features = tfidf_char.fit_transform(descriptions)
            custom_features = self.create_advanced_features(descriptions)
            
            # Combine all features
            from scipy.sparse import hstack, csr_matrix
            combined_features = hstack([
                word_features,
                char_features,
                csr_matrix(custom_features)
            ])
            
            X = combined_features
        else:
            X = tfidf_word.fit_transform(descriptions)
        
        y = categories
        
        # Feature selection
        if X.shape[1] > 30000:
            print("Applying feature selection...")
            selector = SelectKBest(chi2, k=30000)
            X = selector.fit_transform(X, y)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"\nTraining set: {X_train.shape[0]} samples with {X_train.shape[1]} features")
        print(f"Test set: {X_test.shape[0]} samples")
        
        # Choose and train model
        if model_type == 'ensemble':
            classifier = self.create_ensemble_model()
        elif model_type == 'xgboost' and XGBOOST_AVAILABLE:
            classifier = xgb.XGBClassifier(
                n_estimators=500,
                max_depth=10,
                learning_rate=0.05,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42,
                eval_metric='mlogloss',
                n_jobs=-1
            )
        elif model_type == 'neural':
            classifier = MLPClassifier(
                hidden_layer_sizes=(500, 300, 150, 75),
                max_iter=2000,
                random_state=42,
                alpha=0.001,
                learning_rate_init=0.001,
                learning_rate='adaptive',
                beta_1=0.9,
                beta_2=0.999
            )
        elif model_type == 'svm':
            classifier = SVC(
                kernel='rbf',
                class_weight='balanced',
                probability=True,
                random_state=42,
                C=2.0,
                gamma='auto'
            )
        else:
            # Default to Random Forest
            classifier = RandomForestClassifier(
                n_estimators=500,
                class_weight='balanced',
                random_state=42,
                max_depth=25,
                min_samples_split=2,
                min_samples_leaf=1,
                n_jobs=-1
            )
        
        # Train the model
        print("Training the classification model...")
        classifier.fit(X_train, y_train)
        
        # Create final pipeline
        self.model = {
            'classifier': classifier,
            'tfidf_word': tfidf_word,
            'tfidf_char': tfidf_char if self.feature_engineering_enabled else None,
            'feature_engineering': self.feature_engineering_enabled,
            'model_type': model_type
        }
        
        # Evaluate model performance
        y_pred = classifier.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"\nModel training completed!")
        print(f"Accuracy: {accuracy:.4f}")
        print("\nDetailed Classification Report:")
        print(classification_report(y_test, y_pred, zero_division=1))
        
        # Confusion matrix
        print("\nConfusion Matrix:")
        cm = confusion_matrix(y_test, y_pred)
        categories_sorted = sorted(set(categories))
        print(f"Categories: {categories_sorted}")
        print(cm)
        
        # Cross-validation score
        print("\nCross-validation performance:")
        cv_scores = cross_val_score(classifier, X_train, y_train, cv=5, scoring='accuracy')
        print(f"CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
        
        # Save the model
        self.save_model()
        
        return accuracy
    
    def save_model(self):
        """Save the trained model to disk."""
        if self.model is None:
            raise ValueError("No model to save. Train the model first.")
        
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)
        
        print(f"Model saved to {self.model_path}")
    
    def load_model(self):
        """Load a pre-trained model from disk."""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Model file {self.model_path} not found. Train the model first.")
        
        with open(self.model_path, 'rb') as f:
            self.model = pickle.load(f)
        
        print(f"Model loaded from {self.model_path}")
    
    def predict(self, description: str):
        """
        Predict the threat category for a given description.
        """
        if self.model is None:
            try:
                self.load_model()
            except FileNotFoundError:
                raise ValueError("No trained model available. Please train the model first.")
        
        # Prepare features
        if self.model['feature_engineering']:
            word_features = self.model['tfidf_word'].transform([description])
            char_features = self.model['tfidf_char'].transform([description])
            custom_features = self.create_advanced_features([description])
            
            from scipy.sparse import hstack, csr_matrix
            combined_features = hstack([
                word_features,
                char_features,
                csr_matrix(custom_features)
            ])
            X = combined_features
        else:
            X = self.model['tfidf_word'].transform([description])
        
        # Get prediction and probabilities
        prediction = self.model['classifier'].predict(X)[0]
        probabilities = self.model['classifier'].predict_proba(X)[0]
        confidence = max(probabilities)
        
        # Get all class probabilities
        classes = self.model['classifier'].classes_
        all_predictions = dict(zip(classes, probabilities))
        
        return {
            "predicted_category": prediction,
            "confidence": float(confidence),
            "all_predictions": {k: float(v) for k, v in all_predictions.items()}
        }

# Global classifier instance
classifier = AdvancedThreatClassifier()

# Add ML endpoints to the FastAPI app
def add_ml_endpoints(app):
    """Add machine learning endpoints to the FastAPI application."""
    
    @app.post("/api/analyze-advanced", response_model=ThreatAnalysisResponse)
    async def analyze_threat_advanced(request: ThreatAnalysisRequest):
        """Analyze a threat description using the advanced model."""
        try:
            result = classifier.predict(request.description)
            return ThreatAnalysisResponse(**result)
        except Exception as e:
            from fastapi import HTTPException
            raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    
    @app.post("/api/train-ensemble")
    async def train_ensemble_model():
        """Train the ensemble threat classification model."""
        try:
            accuracy = classifier.train_model('ensemble')
            return {
                "status": "success",
                "message": "Ensemble model trained successfully",
                "accuracy": accuracy
            }
        except Exception as e:
            from fastapi import HTTPException
            raise HTTPException(status_code=500, detail=f"Training failed: {str(e)}")
    
    @app.post("/api/train-xgboost")
    async def train_xgboost_model():
        """Train the XGBoost threat classification model."""
        try:
            accuracy = classifier.train_model('xgboost')
            return {
                "status": "success",
                "message": "XGBoost model trained successfully",
                "accuracy": accuracy
            }
        except Exception as e:
            from fastapi import HTTPException
            raise HTTPException(status_code=500, detail=f"Training failed: {str(e)}")
    
    @app.post("/api/train-neural")
    async def train_neural_model():
        """Train the neural network threat classification model."""
        try:
            accuracy = classifier.train_model('neural')
            return {
                "status": "success",
                "message": "Neural network model trained successfully",
                "accuracy": accuracy
            }
        except Exception as e:
            from fastapi import HTTPException
            raise HTTPException(status_code=500, detail=f"Training failed: {str(e)}")

def main():
    """Command-line interface for advanced model operations."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python advanced_ml_model.py <command> [options]")
        print("Commands:")
        print("  ensemble    - Train ensemble model (recommended)")
        print("  xgboost     - Train XGBoost model")
        print("  neural      - Train neural network model")
        print("  svm         - Train SVM model")
        print("  predict     - Interactive prediction mode")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    if command in ['ensemble', 'xgboost', 'neural', 'svm']:
        try:
            print(f"Training {command} model...")
            accuracy = classifier.train_model(command)
            print(f"{command.capitalize()} model training completed successfully!")
            print(f"Final accuracy: {accuracy:.4f}")
        except Exception as e:
            print(f"Training failed: {str(e)}")
            sys.exit(1)
    
    elif command == "predict":
        try:
            classifier.load_model()
            print("Advanced prediction mode. Enter 'quit' to exit.")
            
            while True:
                description = input("\nEnter threat description: ")
                if description.lower() == 'quit':
                    break
                
                result = classifier.predict(description)
                print(f"\nPredicted category: {result['predicted_category']}")
                print(f"Confidence: {result['confidence']:.4f}")
                
                print("\nAll predictions:")
                for category, prob in sorted(result['all_predictions'].items(), 
                                           key=lambda x: x[1], reverse=True):
                    print(f"  {category}: {prob:.4f}")
        
        except Exception as e:
            print(f"Prediction failed: {str(e)}")
            sys.exit(1)
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)

if __name__ == "__main__":
    main()