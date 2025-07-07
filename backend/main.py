from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, func
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import pandas as pd
import os
import pickle
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
import re
from collections import Counter
import warnings
warnings.filterwarnings('ignore')

# Database Configuration
DATABASE_URL = "sqlite:///./threats.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database Model
class Threat(Base):
    __tablename__ = "threats"
    
    id = Column(Integer, primary_key=True, index=True)
    description = Column(String, index=True)
    category = Column(String, index=True)
    severity = Column(String, index=True)

# Pydantic Schemas
class ThreatBase(BaseModel):
    description: str
    category: str
    severity: str

class ThreatResponse(ThreatBase):
    id: int
    
    class Config:
        from_attributes = True

class StatsResponse(BaseModel):
    total: int
    by_category: Dict[str, int]
    by_severity: Dict[str, int]

# ML Schemas
class ThreatAnalysisRequest(BaseModel):
    description: str

class ThreatAnalysisResponse(BaseModel):
    predicted_category: str
    confidence: float
    all_predictions: Dict[str, float]

class ModelTrainingResponse(BaseModel):
    status: str
    message: str
    accuracy: float

# ML Classifier Class
class ThreatClassifier:
    def __init__(self):
        self.model = None
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
    
    def load_model(self):
        """Load the trained model from pickle file."""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Model file {self.model_path} not found. Please train the model first.")
        
        with open(self.model_path, 'rb') as f:
            self.model = pickle.load(f)
        
        print(f"Model loaded from {self.model_path}")
        return True
    
    def predict(self, description: str):
        """Predict threat category using the loaded model."""
        if self.model is None:
            try:
                self.load_model()
            except FileNotFoundError:
                raise HTTPException(
                    status_code=500, 
                    detail="Model not found. Please train the model first using /api/train-model endpoint."
                )
        
        # Preprocess input
        processed_text = self.preprocess_text(description)
        
        if not processed_text.strip():
            return {
                "predicted_category": "Unknown",
                "confidence": 0.0,
                "all_predictions": {}
            }
        
        try:
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
            predicted_label = self.model['label_encoder'].inverse_transform([prediction])[0]
            all_labels = self.model['label_encoder'].classes_
            all_predictions = dict(zip(all_labels, probabilities))
            
            return {
                "predicted_category": predicted_label,
                "confidence": float(max(probabilities)),
                "all_predictions": {k: float(v) for k, v in all_predictions.items()}
            }
            
        except Exception as e:
            raise HTTPException(
                status_code=500, 
                detail=f"Prediction failed: {str(e)}. The model might be corrupted or incompatible."
            )

# Global classifier instance
threat_classifier = ThreatClassifier()

# Database Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Create database tables and try to load model
    Base.metadata.create_all(bind=engine)
    
    # Add some sample data if the database is empty
    db = SessionLocal()
    try:
        if db.query(Threat).count() == 0:
            sample_threats = [
                Threat(description="DDoS attack targeting web servers", category="DDoS", severity="High"),
                Threat(description="Malware detected in email attachment", category="Malware", severity="Critical"),
                Threat(description="Phishing email requesting login credentials", category="Phishing", severity="Medium"),
                Threat(description="Ransomware encrypted company files", category="Ransomware", severity="Critical"),
                Threat(description="Suspicious network traffic detected", category="Network", severity="Medium"),
                Threat(description="Unauthorized access attempt", category="Intrusion", severity="High"),
                Threat(description="SQL injection vulnerability found", category="Web", severity="High"),
                Threat(description="Brute force attack on login system", category="Authentication", severity="Medium"),
            ]
            db.add_all(sample_threats)
            db.commit()
            print("✅ Sample threat data added to database")
    except Exception as e:
        print(f"⚠️ Error adding sample data: {e}")
    finally:
        db.close()
    
    try:
        threat_classifier.load_model()
        print("✅ ML model loaded successfully!")
    except FileNotFoundError:
        print("⚠️  ML model not found. Train the model using /api/train-model endpoint.")
    except Exception as e:
        print(f"⚠️  Error loading ML model: {e}")
    
    yield
    # Shutdown: Cleanup if needed
    pass

# Create FastAPI app with lifespan handler
app = FastAPI(
    title="Threat Intelligence Dashboard API with ML", 
    version="1.0.0",
    description="API for threat intelligence with machine learning capabilities",
    lifespan=lifespan
)

# CORS middleware for fetching data from frontend applications
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",  # Vite default port
        "http://localhost:3000",  # React default port
        "http://127.0.0.1:5173",  # Alternative localhost
        "http://127.0.0.1:3000",  # Alternative localhost
        "http://localhost:8080",  # Vue default port
        "http://localhost:4200",  # Angular default port
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# CRUD API Endpoints
@app.get("/api/threats", response_model=List[ThreatResponse])
async def get_threats(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(10, ge=1, le=100, description="Items per page"),
    search: Optional[str] = Query(None, description="Search in threat descriptions"),
    category: Optional[str] = Query(None, description="Filter by threat category"),
    db: Session = Depends(get_db)
):
    """
    Retrieve threats with pagination, search, and filtering capabilities.
    """
    query = db.query(Threat)
    
    # Apply filters
    if search:
        query = query.filter(Threat.description.ilike(f"%{search}%"))
    
    if category:
        query = query.filter(Threat.category == category)
    
    # Apply pagination
    skip = (page - 1) * limit
    threats = query.offset(skip).limit(limit).all()
    
    return threats

@app.get("/api/stats", response_model=StatsResponse)
async def get_stats(db: Session = Depends(get_db)):
    """
    Get statistical overview of the threat dataset.
    """
    # Total count
    total = db.query(func.count(Threat.id)).scalar()
    
    # Category breakdown
    category_results = db.query(
        Threat.category, 
        func.count(Threat.id)
    ).group_by(Threat.category).all()
    by_category = {category: count for category, count in category_results}
    
    # Severity breakdown
    severity_results = db.query(
        Threat.severity, 
        func.count(Threat.id)
    ).group_by(Threat.severity).all()
    by_severity = {severity: count for severity, count in severity_results}
    
    return StatsResponse(
        total=total,
        by_category=by_category,
        by_severity=by_severity
    )

@app.get("/api/threats/{threat_id}", response_model=ThreatResponse)
async def get_threat(threat_id: int, db: Session = Depends(get_db)):
    """
    Retrieve a specific threat by ID.
    """
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    return threat

@app.get("/api/categories")
async def get_categories(db: Session = Depends(get_db)):
    """
    Get all unique threat categories for filtering.
    """
    categories = db.query(Threat.category).distinct().all()
    return [cat[0] for cat in categories if cat[0]]

# NEW ML ENDPOINTS USING THE .PKL FILE
@app.post("/api/analyze-threat", response_model=ThreatAnalysisResponse)
async def analyze_threat(request: ThreatAnalysisRequest):
    """
    Analyze a threat description using the trained ML model.
    This endpoint uses the threat_classifier.pkl file.
    """
    try:
        result = threat_classifier.predict(request.description)
        return ThreatAnalysisResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/api/train-model", response_model=ModelTrainingResponse)
async def train_model(db: Session = Depends(get_db)):
    """
    Train the ML model using current threat data and save it as threat_classifier.pkl.
    This creates/updates the .pkl file.
    """
    try:
        # Import the training functionality
        from optimized_model import OptimizedThreatClassifier
        
        # Create and train the classifier
        classifier = OptimizedThreatClassifier()
        accuracy = classifier.train_model('best')
        
        # Reload the global classifier with the new model
        threat_classifier.model = None  # Reset current model
        threat_classifier.load_model()  # Load the newly trained model
        
        return ModelTrainingResponse(
            status="success",
            message="Model trained and saved successfully",
            accuracy=accuracy
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Training failed: {str(e)}")

@app.get("/api/model-status")
async def get_model_status():
    """
    Check if the ML model (.pkl file) is loaded and ready for predictions.
    """
    model_exists = os.path.exists(threat_classifier.model_path)
    model_loaded = threat_classifier.model is not None
    
    status = "ready" if model_loaded else "not_loaded"
    if not model_exists:
        status = "not_trained"
    
    return {
        "model_file_exists": model_exists,
        "model_loaded": model_loaded,
        "status": status,
        "model_path": threat_classifier.model_path,
        "message": {
            "ready": "Model is loaded and ready for predictions",
            "not_loaded": "Model file exists but not loaded. Try restarting the server.",
            "not_trained": "Model not trained yet. Use /api/train-model to train the model."
        }.get(status, "Unknown status")
    }

# Health check endpoint
@app.get("/health")
async def health_check():
    """
    Health check endpoint for monitoring.
    """
    return {
        "status": "healthy", 
        "service": "threat-intelligence-api",
        "ml_model_loaded": threat_classifier.model is not None
    }

# Test endpoint to verify API is working
@app.get("/api/test")
async def test_endpoint():
    """
    Simple test endpoint to verify API connectivity.
    """
    return {
        "message": "API is working correctly!",
        "timestamp": pd.Timestamp.now().isoformat(),
        "endpoints": {
            "stats": "/api/stats",
            "threats": "/api/threats",
            "categories": "/api/categories",
            "health": "/health"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)