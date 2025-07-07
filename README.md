# 🛡️ ConSecure: AI-Powered Threat Intelligence Dashboard

A sophisticated cybersecurity intelligence platform that uses advanced machine learning to automatically detect, analyze, and classify cyber threats from text descriptions. Built for security operations centers and threat intelligence teams.

---

## 🌟 Key Highlights

### 🧠 Advanced Machine Learning Engine
This project's **core strength** lies in its sophisticated AI-powered threat classification system:

**🎯 Smart Threat Classification**
- **Multi-Algorithm Ensemble**: Combines RandomForest, Logistic Regression, SVM, and Multinomial Naive Bayes for maximum accuracy
- **XGBoost Integration**: Optional advanced gradient boosting for enterprise-level performance
- **Custom Feature Engineering**: Goes beyond basic text analysis with 15+ intelligent features including:
  - Keyword density analysis (malware, phishing, ransomware indicators)
  - Special character pattern detection
  - Technology stack identification
  - Threat severity scoring
  - URL and IP address pattern recognition

**🔤 Advanced Natural Language Processing**
- **TF-IDF Vectorization**: Converts threat descriptions into mathematical features the AI can understand
- **N-gram Analysis**: Captures context by analyzing word combinations (1-3 word sequences)
- **Text Preprocessing Pipeline**: Intelligent cleaning, normalization, and feature extraction
- **Real-time Prediction**: Instant threat category classification with confidence scores

**🏗️ Robust ML Architecture**
- **Modular Design**: Clean separation of data processing, model training, and prediction logic
- **Model Persistence**: Saves trained models for instant loading and prediction
- **Cross-validation**: Ensures model reliability with proper train/test splits
- **Performance Metrics**: Detailed accuracy, precision, recall, and F1-score reporting

---

## 🚀 Features

### 📊 Interactive Dashboard
- **Real-time Threat Visualization**: Beautiful charts showing threat distribution and trends
- **Statistics Overview**: Live counts of threats by category and severity
- **Responsive Design**: Works perfectly on desktop, tablet, and mobile

### 🔍 Intelligent Threat Analyzer
- **AI-Powered Classification**: Paste any threat description and get instant category prediction
- **Confidence Scoring**: Shows how certain the AI is about its prediction
- **Multiple Model Support**: Choose between different AI models for comparison

### 📋 Comprehensive Threat Management
- **Advanced Filtering**: Search and filter threats by category, severity, or keywords
- **Pagination**: Efficient browsing of large threat databases
- **Detailed Threat Views**: Complete information about each threat

### 🔄 Live API Integration
- **Real-time Data**: Always up-to-date threat intelligence
- **CORS Support**: Seamless frontend-backend communication
- **Health Monitoring**: Built-in system health checks

---

## 🧱 Technology Stack

### Frontend (Modern React Ecosystem)
- **React 18** with TypeScript for type-safe development
- **Vite** for lightning-fast development and builds
- **Tailwind CSS** for beautiful, responsive design
- **Recharts** for interactive data visualization
- **Axios** for robust API communication
- **Vitest** for comprehensive testing

### Backend (High-Performance Python)
- **FastAPI** for modern, fast API development
- **SQLAlchemy** for database operations and ORM
- **SQLite** for lightweight, embedded database
- **Pydantic** for data validation and serialization
- **CORS Middleware** for cross-origin requests

### Machine Learning & Data Science
- **Scikit-learn** for core ML algorithms and preprocessing
- **TF-IDF Vectorizer** for text feature extraction
- **RandomForest, SVM, LogisticRegression** for ensemble classification
- **XGBoost** (optional) for advanced gradient boosting
- **Pandas & NumPy** for data manipulation
- **Pickle** for model serialization

### DevOps & Deployment
- **Docker** support for containerized deployment
- **Uvicorn** ASGI server for production
- **Git** version control with proper .gitignore setup

---

## 🏗️ Project Architecture

```
ConSecure Dashboard
├── 🎨 Frontend (React + Vite)
│   ├── Dashboard (Statistics & Charts)
│   ├── ThreatList (Browsing & Filtering)
│   ├── ThreatAnalyzer (AI Prediction Interface)
│   └── API Layer (Axios Integration)
│
├── 🧠 Backend (FastAPI + ML)
│   ├── main.py (API Endpoints & DB Integration)
│   ├── optimized_model.py (🌟 Advanced ML Engine)
│   ├── ingest.py (Data Loading & Management)
│   └── Database (SQLite + Threat Data)
│
└── 🤖 AI Models
    ├── threat_classifier.pkl (Trained Model)
    ├── TF-IDF Vectorizer (Text Processing)
    └── Feature Engineering Pipeline
```

---

## 🛠️ Setup Instructions

### 1. Backend Setup (AI Engine)

```bash
# Navigate to backend directory
cd backend

# Create virtual environment
python -m venv env

# Activate virtual environment
# On Windows:
env\Scripts\activate
# On macOS/Linux:
source env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the FastAPI server
uvicorn main:app --reload
```

The backend will be available at `http://localhost:8000`

### 2. Frontend Setup (Dashboard)

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

The frontend will be available at `http://localhost:5173`

### 3. Train the AI Model (Optional)

```bash
# In the backend directory
python optimized_model.py
```

This will train a new model with the current threat data and save it for predictions.

---

## 🌐 API Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `GET` | `/api/stats` | Dashboard statistics and metrics |
| `GET` | `/api/threats` | Paginated threat list with filtering |
| `GET` | `/api/categories` | All available threat categories |
| `POST` | `/api/analyze-threat` | **🧠 AI-powered threat classification** |
| `POST` | `/api/train-model` | **🔄 Retrain the ML model** |
| `GET` | `/api/test` | Test API connectivity |
| `GET` | `/health` | System health check |

---

## 🤖 Machine Learning Details

### The AI Brain: OptimizedThreatClassifier

This is the heart of the system - a sophisticated AI engine that I've built from scratch:

**🔍 Text Processing Pipeline**
1. **Preprocessing**: Cleans and normalizes threat descriptions
2. **Feature Engineering**: Extracts 15+ intelligent features from text
3. **Vectorization**: Converts text to numerical features using TF-IDF
4. **Classification**: Uses ensemble of multiple algorithms for best accuracy

**🎯 Smart Features Extracted**
- Malware keyword density
- Phishing indicators
- Ransomware patterns  
- Network threat signatures
- File extension analysis
- URL pattern recognition
- IP address detection
- Special character frequency
- Text length analysis
- Technology stack mentions

**🏆 Model Performance**
- **Ensemble Approach**: Combines multiple algorithms for maximum accuracy
- **Cross-validation**: Ensures reliability across different data splits
- **Confidence Scoring**: Provides probability estimates for predictions
- **Continuous Learning**: Can retrain with new threat data

**💾 Model Persistence**
- Saves trained models as `.pkl` files
- Instant loading for real-time predictions
- Version control for model updates

---

## 🧪 Testing

### Frontend Testing
```bash
cd frontend
npm run test
```

### Backend Testing
```bash
cd backend
pytest  # (if test files are added)
```

---

## 🐳 Docker Support

### Backend Docker
```dockerfile
FROM python:3.10
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Frontend Docker
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY . .
RUN npm install && npm run build
EXPOSE 5173
CMD ["npm", "run", "preview"]
```

---

## 📊 Key Components

### 1. Dashboard
- Real-time threat statistics
- Interactive charts and graphs
- Category distribution analysis
- Threat severity breakdown

### 2. Threat Analyzer (AI-Powered)
- Paste any threat description
- Get instant AI classification
- View confidence scores
- Compare different models

### 3. Threat List
- Browse all threats in database
- Advanced search and filtering
- Pagination for large datasets
- Detailed threat information

### 4. API Health Monitor
- Real-time connectivity status
- CORS configuration testing
- Database connection health
- Model loading status

---

## 🎯 What Makes This Special

### Advanced AI Integration
Unlike basic threat management tools, this system uses sophisticated machine learning to automatically understand and classify threats. The AI can learn from new threats and improve over time.

### Real-world Applications
- **SOC Teams**: Automatically categorize incoming threat reports
- **Threat Intelligence**: Classify and organize threat data
- **Security Research**: Analyze threat patterns and trends
- **Incident Response**: Quickly identify threat types during incidents

### Scalable Architecture
Built with modern technologies that can handle everything from small security teams to enterprise-level deployments.

---

## 👨‍💻 Author

**Niel Abhishek J David**
- Full-stack Developer & Cybersecurity Enthusiast  
- Machine Learning Engineer & AI Researcher
- Passionate about building intelligent security solutions

### Other Projects
- MagicMirror² Smart Display System
- Facial Recognition Authentication System
- Advanced Threat Analysis Tools
- Intelligent Security Automation

---

## 🚀 Getting Started

1. **Clone the repository**
2. **Set up the backend** (follow backend setup instructions)
3. **Set up the frontend** (follow frontend setup instructions)
4. **Train the AI model** (optional, for custom data)
5. **Start exploring threats** with AI-powered analysis!

---

## 📝 License

This project is built for educational and professional demonstration purposes.

---

**Built with ❤️ and 🧠 for the ConSecure July 2025 Assignment**

*Combining cutting-edge AI with practical cybersecurity needs*