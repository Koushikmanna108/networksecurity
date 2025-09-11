## 🛡️ Network Security – Malicious URL Detection

This project is a Machine Learning-based Web Security System that detects whether a given URL is malicious or benign.
It supports:

● Training ML models on phishing dataset (phishingData.csv)

● Predicting malicious URLs via CSV file upload

● Predicting single URL via form input

The system is built using FastAPI, scikit-learn, and MongoDB, with a web interface for easy interaction.

## 📂 Project Structure
```
NETWORK SECURITY/
│── app.py                     # FastAPI application (API + UI)
│── main.py                    # For testing
│── push_data.py                # MongoDB data ingestion
│── test_mongodb.py             # MongoDB connection test
│── requirements.txt            # Dependencies
│── setup.py                    # Install project as package
│── README.md                   # Project documentation
│
├── final_model/                # Saved ML model & preprocessor
│   ├── model.pkl
│   ├── preprocessor.pkl
│
├── Network_Data/
│   ├── phishingData.csv        # Training dataset
│
├── data_schema/                # Data schema folder
│   ├── schema.yaml             # Defines dataset schema (features & datatypes)
│
├── prediction_output/           # Stores predictions
│   ├── output.csv
│
├── templates/                  # HTML templates
│   ├── table.html              # Result page
│
├── networksecurity/            # Main ML package
│   ├── components/             # Data ingestion,validation, transformation, training
│   ├── pipeline/               # Training & batch prediction pipelines
│   ├── utils/                  # Feature extractor, utils
│   ├── logging/                # Custom logger
│   ├── exception/              # Custom exception handling
│   ├── constant/               # Constants
│   ├── entity/                 # Config & artifacts
```

## ⚙️ Installation

### 1. Clone the repo
```
git clone https://github.com/Koushikmanna108/networksecurity
cd networksecurity
```

### 2. Create a virtual environment
```
conda create -p venv python==3.13 -y
conda activate venv/ # On Windows
```

### 3. Install dependencies
```
pip install -r requirements.txt
```

### 4. Set up MongoDB connection
Create a .env file in the root directory:
```
MONGODB_URL=mongodb+srv://kmanna713:Koushik642005@cluster0.uf4ybca.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0/
```

## 🚀 Running the Application
### Start FastAPI Server
```
python app.py
```

The app will run at: http://127.0.0.1:8000/docs

## 🧪 Usage
### 🔹 Train the Model

Endpoint:
```
GET /train
```

This will:

● Ingest data (phishingData.csv)

● Train preprocessing pipeline + ML model

● Save artifacts in final_model/

### 🔹 Predict from CSV

Endpoint:
```
POST /predict
```

Upload a CSV file with feature columns.

● Predictions are stored in prediction_output/output.csv

● Results are shown in a web table

### 🔹 Predict from URL

Endpoint:
```
POST /predict-url
```

Input a URL in the form.

● The system extracts 30+ features from the URL

● Runs prediction

● Displays result as Benign / Malicious

● Saves prediction in prediction_output/output.csv

## 📊 Features Extracted from URL

The system checks 30 URL features such as:

● IP Address usage

● URL Length

● Shortening services (bit.ly, tinyurl, etc.)

● HTTPS status

● Domain age & DNS records

● Abnormal URL patterns

● Redirects, iFrames, popups

● Google indexing & PageRank


## ✅ Example URLs for Testing
### Benign:

● https://www.google.com

● https://www.wikipedia.org

● https://github.com

### Malicious:

● http://login.verify-update.com

● http://phishingsite.co.vu

● http://free-gift-cards-online.xyz

## 👨‍💻 Tech Stack

● FastAPI – Web framework

● scikit-learn – ML model

● pandas, numpy – Data processing

● MongoDB – Data storage

● Jinja2 – HTML rendering

## 🔮 Future Enhancements

● Real-time URL scanning via API

● Integration with browser extensions

● More advanced ML/DL models (XGBoost, LSTM)

## 📌 Author

👤 Koushik Manna
🔗 GitHub: Koushikmanna108