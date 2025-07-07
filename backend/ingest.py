import pandas as pd
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from main import Threat, Base

def ingest_csv_data(csv_file_path: str):
    """
    Ingest cybersecurity threat data from CSV file into the database.
    
    Args:
        csv_file_path (str): Path to the CSV file containing threat data
    """
    
    # Database setup
    DATABASE_URL = "sqlite:///./threats.db"
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    try:
        # Read the CSV file
        print(f"Reading data from {csv_file_path}...")
        df = pd.read_csv(csv_file_path)
        
        # Display basic information about the dataset
        print(f"Dataset shape: {df.shape}")
        print(f"Columns: {list(df.columns)}")
        
        # Check for required columns (handle both underscore and space versions)
        required_columns = ['Cleaned Threat Description', 'Threat Category', 'Severity Score']
        alt_columns = ['Cleaned_Threat_Description', 'Threat_Category', 'Severity_Score']
        
        # Check which column format is present
        if all(col in df.columns for col in required_columns):
            desc_col, cat_col, sev_col = required_columns
        elif all(col in df.columns for col in alt_columns):
            desc_col, cat_col, sev_col = alt_columns
        else:
            print(f"Error: Required columns not found. Looking for either:")
            print(f"  {required_columns} OR {alt_columns}")
            print(f"  Available columns: {list(df.columns)}")
            return False
        
        # Clean and prepare data
        df = df.dropna(subset=[desc_col, cat_col, sev_col])  # Remove rows with missing values
        df[desc_col] = df[desc_col].astype(str)
        df[cat_col] = df[cat_col].astype(str)
        df[sev_col] = df[sev_col].astype(str)
        
        print(f"Cleaned dataset shape: {df.shape}")
        
        # Create database session
        db = SessionLocal()
        
        # Clear existing data (optional - remove if you want to append)
        existing_count = db.query(Threat).count()
        if existing_count > 0:
            print(f"Found {existing_count} existing records. Clearing database...")
            db.query(Threat).delete()
            db.commit()
        
        # Insert data in batches for better performance
        batch_size = 1000
        total_inserted = 0
        
        for i in range(0, len(df), batch_size):
            batch = df.iloc[i:i + batch_size]
            threats_batch = []
            
            for _, row in batch.iterrows():
                threat = Threat(
                    description=row[desc_col],
                    category=row[cat_col],
                    severity=str(row[sev_col])
                )
                threats_batch.append(threat)
            
            db.add_all(threats_batch)
            db.commit()
            
            total_inserted += len(threats_batch)
            print(f"Inserted {total_inserted} records...")
        
        print(f"Successfully ingested {total_inserted} threat records into the database.")
        
        # Display summary statistics
        print("\nDataset Summary:")
        print(f"Total records: {total_inserted}")
        print(f"Unique categories: {df[cat_col].nunique()}")
        print(f"Categories: {sorted(df[cat_col].unique())}")
        print(f"Unique severity levels: {df[sev_col].nunique()}")
        print(f"Severity levels: {sorted(df[sev_col].unique())}")
        
        db.close()
        return True
        
    except FileNotFoundError:
        print(f"Error: Could not find file '{csv_file_path}'")
        return False
    except Exception as e:
        print(f"Error during ingestion: {str(e)}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ingest.py <path_to_csv_file>")
        print("Example: python ingest.py Cybersecurity_Dataset.csv")
        sys.exit(1)
    
    csv_file_path = sys.argv[1]
    success = ingest_csv_data(csv_file_path)
    
    if success:
        print("\nData ingestion completed successfully!")
        print("You can now start the API server with: python main.py")
    else:
        print("\nData ingestion failed!")
        sys.exit(1)