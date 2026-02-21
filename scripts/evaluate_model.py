import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, classification_report, roc_curve, auc
from core.forensics_engine import IoTForensicsEngine

def run_benchmarks():
    print("🧪 Starting Model Evaluation Benchmark...")
    
    #Use existing data for testing
    c2_path = "data/heartbeat_analysis.csv"
    ddos_path = "data/ddos_traffic.csv"
    
    #Initialize engine and run forensics
    engine = IoTForensicsEngine(c2_path, ddos_path)
    if not engine.run_forensics():
        print("❌ Error: No data found for evaluation.")
        return

    engine.analyze_behavior()
    engine.run_ml_detection()
    
    #Validation Logic
    y_true = [0] * 1000 + [1] * 1000 
    y_pred = [1 if val == 1 else 0 for val in engine.df_c2['ai_label']] 
    
    #Generate Confusion Matrix Plot
    plt.figure(figsize=(8, 6))
    cm = confusion_matrix(y_true, y_pred)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Normal', 'Bot'], yticklabels=['Normal', 'Bot'])
    plt.title('Confusion Matrix - IoT Forensic AI')
    plt.ylabel('Actual Label')
    plt.xlabel('Predicted Label')
    plt.savefig('evaluation_results_cm.png')
    print("[✓] Confusion Matrix saved as evaluation_results_cm.png")
    print("\n--- SCIENTIFIC CLASSIFICATION REPORT ---")
    print(classification_report(y_true, y_pred))

if __name__ == "__main__":
    run_benchmarks()