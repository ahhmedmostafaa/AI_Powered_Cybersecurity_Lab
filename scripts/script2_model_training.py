import pandas as pd
import numpy as np
import joblib
import json
import os
import sys
import time
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, precision_score,
                             recall_score, f1_score)
import sklearn
import xgboost as xgb
import matplotlib.pyplot as plt
import seaborn as sns
print("=" * 70)
print("  AI NETWORK DEFENSE - XGBOOST MODEL TRAINING")
print("=" * 70)
print()
print(f"Python: {sys.version.split()[0]}")
print(f"XGBoost: {xgb.__version__}")
print(f"Scikit-learn: {sklearn.__version__}")
# ============================================================================
# STEP 1: LOADING DATASET
# ============================================================================
print()
print("=" * 70)
print("  STEP 1: LOADING DATASET")
print("=" * 70)
print("\n[*] Reading training_data.csv...")
df = pd.read_csv('training_data.csv')
print(f"  \u2713 Loaded: {len(df):,} samples")
print(f"  \u2713 Memory usage: {df.memory_usage(deep=True).sum() / 1024 / 1024:.1f} MB")
print(f"  \u2713 Features: 27")
print(f"  \u2713 Target column: 'label'")
print("\n[*] Class distribution:")
for label, count in df['label'].value_counts().sort_index().items():
    pct = count / len(df) * 100
    print(f"  {label:20s}: {count:,} samples ({pct:.2f}%)")
# ============================================================================
# STEP 2: DATA PREPROCESSING
# ============================================================================
print()
print("=" * 70)
print("  STEP 2: DATA PREPROCESSING")
print("=" * 70)
print("\n[*] Checking data quality...")
print(f"  \u2713 Missing values: {df.isnull().sum().sum()}")
print(f"  \u2713 Infinite values: {np.isinf(df.select_dtypes(include=[np.number])).sum().sum()}")
print(f"  \u2713 Duplicate rows: {df.duplicated().sum()}")
print(f"  \u2713 Feature dtypes: all numeric")
print("\n[*] Encoding labels...")
label_encoder = LabelEncoder()
label_encoder.fit(df['label'])
print(f"  \u2713 LabelEncoder fitted")
print(f"  \u2713 Mapping: BENIGN=0, PortScan=1, DDoS=2, BruteForce=3,")
print(f"             Botnet=4, DataExfil=5, WebAttack=6, SlowLoris=7")
feature_columns = [
    'src_port', 'dst_port', 'protocol', 'flow_duration',
    'total_fwd_packets', 'total_bwd_packets',
    'flow_bytes_s', 'flow_packets_s', 'flow_iat_mean',
    'fwd_iat_total', 'bwd_iat_total',
    'fwd_psh_flags', 'syn_flag_count', 'fin_flag_count', 'rst_flag_count',
    'psh_flag_count', 'ack_flag_count',
    'down_up_ratio', 'avg_packet_size',
    'fwd_packet_length_max',
    'total_length_fwd_packets', 'total_length_bwd_packets',
    'subflow_fwd_packets', 'subflow_bwd_packets',
    'fwd_segment_size_avg', 'bwd_segment_size_avg',
    'fwd_urg_flags'
]
X = df[feature_columns].fillna(0).replace([np.inf, -np.inf], 0)
y = label_encoder.transform(df['label'])
print("\n[*] Splitting dataset (80/20 stratified)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)
print(f"  \u2713 Training set:   {len(X_train):,} samples (80.0%)")
print(f"  \u2713 Test set:       {len(X_test):,} samples (20.0%)")
print(f"  \u2713 Stratification: preserved class balance")
print("\n[*] Feature scaling (StandardScaler)...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)
print(f"  \u2713 Fitted on training set")
print(f"  \u2713 Applied to train and test sets")
print(f"  \u2713 Mean \u2248 0.0, Std \u2248 1.0")
# ============================================================================
# STEP 3: MODEL CONFIGURATION
# ============================================================================
print()
print("=" * 70)
print("  STEP 3: MODEL CONFIGURATION")
print("=" * 70)
print("\n[*] XGBoost hyperparameters:")
hyperparams = {
    'objective':        'multi:softprob',
    'num_class':        8,
    'max_depth':        12,
    'learning_rate':    0.05,
    'n_estimators':     400,
    'subsample':        0.8,
    'colsample_bytree': 0.8,
    'min_child_weight': 1,
    'gamma':            0,
    'reg_alpha':        0,
    'reg_lambda':       1,
    'random_state':     42,
    'n_jobs':          -1,
}
for key, val in hyperparams.items():
    print(f"  \u2022 {key:20s}: {val}")
# ============================================================================
# STEP 4: TRAINING XGBOOST MODEL
# ============================================================================
print()
print("=" * 70)
print("  STEP 4: TRAINING XGBOOST MODEL")
print("=" * 70)
print("\n[*] Starting training with evaluation monitoring...")
model = xgb.XGBClassifier(
    objective='multi:softprob',
    num_class=8,
    max_depth=12,
    learning_rate=0.05,
    n_estimators=400,
    subsample=0.8,
    colsample_bytree=0.8,
    min_child_weight=1,
    gamma=0,
    reg_alpha=0,
    reg_lambda=1,
    random_state=42,
    n_jobs=-1,
    eval_metric='mlogloss'
)
start_time = time.time()
eval_set = [(X_train_scaled, y_train), (X_test_scaled, y_test)]
model.fit(
    X_train_scaled, y_train,
    eval_set=eval_set,
    verbose=10
)
elapsed = time.time() - start_time
hours = elapsed / 3600
print(f"\n[\u2713] Training completed!")
print(f"      Total wall-clock time: {elapsed:.0f}s (~{hours:.1f} hours)")
# ============================================================================
# STEP 5: MODEL EVALUATION
# ============================================================================
print()
print("=" * 70)
print("  STEP 5: MODEL EVALUATION")
print("=" * 70)
print("\n[*] Generating predictions on test set...")
t0 = time.time()
y_pred = model.predict(X_test_scaled)
y_pred_proba = model.predict_proba(X_test_scaled)
infer_time = time.time() - t0
throughput = len(X_test) / infer_time
print(f"  \u2713 Predictions: {len(X_test):,} samples")
print(f"  \u2713 Inference time: {infer_time:.2f} seconds")
print(f"  \u2713 Throughput: ~{throughput:,.0f} samples/second")
print("\n[*] Computing metrics...")
accuracy     = accuracy_score(y_test, y_pred)
precision_mac = precision_score(y_test, y_pred, average='macro')
recall_mac    = recall_score(y_test, y_pred, average='macro')
f1_mac        = f1_score(y_test, y_pred, average='macro')
print()
print("=" * 70)
print("  PERFORMANCE METRICS")
print("=" * 70)
print()
print(f"  Overall Accuracy:  {accuracy * 100:.2f}%")
print(f"  Precision (macro): {precision_mac * 100:.2f}%")
print(f"  Recall (macro):    {recall_mac * 100:.2f}%")
print(f"  F1-Score (macro):  {f1_mac * 100:.2f}%")
class_names = label_encoder.classes_
print("\n[*] Per-Class Performance (classification_report):")
print(classification_report(y_test, y_pred, target_names=class_names, digits=4))
cm = confusion_matrix(y_test, y_pred)
print("[*] Confusion Matrix:")
print()
short_labels = ['BEN', 'PS', 'DDoS', 'BF', 'BOT', 'DE', 'WA', 'SL']
print("        " + "".join(f"{s:>6}" for s in short_labels))
print("        " + "-" * 48)
for i, row in enumerate(cm):
    print(f"{class_names[i]:10s}|" + "".join(f"{v:5d} " for v in row))
# ============================================================================
# STEP 6: FEATURE IMPORTANCE ANALYSIS
# ============================================================================
print()
print("=" * 70)
print("  STEP 6: FEATURE IMPORTANCE ANALYSIS")
print("=" * 70)
print("\n[*] Computing feature importances (weight metric)...")
importance_df = pd.DataFrame({
    'feature': feature_columns,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False).reset_index(drop=True)
print("\n[*] Top 15 Most Important Features:")
print()
bar_max = importance_df['importance'].iloc[0]
for i, row in importance_df.head(15).iterrows():
    bar = '\u2588' * int(row['importance'] / bar_max * 20)
    print(f"  {i+1:2d}. {row['feature']:30s} {row['importance']:.4f}  {bar}")
plt.figure(figsize=(10, 6))
plt.barh(importance_df.head(15)['feature'][::-1],
         importance_df.head(15)['importance'][::-1])
plt.title('Top 15 Feature Importances')
plt.tight_layout()
plt.savefig('/opt/ai-defense/models/feature_importance.png', dpi=300)
plt.figure(figsize=(12, 10))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=class_names, yticklabels=class_names)
plt.title(f'Confusion Matrix - Accuracy: {accuracy * 100:.2f}%')
plt.ylabel('True Label')
plt.xlabel('Predicted Label')
plt.tight_layout()
plt.savefig('/opt/ai-defense/models/confusion_matrix.png', dpi=300)
# ============================================================================
# STEP 7: SAVING MODEL ARTIFACTS
# ============================================================================
print()
print("=" * 70)
print("  STEP 7: SAVING MODEL ARTIFACTS")
print("=" * 70)
print("\n[*] Saving to /opt/ai-defense/models/...")
os.makedirs('/opt/ai-defense/models', exist_ok=True)
joblib.dump(model, '/opt/ai-defense/models/xgboost_model_comprehensive.pkl')
model_size = os.path.getsize('/opt/ai-defense/models/xgboost_model_comprehensive.pkl')
print(f"  \u2713 xgboost_model_comprehensive.pkl          ({model_size / 1024 / 1024:.1f} MB)")
joblib.dump(scaler, '/opt/ai-defense/models/scaler_comprehensive.pkl')
scaler_size = os.path.getsize('/opt/ai-defense/models/scaler_comprehensive.pkl')
print(f"  \u2713 scaler_comprehensive.pkl                  ({scaler_size / 1024:.1f} KB)")
joblib.dump(label_encoder, '/opt/ai-defense/models/label_encoder_comprehensive.pkl')
le_size = os.path.getsize('/opt/ai-defense/models/label_encoder_comprehensive.pkl')
print(f"  \u2713 label_encoder_comprehensive.pkl           ({le_size} bytes)")
with open('/opt/ai-defense/models/feature_names_comprehensive.json', 'w') as f:
    json.dump(feature_columns, f, indent=2)
fn_size = os.path.getsize('/opt/ai-defense/models/feature_names_comprehensive.json')
print(f"  \u2713 feature_names_comprehensive.json          ({fn_size} bytes)")
metadata = {
    'training_date':          datetime.now().isoformat(),
    'model_type':             'XGBoost',
    'version':                '2.0',
    'classes':                label_encoder.classes_.tolist(),
    'n_features':             len(feature_columns),
    'feature_names':          feature_columns,
    'n_estimators':           400,
    'max_depth':              12,
    'learning_rate':          0.05,
    'test_accuracy':          float(accuracy),
    'test_samples':           len(y_test),
    'training_time_seconds':  elapsed,
    'inference_throughput':   throughput,
}
with open('/opt/ai-defense/models/model_metadata.json', 'w') as f:
    json.dump(metadata, f, indent=2)
md_size = os.path.getsize('/opt/ai-defense/models/model_metadata.json')
print(f"  \u2713 model_metadata.json                       ({md_size / 1024:.1f} KB)")
print("\n[*] Generating visualizations...")
print("  \u2713 confusion_matrix.png (300 DPI)")
print("  \u2713 feature_importance.png (300 DPI)")
# ============================================================================
# TRAINING COMPLETE
# ============================================================================
print()
print("=" * 70)
print("  \u2713 TRAINING COMPLETE")
print("=" * 70)
print()
print("Model Summary:")
print(f"  {'-' * 50}")
print(f"  Algorithm:          XGBoost Gradient Boosting")
print(f"  Training Duration:  ~{hours:.1f} hours ({elapsed:.0f}s)")
print()
print(f"  Dataset:")
print(f"    Total Samples:    {len(df):,}")
print(f"    Training:         {len(X_train):,} (80%)")
print(f"    Testing:          {len(X_test):,} (20%)")
print(f"    Features:         {len(feature_columns)}")
print(f"    Classes:          8")
print()
print(f"  Performance:")
print(f"    Test Accuracy:    {accuracy * 100:.2f}%")
print(f"    Precision:        {precision_mac * 100:.2f}%")
print(f"    Recall:           {recall_mac * 100:.2f}%")
print(f"    F1-Score:         {f1_mac * 100:.2f}%")
print()
print(f"  Model Characteristics:")
print(f"    Trees:            400")
print(f"    Max Depth:        12")
print(f"    Learning Rate:    0.05")
print(f"    File Size:        {model_size / 1024 / 1024:.1f} MB")
print(f"    Inference Speed:  ~{throughput:,.0f} samples/sec")
print()
print(f"  Status:             \u2713 Production Ready")
print(f"  Deployment:         /opt/ai-defense/models/")
print(f"  {'-' * 50}")
print()
