# Performance Results — AI-Powered Cybersecurity Lab

## XGBoost Model Performance (Test Set: 16,000 samples)

| Metric              | Value    |
|---------------------|----------|
| Overall Accuracy    | 98.94%   |
| Macro Precision     | 98.93%   |
| Macro Recall        | 98.92%   |
| Macro F1-Score      | 98.92%   |
| Inference Speed     | ~11,200 samples/sec |
| Per-Sample Latency  | ~0.089 ms |
| Training Duration   | ~3.5 hours |
| Model Size          | 21.4 MB  |

## Per-Class Results

| Attack Class  | Precision | Recall | F1-Score | Support |
|---------------|-----------|--------|----------|---------|
| BENIGN        | 0.9965    | 0.9965 | 0.9965   | 2,000   |
| PortScan      | 0.9899    | 0.9925 | 0.9912   | 2,000   |
| DDoS          | 0.9980    | 0.9970 | 0.9975   | 2,000   |
| BruteForce    | 0.9849    | 0.9785 | 0.9817   | 2,000   |
| Botnet        | 0.9920    | 0.9905 | 0.9913   | 2,000   |
| DataExfil     | 0.9838    | 0.9815 | 0.9827   | 2,000   |
| WebAttack     | 0.9793    | 0.9835 | 0.9814   | 2,000   |
| SlowLoris     | 0.9901    | 0.9920 | 0.9911   | 2,000   |

## Live Validation Results (240 independent trials)

| Attack Scenario | Primary Detection     | Confidence | MTTM (ms) | σ (ms) | Rate     |
|-----------------|-----------------------|------------|-----------|--------|----------|
| PortScan        | ML + Rule Heuristics  | 99%        | 912       | ±38    | 30/30    |
| Botnet C2       | ML + Zeek             | 99%        | 780       | ±29    | 30/30    |
| DDoS / SYN Flood| Suricata + Zeek + Rules| 99%       | 743       | ±21    | 30/30    |
| SlowLoris       | Heuristics + ML       | 98%        | 921       | ±47    | 30/30    |
| SSH BruteForce  | Suricata + ML         | 99%        | 830       | ±33    | 30/30    |
| RDP BruteForce  | Suricata IDS          | 99%        | 874       | ±25    | 30/30    |
| DataExfiltration| ML + Heuristics       | 98%        | 958       | ±43    | 30/30    |
| WebAttack       | Heuristics + ML       | 98%        | 934       | ±39    | 30/30    |
| **OVERALL**     | **All Layers**        | **≥98%**   | **872**   | **±148**| **240/240** |

## Dataset Statistics

| Class          | Samples | Capture Duration | Rate    |
|----------------|---------|------------------|---------|
| BENIGN         | 10,000  | 5.0 hr           | 0.6 p/s |
| PortScan       | 10,000  | 2.5 hr           | 1.1 p/s |
| DDoS           | 10,000  | 4.0 hr           | 0.7 p/s |
| BruteForce     | 10,000  | 1.5 hr           | 1.9 p/s |
| Botnet         | 10,000  | 1.5 hr           | 1.9 p/s |
| DataExfil      | 10,000  | 3.5 hr           | 0.8 p/s |
| WebAttack      | 10,000  | 3.0 hr           | 0.9 p/s |
| SlowLoris      | 10,000  | 3.0 hr           | 0.9 p/s |
| **TOTAL**      | **80,000** | **~24 hr**    | —       |
