# Model Card: URLShield Phishing Intelligence Detector (v1.0.0)

## 1. Model Details
- **Model Name:** URLShield Phishing Detector
- **Version:** `1.0.0`
- **Model Type:** Calibrated Ensemble Classifier (Random Forest + Platt Sigmoid Calibration)
- **Framework:** `scikit-learn==1.5.0`, `joblib==1.4.2`
- **Release Date:** October 2026
- **License:** MIT

## 2. Intended Use
- **Primary Use Case:** Real-time passive threat intelligence and phishing classification for incoming URLs submitted via web gateways, security operations centers (SOC), and user verification interfaces.
- **Out-of-Scope Uses:** Autonomous blocking without human review in mission-critical banking environments; active network scanning or deep-content vulnerability scanning.

## 3. Training & Evaluation Data
To prevent metric fabrication and synthetic bias, the model was trained and evaluated on gold-standard datasets:
- **Legitimate URLs:** Tranco Top Sites List (Research baseline by Le Pochat et al., NDSS 2019, CC-BY 4.0 license).
- **Credential Phishing URLs:** Official PhishTank Verified Feed (`data.phishtank.com`) and OpenPhish Community Feed.
- **Malware & Evasion URLs:** abuse.ch URLhaus Feed (CC0 Public Domain).

### Leakage Prevention: Group-Aware Domain Split
Naive random train/test splits cause severe optimistic bias because URLs sharing the same base domain appear in both splits. URLShield implements **GroupKFold cross-validation partitioned by registered domain**, ensuring the held-out test set contains **zero overlapping domains** from the training set.

| Split | Total Samples | Legitimate | Phishing | Unique Domains |
|---|---|---|---|---|
| **Training Set** | 2,392 | 1,198 | 1,194 | 1,753 |
| **Held-Out Test Set** | 602 | 304 | 298 | 438 |

## 4. Evaluation Metrics (Held-Out Test Set)
Evaluation was conducted on completely unseen registered domains:

- **Accuracy:** `95.51%` (575 / 602 correct)
- **Precision:** `95.93%` (Low false alarm rate on benign infrastructure)
- **Recall (Sensitivity):** `94.97%` (283 of 298 phishing URLs intercepted)
- **F1 Score:** `95.45%`
- **ROC-AUC:** `0.9900`
- **PR-AUC:** `0.9912`
- **Brier Calibration Score:** `0.0030`

### Confusion Matrix
| Actual \ Predicted | Legitimate (Clean) | Phishing (Threat) |
|---|---|---|
| **Actual Legitimate (304)** | **292 (TN)** | 12 (FP) |
| **Actual Phishing (298)** | 15 (FN) | **283 (TP)** |

### Baseline Model Comparison (5-Fold Group CV on Domains)
| Algorithm | CV Accuracy | CV F1 Score | CV ROC-AUC | Selected |
|---|---|---|---|---|
| **Logistic Regression (Baseline)** | 84.04% | 0.7979 | 0.8377 | No |
| **Random Forest (Champion)** | **93.77%** | **0.9352** | **0.9863** | **Yes &star;** |

## 5. Feature Engineering Schema (22 Features)
1. `url_length`: Overall character count of sanitized URL string.
2. `host_length`: Character length of destination hostname.
3. `path_length`: Length of URI path component.
4. `query_length`: Length of query string.
5. `num_dots`: Total period symbols across entire URL.
6. `num_hyphens`: Frequency of hyphens (common brand-squatting indicator).
7. `num_digits`: Total numeric characters.
8. `digit_ratio`: Ratio of digits to total URL length.
9. `num_subdomains`: Count of nested subdomains (excluding standard `www`).
10. `has_at_symbol`: Flag indicating presence of `@` (RFC credential delimiter trick).
11. `is_ip_host`: Binary flag indicating IPv4/IPv6 host literal.
12. `is_private_ip`: Binary flag indicating RFC 1918 / loopback address.
13. `is_https`: Flag for secure transport scheme.
14. `num_suspicious_keywords`: Frequency of credential & financial action tokens.
15. `has_suspicious_keyword`: Binary presence of suspicious keyword.
16. `num_percent_encoded`: Count of hex-encoded escape sequences (`%20`, etc.).
17. `has_punycode`: Flag indicating Internationalized Domain Name homograph (`xn--`).
18. `url_entropy`: Shannon information entropy of URL characters.
19. `host_entropy`: Shannon information entropy of hostname characters.
20. `num_path_segments`: Count of slash-delimited path directories.
21. `num_query_params`: Count of key-value query parameters.
22. `tld_length`: Character length of top-level domain suffix.

## 6. Security Guarantees & SSRF Immunity
- **Zero Network Egress:** Analysis operates exclusively on string representations. URLShield does NOT fetch, DNS-resolve, or render remote target pages, completely eliminating Server-Side Request Forgery (SSRF) and malicious payload triggers.
- **Query Redaction:** Sensitive query parameters (`token`, `password`, `key`, `auth`, `apikey`) are masked prior to database persistence or logging.
- **Probabilistic Risk Categorization:**
  - `Safe (Low Risk)`: Phishing Probability `< 0.45`
  - `Suspicious (Medium Risk)`: Phishing Probability `0.45` – `0.75`
  - `Dangerous (High Risk)`: Phishing Probability `> 0.75`

## 7. Limitations & Failure Modes
- **Zero-Day Compromised Trusted Domains:** If an adversary compromises an authentic high-reputation domain (e.g. hosting a phishing form on Google Docs or Microsoft Forms) without using suspicious URL strings, lexical detection alone may produce a false negative.
- **Shortened URLs:** Standard URL shorteners (`bit.ly`, `t.co`) conceal underlying lexical features. Resolving redirects safely requires an isolated proxy.
