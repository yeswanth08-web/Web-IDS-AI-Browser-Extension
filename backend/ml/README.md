# Optional packet-level model

No trained model is shipped. The API looks for `webguard_rf.joblib` in this directory after you train one.

The training script expects numeric packet-feature columns:

`Length, TTL, Protocol, IsTCP, IsUDP, IsICMP, Label`

Labels in `Benign`, `Normal`, `0`, `False`, or `Legitimate` are mapped to `benign`; non-empty attack labels are mapped to `attack`. The script rejects missing/empty labels, drops rows with no usable numeric features, uses a stratified hold-out split, and prints precision/recall/F1 plus a confusion matrix.

This is a small packet-level baseline. It is not directly compatible with raw CIC-IDS2017/2018 flow columns; create and document a feature mapping first. A random row split may overestimate performance when records from the same capture/host appear in both splits. Prefer capture/time/host-separated evaluation for research reporting.
