# Evaluation

Dataset: 26,825 events over 14 days (seeded synthetic, labeled): 9 injected attack chains, 11 near-miss benign chains, plus realistic background noise.

### v1 (first draft)

| Rule | Single-event alerts | Composite alerts | TP | FP | Recall | Precision | SNR (TP:FP) | Alert reduction | Median time to detect |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ransomware-precursor | 163 (9 from attacks) | 16 | 3 | 13 | 3/3 | 0.19 | 3:13 | 90.18% | 90.0 min |
| spray-to-mailbox-access | 11,101 (81 from attacks) | 6 | 3 | 3 | 3/3 | 0.50 | 3:3 | 99.95% | 28.0 min |
| token-to-cloud-theft | 15,561 (126 from attacks) | 11 | 3 | 8 | 3/3 | 0.27 | 3:8 | 99.93% | 35.0 min |

### Tuned

| Rule | Single-event alerts | Composite alerts | TP | FP | Recall | Precision | SNR (TP:FP) | Alert reduction | Median time to detect |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ransomware-precursor | 149 (9 from attacks) | 3 | 3 | 0 | 3/3 | 1.00 | 3:0 | 97.99% | 90.0 min |
| spray-to-mailbox-access | 11,101 (81 from attacks) | 3 | 3 | 0 | 3/3 | 1.00 | 3:0 | 99.97% | 28.0 min |
| token-to-cloud-theft | 14,372 (126 from attacks) | 3 | 3 | 0 | 3/3 | 1.00 | 3:0 | 99.98% | 35.0 min |

False-positive entities (tuned): ransomware-precursor: none; spray-to-mailbox-access: none; token-to-cloud-theft: none
