# M1 payload classifier — evaluation

- Samples: 30000 (train 25500, test 4500); labels: benign, sqli, xss, traversal, cmdi, ssti
- Char-CNN, INT8 ONNX, CPU. Train time: 37.2s. Model size: 116.9 KB.
- ONNX(int8) vs PyTorch agreement on test set: 100.0%

## Held-out test split
- Detection rate (attack flagged as any attack): 100.00% (n=2260)
- False-positive rate (benign flagged as attack): 0.00% (n=2240)

| class | precision | recall |
|---|---|---|
| benign | 1.0000 | 1.0000 |
| sqli | 1.0000 | 1.0000 |
| xss | 1.0000 | 1.0000 |
| traversal | 1.0000 | 1.0000 |
| cmdi | 1.0000 | 1.0000 |
| ssti | 1.0000 | 1.0000 |

## Obfuscated robustness split (heavy encoding/casing)
- Detection rate: 100.00% (n=2000)
- False-positive rate: 0.00% (n=1200)
