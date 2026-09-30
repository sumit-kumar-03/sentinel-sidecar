"""Train M4 (binary prompt-injection), export INT8 ONNX to /work/out/m4.onnx."""

from __future__ import annotations

import json
import os
from pathlib import Path

import numpy as np
import torch
from torch import nn

from . import dataset_m4
from .encode import MAX_LEN, encode
from .model import CharCNN

OUT = Path(os.environ.get("OUT_DIR", "/work/out"))


def main():
    torch.manual_seed(7)
    rows = dataset_m4.build()
    X = np.array([encode(t) for t, _ in rows], dtype=np.int64)
    y = np.array([lbl for _, lbl in rows], dtype=np.int64)
    n = len(X); split = int(n * 0.85)
    Xtr, Xte, ytr, yte = X[:split], X[split:], y[:split], y[split:]

    model = CharCNN(len(dataset_m4.LABELS))
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    lossf = nn.CrossEntropyLoss()
    Xtr_t, ytr_t = torch.from_numpy(Xtr), torch.from_numpy(ytr)
    for ep in range(8):
        model.train(); perm = torch.randperm(len(Xtr_t)); tot = 0.0
        for i in range(0, len(Xtr_t), 256):
            idx = perm[i:i+256]; opt.zero_grad()
            loss = lossf(model(Xtr_t[idx]), ytr_t[idx]); loss.backward(); opt.step()
            tot += float(loss) * len(idx)
        print(f"epoch {ep+1}/8 loss={tot/len(Xtr_t):.4f}", flush=True)

    model.eval()
    with torch.no_grad():
        pred = model(torch.from_numpy(Xte)).argmax(1).numpy()
    tp = int(((pred == 1) & (yte == 1)).sum()); fn = int(((pred == 0) & (yte == 1)).sum())
    fp = int(((pred == 1) & (yte == 0)).sum()); tn = int(((pred == 0) & (yte == 0)).sum())
    detection = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    OUT.mkdir(parents=True, exist_ok=True)
    fp32 = OUT / "m4_fp32.onnx"
    torch.onnx.export(model, torch.zeros(1, MAX_LEN, dtype=torch.int64), str(fp32),
                      input_names=["input"], output_names=["logits"],
                      dynamic_axes={"input": {0: "batch"}, "logits": {0: "batch"}}, opset_version=17)
    from onnxruntime.quantization import quantize_dynamic, QuantType
    quantize_dynamic(str(fp32), str(OUT / "m4.onnx"), weight_type=QuantType.QInt8,
                     op_types_to_quantize=["MatMul", "Gemm"])
    fp32.unlink(missing_ok=True)
    (OUT / "m4_labels.json").write_text(json.dumps(dataset_m4.LABELS))
    size = round((OUT / "m4.onnx").stat().st_size / 1024, 1)
    report = (f"# M4 prompt-injection classifier\n\n"
              f"- Binary char-CNN, INT8 ONNX ({size} KB). Samples: {n}.\n"
              f"- Detection (injection recall): {detection*100:.2f}%\n"
              f"- False-positive rate (benign flagged): {fpr*100:.2f}%\n")
    (OUT / "m4_report.md").write_text(report)
    print(report)


if __name__ == "__main__":
    main()
