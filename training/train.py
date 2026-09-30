"""Train M1, evaluate, and export an INT8-quantized ONNX model.

Outputs into OUT_DIR (default /work/out): m1.onnx (quantized), m1_labels.json,
and m1_report.md. Everything runs on CPU.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import numpy as np
import torch
from torch import nn

from . import dataset
from .encode import MAX_LEN
from .model import CharCNN

OUT = Path(os.environ.get("OUT_DIR", "/work/out"))
SEED = 1337


def _encode_batch(texts):
    from .encode import encode
    return np.array([encode(t) for t in texts], dtype=np.int64)


def _metrics(y_true, y_pred, n_labels):
    # per-class precision/recall + attack-vs-benign detection/FPR (benign=0)
    cm = np.zeros((n_labels, n_labels), dtype=np.int64)
    for t, p in zip(y_true, y_pred):
        cm[t, p] += 1
    per = {}
    for c in range(n_labels):
        tp = cm[c, c]
        prec = tp / cm[:, c].sum() if cm[:, c].sum() else 0.0
        rec = tp / cm[c, :].sum() if cm[c, :].sum() else 0.0
        per[c] = (round(float(prec), 4), round(float(rec), 4))
    attack_true = np.array(y_true) != 0
    attack_pred = np.array(y_pred) != 0
    detected = int((attack_true & attack_pred).sum())
    n_attack = int(attack_true.sum())
    fp = int((~attack_true & attack_pred).sum())
    n_benign = int((~attack_true).sum())
    return per, {
        "detection_rate": round(detected / n_attack, 4) if n_attack else 0.0,
        "false_positive_rate": round(fp / n_benign, 4) if n_benign else 0.0,
        "n_attack": n_attack, "n_benign": n_benign,
    }


def main():
    torch.manual_seed(SEED)
    rows = dataset.build()
    texts = [r[0] for r in rows]
    labels = np.array([r[1] for r in rows], dtype=np.int64)
    X = _encode_batch(texts)
    n = len(X)
    split = int(n * 0.85)
    Xtr, Xte = X[:split], X[split:]
    ytr, yte = labels[:split], labels[split:]

    n_labels = len(dataset.LABELS)
    model = CharCNN(n_labels)
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    lossf = nn.CrossEntropyLoss()

    Xtr_t = torch.from_numpy(Xtr)
    ytr_t = torch.from_numpy(ytr)
    batch = 256
    epochs = 8
    t0 = time.time()
    for ep in range(epochs):
        model.train()
        perm = torch.randperm(len(Xtr_t))
        total = 0.0
        for i in range(0, len(Xtr_t), batch):
            idx = perm[i:i + batch]
            opt.zero_grad()
            out = model(Xtr_t[idx])
            loss = lossf(out, ytr_t[idx])
            loss.backward()
            opt.step()
            total += float(loss) * len(idx)
        print(f"epoch {ep+1}/{epochs} loss={total/len(Xtr_t):.4f}", flush=True)
    train_secs = round(time.time() - t0, 1)

    model.eval()
    with torch.no_grad():
        te_pred = model(torch.from_numpy(Xte)).argmax(1).numpy()
    per, agg = _metrics(yte, te_pred, n_labels)

    # obfuscated robustness split
    obf = dataset.obfuscated_eval()
    Xo = _encode_batch([r[0] for r in obf])
    yo = np.array([r[1] for r in obf])
    with torch.no_grad():
        obf_pred = model(torch.from_numpy(Xo)).argmax(1).numpy()
    _, obf_agg = _metrics(yo, obf_pred, n_labels)

    OUT.mkdir(parents=True, exist_ok=True)
    fp32 = OUT / "m1_fp32.onnx"
    dummy = torch.zeros(1, MAX_LEN, dtype=torch.int64)
    torch.onnx.export(model, dummy, str(fp32), input_names=["input"], output_names=["logits"],
                      dynamic_axes={"input": {0: "batch"}, "logits": {0: "batch"}}, opset_version=17)

    from onnxruntime.quantization import quantize_dynamic, QuantType
    final = OUT / "m1.onnx"
    quantize_dynamic(str(fp32), str(final), weight_type=QuantType.QInt8,
                     op_types_to_quantize=["MatMul", "Gemm"])
    fp32.unlink(missing_ok=True)
    (OUT / "m1_labels.json").write_text(json.dumps(dataset.LABELS))

    # verify the exported int8 model matches on the test set
    import onnxruntime as ort
    sess = ort.InferenceSession(str(final), providers=["CPUExecutionProvider"])
    onnx_pred = sess.run(None, {"input": Xte})[0].argmax(1)
    agree = float((onnx_pred == te_pred).mean())

    size_kb = round(final.stat().st_size / 1024, 1)
    report = [
        "# M1 payload classifier — evaluation",
        "",
        f"- Samples: {n} (train {split}, test {n-split}); labels: {', '.join(dataset.LABELS)}",
        f"- Char-CNN, INT8 ONNX, CPU. Train time: {train_secs}s. Model size: {size_kb} KB.",
        f"- ONNX(int8) vs PyTorch agreement on test set: {round(agree*100,2)}%",
        "",
        "## Held-out test split",
        f"- Detection rate (attack flagged as any attack): {agg['detection_rate']*100:.2f}% (n={agg['n_attack']})",
        f"- False-positive rate (benign flagged as attack): {agg['false_positive_rate']*100:.2f}% (n={agg['n_benign']})",
        "",
        "| class | precision | recall |",
        "|---|---|---|",
    ]
    for c, name in enumerate(dataset.LABELS):
        report.append(f"| {name} | {per[c][0]:.4f} | {per[c][1]:.4f} |")
    report += [
        "",
        "## Obfuscated robustness split (heavy encoding/casing)",
        f"- Detection rate: {obf_agg['detection_rate']*100:.2f}% (n={obf_agg['n_attack']})",
        f"- False-positive rate: {obf_agg['false_positive_rate']*100:.2f}% (n={obf_agg['n_benign']})",
        "",
    ]
    (OUT / "m1_report.md").write_text("\n".join(report))
    print("\n".join(report))
    print(f"\nwrote {final} ({size_kb} KB), m1_labels.json, m1_report.md")


if __name__ == "__main__":
    main()
