"""Fixed char-level encoding shared by training and the engine.

The vocabulary is fixed (not learned) so the training and inference paths agree
without shipping a vocab file: index 0 is padding, 1 is unknown, and every other
printable byte maps to a stable index. Inputs are truncated/padded to MAX_LEN.
"""

from __future__ import annotations

MAX_LEN = 256
# Printable ASCII plus tab/newline; order is fixed and must never be reordered.
_CHARS = "".join(chr(c) for c in range(32, 127)) + "\t\n"
_STOI = {ch: i + 2 for i, ch in enumerate(_CHARS)}  # 0=pad, 1=unk
VOCAB_SIZE = len(_CHARS) + 2


def encode(text: str, max_len: int = MAX_LEN) -> list[int]:
    ids = [_STOI.get(ch, 1) for ch in text[:max_len]]
    if len(ids) < max_len:
        ids += [0] * (max_len - len(ids))
    return ids

