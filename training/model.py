"""Small char-level CNN for payload classification (CPU-friendly)."""

from __future__ import annotations

import torch
from torch import nn

from .encode import MAX_LEN, VOCAB_SIZE


class CharCNN(nn.Module):
    def __init__(self, num_labels: int, embed_dim: int = 24, channels: int = 64,
                 kernels: tuple[int, ...] = (3, 5, 7)):
        super().__init__()
        self.embed = nn.Embedding(VOCAB_SIZE, embed_dim, padding_idx=0)
        self.convs = nn.ModuleList(
            [nn.Conv1d(embed_dim, channels, k, padding=k // 2) for k in kernels]
        )
        self.dropout = nn.Dropout(0.3)
        self.fc1 = nn.Linear(channels * len(kernels), 64)
        self.fc2 = nn.Linear(64, num_labels)

    def forward(self, x):                       # x: (batch, MAX_LEN) int64
        e = self.embed(x).transpose(1, 2)       # (batch, embed, len)
        pooled = [torch.relu(conv(e)).max(dim=2).values for conv in self.convs]
        h = torch.cat(pooled, dim=1)            # (batch, channels*len(kernels))
        h = torch.relu(self.fc1(self.dropout(h)))
        return self.fc2(h)                       # logits (batch, num_labels)


def input_length() -> int:
    return MAX_LEN
