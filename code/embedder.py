"""本地编码器封装（CodeBERT / text2vec），不涉及任何 LLM 或远程 API。

向量口径（论文 3.3.1）：**末层隐状态**按 attention_mask 做掩码平均池化，再 L2 归一化。
归一化后 L2 距离与余弦相似度等价，因此 FAISS 用 IndexFlatL2 即可。
"""

import numpy as np
import torch
from transformers import AutoModel, AutoTokenizer

import config


class Encoder:
    def __init__(self, model_name, max_length=config.MAX_LENGTH,
                 batch_size=config.BATCH_SIZE, device=None):
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.max_length = max_length
        self.batch_size = batch_size
        self.tokenizer = self._load(AutoTokenizer, model_name)
        self.model = self._load(AutoModel, model_name).to(self.device).eval()
        self.dim = int(self.model.config.hidden_size)

    @staticmethod
    def _load(factory, model_name):
        """优先用本地 HF 缓存，缓存缺失时才联网下载。"""
        try:
            return factory.from_pretrained(model_name, local_files_only=True)
        except (OSError, EnvironmentError):
            return factory.from_pretrained(model_name)

    def encode(self, texts):
        """texts: list[str] -> float32 矩阵 [n, dim]，逐行 L2 归一化。"""
        vectors = []
        for start in range(0, len(texts), self.batch_size):
            batch = [t if isinstance(t, str) and t.strip() else "empty"
                     for t in texts[start:start + self.batch_size]]
            inputs = self.tokenizer(batch, padding=True, truncation=True,
                                    max_length=self.max_length,
                                    return_tensors="pt").to(self.device)
            with torch.no_grad():
                hidden = self.model(**inputs, output_hidden_states=True).hidden_states
            last = hidden[-1]                                  # 只用末层（论文 3.3.1）
            mask = inputs["attention_mask"].unsqueeze(-1).to(last.dtype)
            pooled = (last * mask).sum(1) / mask.sum(1).clamp(min=1.0)
            vectors.append(torch.nn.functional.normalize(pooled.float(), dim=-1).cpu().numpy())
        if not vectors:
            return np.zeros((0, self.dim), dtype="float32")
        return np.vstack(vectors).astype("float32")