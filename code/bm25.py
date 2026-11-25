"""类别通道：CWE 节点文本上的 Okapi BM25（纯词法，不需要模型）。"""

import re
from collections import Counter

import numpy as np

TOKEN = re.compile(r"[a-z0-9]+")


def tokenize(text):
    """小写 + 按字母数字切分，让 'out-of-bounds' 与 'out of bounds' 得到相同词元。"""
    return TOKEN.findall(str(text).lower())


class BM25Index:
    def __init__(self, ids, texts, k1=1.5, b=0.75):
        if not ids or len(ids) != len(texts):
            raise ValueError("ids 与 texts 必须等长且非空")
        self.ids = list(ids)
        self.k1, self.b = float(k1), float(b)

        docs = [tokenize(text) for text in texts]
        total = len(docs)
        average = max(sum(len(doc) for doc in docs) / total, 1e-9)

        df = Counter()
        for doc in docs:
            df.update(set(doc))                      # 文档频率
        idf = {t: float(np.log((total - n + 0.5) / (n + 0.5) + 1.0)) for t, n in df.items()}

        # 倒排表：词元 -> (文档行号数组, 该项得分数组)
        postings = {}
        for row, doc in enumerate(docs):
            for token, freq in Counter(doc).items():
                weight = freq * (self.k1 + 1) / (
                    freq + self.k1 * (1 - self.b + self.b * len(doc) / average))
                rows, weights = postings.setdefault(token, ([], []))
                rows.append(row)
                weights.append(weight * idf[token])
        self.postings = {t: (np.asarray(rows), np.asarray(weights))
                         for t, (rows, weights) in postings.items()}

    def score(self, query):
        scores = np.zeros(len(self.ids))
        for token in set(tokenize(query)):
            posting = self.postings.get(token)
            if posting is not None:
                scores[posting[0]] += posting[1]
        return scores

    def search(self, query, topk=3, allowed=None):
        """按 BM25 得分降序取 topk；同分按 CWE 编号排序，保证可复现。"""
        scores = self.score(query)
        order = sorted(range(len(self.ids)),
                       key=lambda i: (-scores[i], int(self.ids[i].split("-")[-1])))
        results = []
        for row in order:
            cwe_id = self.ids[row]
            if allowed is not None and cwe_id not in allowed:
                continue
            results.append({"cwe_id": cwe_id, "score": float(scores[row])})
            if len(results) >= topk:
                break
        return results