"""第 2 步：训练集编码 -> FAISS 索引 + 实例元数据。

生成（config.INDEX_DIR）：
    faiss_index_code.index   func_before   CodeBERT    768 维
    faiss_index_desc.index   description   text2vec    384 维
    meta.jsonl               每个索引行一条记录：cve_id / cwe_id / 原始文本

AST 不建向量索引：论文 3.3.1 的语法相似度是对 AST 线性化序列做 Levenshtein，
在检索时直接用 meta.jsonl 里的 ast 文本计算（见 retriever.syntax_similarity）。

用法：
    python code/build_index.py [--limit 200]
"""

import argparse
import json
from pathlib import Path

import faiss
import numpy as np
import pandas as pd

import config
from embedder import Encoder

INDEX_FILES = (
    ("code", "faiss_index_code.index"),
    ("desc", "faiss_index_desc.index"),
)


def build(train_csv, index_dir, limit=0):
    frame = pd.read_csv(train_csv, dtype=str, keep_default_na=False, encoding="utf-8-sig")
    if limit and limit > 0:
        frame = frame.head(limit)
    if frame.empty:
        raise ValueError(f"训练集为空: {train_csv}")

    code_encoder = Encoder(config.CODE_MODEL)
    desc_encoder = Encoder(config.DESC_MODEL)
    vectors = {
        "code": code_encoder.encode(frame["func_before"].tolist()),
        "desc": desc_encoder.encode(frame["description"].tolist()),
    }

    target = Path(index_dir)
    target.mkdir(parents=True, exist_ok=True)
    for obsolete in ("faiss_index_ast.index",):        # 旧版 AST 向量索引已不再使用
        (target / obsolete).unlink(missing_ok=True)
    for name, filename in INDEX_FILES:
        matrix = np.ascontiguousarray(vectors[name], dtype="float32")
        index = faiss.IndexFlatL2(matrix.shape[1])
        index.add(matrix)
        faiss.write_index(index, str(target / filename))

    meta_path = target / "meta.jsonl"
    with meta_path.open("w", encoding="utf-8") as handle:
        for row in frame.itertuples(index=False):
            record = {
                "cve_id": row.cve_id,
                "cwe_id": row.cwe_id,
                "func_before": row.func_before,
                "ast": row.ast,
                "description": row.description,
            }
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(f"训练样本 {len(frame)} 行；索引维度 "
          + " / ".join(f"{name}={vectors[name].shape[1]}" for name, _ in INDEX_FILES))
    print(f"索引与元数据 -> {target}")
    return len(frame)


def main(argv=None):
    parser = argparse.ArgumentParser(description="训练集 -> FAISS 索引")
    parser.add_argument("--train-csv", default=str(config.TRAIN_CSV))
    parser.add_argument("--index-dir", default=str(config.INDEX_DIR))
    parser.add_argument("--limit", type=int, default=0, help="只编码前 N 行（0=全部）")
    args = parser.parse_args(argv)
    build(args.train_csv, args.index_dir, args.limit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())