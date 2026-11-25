"""第 4 步：双通道检索 + CWE 知识图谱上下文。

实例通道
    code / ast / desc 三路编码 -> FAISS 粗召回(2*TOPK) -> Jaccard + AST 余弦重排
    -> 与描述通道结果取并集 -> 0.6*代码余弦 + 0.4*描述余弦 排序取 TOPK
类别通道
    BM25 查询串用 LLM 行为摘要（llm_summary.py 产出的缓存），缺失时退回 description
候选融合
    两通道按 CWE 去重合并（实例候选在前、类别候选按 BM25 顺序追加），再从 CWE 知识图谱
    取候选定义 + 祖先链
输出
    results/retrieval.csv（逐样本候选）与 data/context.jsonl（供 classify.py 做 4 步 CoT）

用法：
    python code/retriever.py [--limit 20]
"""

import argparse
import json
import re
from pathlib import Path

import faiss
import numpy as np
import pandas as pd

import config
import llm_summary
from bm25 import BM25Index
from cwe_graph import CWEGraph
from embedder import Encoder

WORD = re.compile(r"[a-z0-9_]+")


def jaccard(left, right):
    a, b = set(WORD.findall(str(left).lower())), set(WORD.findall(str(right).lower()))
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def ast_tokens(text, cap=config.AST_MAX_TOKENS):
    """AST 线性化序列（空白分隔的节点类型），按前 cap 个词元截断以控制编辑距离开销。"""
    return str(text).split()[:cap]


try:                                      # 可选：C++ 实现的编辑距离（比 numpy DP 再快一个量级）
    from rapidfuzz.distance import Levenshtein as _Levenshtein
except ImportError:                       # pragma: no cover - 未安装时走 numpy 实现
    _Levenshtein = None


def levenshtein(left, right):
    """两个词元 id 序列的编辑距离；有 rapidfuzz 用它，否则用 numpy 前缀最小值 DP。"""
    if _Levenshtein is not None:
        return int(_Levenshtein.distance(left, right))
    n, m = len(left), len(right)
    if n == 0 or m == 0:
        return max(n, m)
    # DP 行内递推 cur[j] = j + min_{k<=j}(h[k] - k)，前缀最小值可整行向量化
    previous = np.arange(m + 1)
    for i in range(1, n + 1):
        cost = (right != left[i - 1])
        candidate = np.minimum(previous[1:] + 1, previous[:-1] + cost)
        prefix = np.empty(m + 1)
        prefix[0] = i
        prefix[1:] = candidate - np.arange(1, m + 1)
        previous = np.minimum.accumulate(prefix) + np.arange(m + 1)
    return int(previous[-1])


def syntax_similarity(left_ids, right_ids):
    """论文式 (4)：SynSim = 1 - lev(A, B) / max(len(A), len(B))。"""
    if not len(left_ids) or not len(right_ids):
        return 0.0
    return 1.0 - levenshtein(left_ids, right_ids) / max(len(left_ids), len(right_ids))


def merge_candidates(instance, category, allowed=None):
    """论文 3.3.3 的候选融合：按 CWE ID 去重，实例通道候选按首次出现顺序在前，
    类别通道新增候选按 BM25 排名顺序追加，并标注来源（两通道都有则 sources 含两项）。"""
    merged, position = [], {}
    for name, items in (("instance", instance), ("category", category)):
        for item in items:
            cwe_id = item["cwe_id"]
            if allowed is not None and cwe_id not in allowed:
                continue
            index = position.get(cwe_id)
            if index is None:
                position[cwe_id] = len(merged)
                merged.append({"cwe_id": cwe_id, "sources": [name], "score": item.get("score"),
                               "instance_rank": None, "category_rank": None})
                index = len(merged) - 1
            elif name not in merged[index]["sources"]:
                merged[index]["sources"].append(name)
            merged[index][f"{name}_rank"] = item.get("rank")
    return [dict(item, rank=rank) for rank, item in enumerate(merged, 1)]


class DualChannelRetriever:
    def __init__(self, index_dir=config.INDEX_DIR, graph_path=config.CWE_JSON,
                 label_space_path=config.LABEL_SPACE_JSON):
        self.index_dir = Path(index_dir)
        self.meta = [json.loads(line) for line in
                     (self.index_dir / "meta.jsonl").open(encoding="utf-8")]
        self.code_index = faiss.read_index(str(self.index_dir / "faiss_index_code.index"))
        self.desc_index = faiss.read_index(str(self.index_dir / "faiss_index_desc.index"))
        if not (len(self.meta) == self.code_index.ntotal == self.desc_index.ntotal):
            raise ValueError("索引行数与 meta.jsonl 不一致，请重新 build_index")
        # AST 词元先编码成整数 id，Levenshtein 只比较整数；词表随查询扩展，id 保持稳定
        self.vocab = {}
        self.ast_ids = [self._token_ids(ast_tokens(record["ast"])) for record in self.meta]

        self.graph = CWEGraph(graph_path)
        label_space = Path(label_space_path)
        self.label_space = (json.loads(label_space.read_text(encoding="utf-8"))["cwe_ids"]
                            if label_space.is_file() else self.graph.cwe_ids)
        self.allowed = set(self.label_space)

        self.code_encoder = Encoder(config.CODE_MODEL)
        self.desc_encoder = Encoder(config.DESC_MODEL)
        # 论文 3.3.2：类别通道文档 = CWE 名称 + 描述
        self.bm25 = BM25Index(self.graph.cwe_ids,
                              [self.graph.bm25_text(cid) for cid in self.graph.cwe_ids],
                              config.BM25_K1, config.BM25_B)

    def encode_queries(self, codes, descriptions):
        return {
            "code": self.code_encoder.encode(codes),
            "desc": self.desc_encoder.encode(descriptions),
        }

    def _token_ids(self, tokens):
        return np.asarray([self.vocab.setdefault(token, len(self.vocab)) for token in tokens],
                          dtype=np.int32)

    def instance_channel(self, code, ast, query, topk=config.TOPK):
        recall = min(config.CODE_RECALL, len(self.meta))
        _, rows = self.code_index.search(query["code"][None, :], recall)

        query_ast = self._token_ids(ast_tokens(ast))
        candidates = []
        for row in rows[0]:
            if row < 0:
                continue
            lexical = jaccard(code, self.meta[row]["func_before"])
            syntax = syntax_similarity(query_ast, self.ast_ids[int(row)])
            # 论文式 (6)：CodeSim = λ·SynSim + (1-λ)·LexSim
            code_sim = config.SYNTAX_W * syntax + config.LEXICAL_W * lexical
            candidates.append((code_sim, int(row)))
        candidates.sort(key=lambda item: (-item[0], item[1]))
        top_code = [row for _, row in candidates[:topk]]

        _, desc_rows = self.desc_index.search(query["desc"][None, :], min(topk, len(self.meta)))
        union = list(dict.fromkeys(top_code + [int(r) for r in desc_rows[0] if r >= 0]))

        results = []
        for row in union:
            # 论文式 (7)：Sim = φ·CodeSim + (1-φ)·DescSim
            code_sim = (config.SYNTAX_W * syntax_similarity(query_ast, self.ast_ids[row])
                        + config.LEXICAL_W * jaccard(code, self.meta[row]["func_before"]))
            desc_sim = float(query["desc"] @ self.desc_index.reconstruct(row))
            score = config.CODE_FUSE_W * code_sim + config.DESC_FUSE_W * desc_sim
            record = self.meta[row]
            results.append({"cwe_id": record["cwe_id"], "cve_id": record["cve_id"],
                            "row": row, "score": score})
        results.sort(key=lambda item: (-item["score"], item["row"]))
        return [dict(item, rank=rank, score=round(item["score"], 6))
                for rank, item in enumerate(results[:topk], 1)]

    def category_channel(self, query, topk=config.CWE_TOPK):
        hits = self.bm25.search(query, topk=topk, allowed=self.allowed)
        return [dict(hit, rank=rank, score=round(hit["score"], 6))
                for rank, hit in enumerate(hits, 1)]

    def retrieve(self, code, description, ast, query=None, summary=None):
        if query is None:
            batch = self.encode_queries([code], [description])
            query = {name: matrix[0] for name, matrix in batch.items()}
        instance = self.instance_channel(code, ast, query)
        query_text = summary or description       # 类别通道：行为摘要优先
        category = self.category_channel(query_text)
        merged = merge_candidates(instance, category, self.allowed)
        return {"instance": instance, "category": category, "candidates": merged,
                "summary": summary or "", "category_query": query_text}


def build_context(row, result, graph, retriever):
    """把一次检索结果整理成 4 步 CoT 需要的完整上下文。"""
    samples = []
    for item in result["instance"]:
        record = retriever.meta[item["row"]]
        samples.append({
            "cve_id": record["cve_id"], "cwe_id": record["cwe_id"], "score": item["score"],
            "patch": graph.patch_text(record["cwe_id"]),
            "code": record["func_before"], "description": record["description"],
        })
    knowledge = graph.collect_knowledge([item["cwe_id"] for item in result["candidates"]])
    return {
        "sample_idx": row.Index,
        "cve_id": getattr(row, "cve_id", ""),
        "gold": getattr(row, "cwe_id", ""),
        "code": row.func_before,
        "description": row.description,
        "behavior_summary": result["summary"],
        "category_query": result["category_query"],
        "samples": samples,
        "instance_candidates": result["instance"],
        "category_candidates": result["category"],
        "candidates": result["candidates"],
        **knowledge,
    }


def _join(items):
    return "|".join(item["cwe_id"] for item in items)


def main(argv=None):
    parser = argparse.ArgumentParser(description="双通道检索 + 知识图谱上下文")
    parser.add_argument("--input", default=str(config.TEST_CSV))
    parser.add_argument("--output", default=str(config.RESULT_CSV))
    parser.add_argument("--context-out", default=str(config.CONTEXT_JSONL))
    parser.add_argument("--summaries", default=str(config.SUMMARY_CSV))
    parser.add_argument("--index-dir", default=str(config.INDEX_DIR))
    parser.add_argument("--cwe-json", default=str(config.CWE_JSON))
    parser.add_argument("--label-space", default=str(config.LABEL_SPACE_JSON))
    parser.add_argument("--limit", type=int, default=0, help="只检索前 N 行（0=全部）")
    args = parser.parse_args(argv)

    frame = pd.read_csv(args.input, dtype=str, keep_default_na=False, encoding="utf-8-sig")
    if args.limit and args.limit > 0:
        frame = frame.head(args.limit).copy()
    if frame.empty:
        raise ValueError(f"测试集为空: {args.input}")

    retriever = DualChannelRetriever(args.index_dir, args.cwe_json, args.label_space)
    summaries = llm_summary.load_cache(args.summaries)
    print(f"行为摘要缓存 {len(summaries)} 条（{args.summaries}）")
    queries = retriever.encode_queries(frame["func_before"].tolist(),
                                       frame["description"].tolist())

    output_rows, contexts = [], []
    for position, row in enumerate(frame.itertuples(index=True)):
        single = {name: matrix[position] for name, matrix in queries.items()}
        summary = summaries.get(llm_summary.text_digest(row.func_before, row.description))
        result = retriever.retrieve(row.func_before, row.description, row.ast,
                                    query=single, summary=summary)
        context = build_context(row, result, retriever.graph, retriever)
        contexts.append(context)
        output_rows.append({
            "sample_idx": position,
            "cve_id": context["cve_id"],
            "gold": context["gold"],
            "candidates": _join(result["candidates"]),
            "instance_candidates": _join(result["instance"]),
            "category_candidates": _join(result["category"]),
            "top1": result["candidates"][0]["cwe_id"] if result["candidates"] else "",
            "top1_sources": ",".join(result["candidates"][0]["sources"]) if result["candidates"] else "",
            "behavior_summary": result["summary"],
        })
        if (position + 1) % 10 == 0:
            print(f"  已检索 {position + 1}/{len(frame)}")

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(output_rows).to_csv(output, index=False, encoding="utf-8-sig")

    context_path = Path(args.context_out)
    context_path.parent.mkdir(parents=True, exist_ok=True)
    with context_path.open("w", encoding="utf-8") as handle:
        for context in contexts:
            handle.write(json.dumps(context, ensure_ascii=False) + "\n")
    print(f"检索完成 {len(output_rows)} 行 -> {output}；CoT 上下文 -> {context_path}")
    print(f"类别通道语料 {len(retriever.graph.cwe_ids)} 个节点；标签空间 {len(retriever.label_space)} 个 CWE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())