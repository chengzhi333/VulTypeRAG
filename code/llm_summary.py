"""第 3 步：LLM 生成漏洞行为摘要（类别通道的 BM25 查询）。

论文 3.3.2：让 LLM 概括漏洞行为的四个方面——关键操作、受影响对象、已知触发条件、
弱点机制——生成的摘要作为 BM25 查询去检索官方 CWE 文本。提示词里**不出现**真实
CWE/CVE 编号、AST 和 CVE 元数据，避免摘要"猜到"答案污染检索评测。

摘要按 (code, description) 内容哈希缓存到 data/behavior_summaries.csv，重跑不重复调用 LLM。

用法：
    python code/llm_summary.py --input data/test.csv [--limit 20] [--workers 4]
"""

import argparse
import hashlib
import json
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd

import config
from llm_client import chat, load_config

SYSTEM_PROMPT = "你负责结合漏洞代码与漏洞描述，提炼简洁、准确的漏洞行为摘要，用于检索官方 CWE 定义。"
USER_TEMPLATE = (
    "用英文撰写一段不超过 {limit} 个单词的漏洞行为摘要。\n\n"
    "结合提供的漏洞代码与漏洞描述，重点提炼以下四方面信息：关键操作、受影响的对象、"
    "已知触发条件、弱点机制。\n\n"
    "不推测缺失信息或建立未经支持的因果关系。直接描述漏洞行为，仅输出摘要段落，"
    "不包含 CWE/CVE 编号、分类结论、修复建议或额外分析。\n\n"
    "漏洞代码：\n{code}\n\n漏洞描述：\n{description}"
)
REPAIR_TEMPLATE = (
    "上一版回答未通过校验：{error}\n"
    "请改写为 {low}-{high} 个英文单词的完整摘要段落，只依据原始代码与描述，"
    "不得出现 CWE/CVE 编号或额外分析。\n\n上一版回答：\n{previous}"
)
CWE_CVE_ID = re.compile(r"\b(?:CWE|CVE)\s*[-:]?\s*\d+", re.IGNORECASE)
CODE_FENCE = re.compile(r"```")
WORD = re.compile(r"[A-Za-z0-9_]+(?:[-'][A-Za-z0-9_]+)*")


def text_digest(*parts):
    return hashlib.sha256(json.dumps(parts, ensure_ascii=False).encode("utf-8")).hexdigest()


def build_messages(code, description, limit=config.SUMMARY_WORD_LIMIT):
    return [{"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": USER_TEMPLATE.format(limit=limit, code=code, description=description)}]


def validate_summary(content):
    """返回 (摘要, 单词数)；不合格抛 ValueError。"""
    if not isinstance(content, str) or not content.strip():
        raise ValueError("The LLM returned an empty summary.")
    text = " ".join(content.split())
    if CWE_CVE_ID.search(text):
        raise ValueError("The summary must not contain CWE/CVE identifiers.")
    if CODE_FENCE.search(text):
        raise ValueError("The summary must not contain code fences.")
    words = WORD.findall(text)
    if not 1 <= len(words) <= config.SUMMARY_WORD_LIMIT:
        raise ValueError(f"Expected 1-{config.SUMMARY_WORD_LIMIT} English words, received {len(words)}.")
    return text, len(words)


def summarize_one(code, description, chat_fn=chat, max_attempts=2):
    """单条摘要生成；首次不合格时带错误信息改写一次。"""
    messages = build_messages(code, description)
    previous, error = "", ""
    for attempt in range(1, max_attempts + 1):
        if attempt > 1:
            messages.append({"role": "assistant", "content": previous})
            messages.append({"role": "user", "content": REPAIR_TEMPLATE.format(
                error=error, low=30, high=40, previous=previous)})
        previous = chat_fn(messages, max_tokens=config.SUMMARY_MAX_TOKENS)
        try:
            summary, words = validate_summary(previous)
            return summary, words, attempt
        except ValueError as exc:
            error = str(exc)
    raise ValueError(f"摘要生成失败：{error}")


def load_cache(path=config.SUMMARY_CSV):
    path = Path(path)
    if not path.is_file():
        return {}
    frame = pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8-sig")
    return {row.input_sha256: row.behavior_summary for row in frame.itertuples(index=False)}


def run(input_csv, output_csv, limit=0, workers=config.SUMMARY_WORKERS, chat_fn=chat, sample_col="func_before"):
    if chat_fn is chat:                      # 缺少配置时立刻报错，而不是逐行失败
        load_config()
    frame = pd.read_csv(input_csv, dtype=str, keep_default_na=False, encoding="utf-8-sig")
    if limit and limit > 0:
        frame = frame.head(limit).copy()
    cache = load_cache(output_csv)
    rows = []
    for position, row in enumerate(frame.itertuples(index=False)):
        code, description = getattr(row, sample_col), row.description
        digest = text_digest(code, description)
        cached = cache.get(digest)
        rows.append({"sample_idx": position, "input_sha256": digest,
                     "behavior_summary": cached or "", "summary_words": "", "status": ""})
    pending = [item for item in rows if not item["behavior_summary"]]
    print(f"行为摘要：{len(rows)} 行，缓存命中 {len(rows) - len(pending)}，待生成 {len(pending)}")

    def work(item):
        code = frame.iloc[item["sample_idx"]][sample_col]
        summary, words, attempts = summarize_one(code, frame.iloc[item["sample_idx"]]["description"], chat_fn)
        return summary, words, attempts

    failed = 0
    if pending:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            for item, future in zip(pending, [pool.submit(work, i) for i in pending]):
                try:
                    summary, words, attempts = future.result()
                    item.update(behavior_summary=summary, summary_words=words, status=f"complete({attempts})")
                except Exception as exc:                       # 失败行留空，可重跑补齐
                    failed += 1
                    item.update(status=f"failed: {type(exc).__name__}")
                    print(f"  [row {item['sample_idx']}] {exc}")
    for item in rows:
        item.setdefault("behavior_summary", "")
        if not item["status"]:
            item["status"] = "cached"
    Path(output_csv).parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(output_csv, index=False, encoding="utf-8-sig")
    print(f"摘要写入 {output_csv}；失败 {failed} 行")
    return len(pending), failed


def main(argv=None):
    parser = argparse.ArgumentParser(description="LLM 行为摘要生成")
    parser.add_argument("--input", default=str(config.TEST_CSV))
    parser.add_argument("--output", default=str(config.SUMMARY_CSV))
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--workers", type=int, default=config.SUMMARY_WORKERS)
    args = parser.parse_args(argv)
    run(args.input, args.output, args.limit, args.workers)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())