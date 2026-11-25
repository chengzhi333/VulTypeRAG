"""第 7 步：评估。

分类指标（论文 4.3）：Accuracy、Weighted F1、macro MCC。
若存在 retrieval.csv，同时给出检索诊断：各通道 Recall@k / MRR。

用法：
    python code/evaluate.py [--final data/results/final.csv] [--retrieval data/results/retrieval.csv]
"""

import argparse
import json
import warnings
from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, matthews_corrcoef

import config

CHANNELS = (("instance_candidates", "instance", "实例通道"),
            ("category_candidates", "category", "类别通道"),
            ("candidates", "rrf", "双通道合并"))
KS = (1, 3, 5)


def classification(frame):
    y_true = frame["gold"].str.upper().str.strip()
    y_pred = frame["final"].str.upper().str.strip()
    metrics = {
        "rows": int(len(frame)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "weighted_f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "mcc_overall": float(matthews_corrcoef(y_true, y_pred)),
    }
    per_class = []
    for label in sorted(set(y_true) | set(y_pred)):
        if (y_true == label).all() or (y_pred == label).all():
            continue                                   # 常量列无法计算 MCC
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            per_class.append(matthews_corrcoef((y_true == label), (y_pred == label)))
    metrics["mcc_macro"] = float(sum(per_class) / len(per_class)) if per_class else 0.0
    return metrics


def retrieval(frame):
    frame = frame[frame["gold"].str.startswith("CWE-")]
    report = {"rows": int(len(frame))}
    print(f"\n{'检索通道':<12}{'样本':>6}{'R@1':>9}{'R@3':>9}{'R@5':>9}{'MRR':>9}")
    for column, key, name in CHANNELS:
        ranks = []
        for gold, joined in zip(frame["gold"], frame[column]):
            candidates = [cid for cid in str(joined).split("|") if cid]
            ranks.append(candidates.index(gold) + 1 if gold in candidates else 0)
        total = len(ranks) or 1
        metrics = {f"recall@{k}": sum(1 for r in ranks if 0 < r <= k) / total for k in KS}
        metrics["mrr"] = sum(1.0 / r for r in ranks if r) / total
        report[key] = metrics
        print(f"{name:<12}{len(ranks):>6}{metrics['recall@1']:>9.4f}{metrics['recall@3']:>9.4f}"
              f"{metrics['recall@5']:>9.4f}{metrics['mrr']:>9.4f}")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="分类指标 + 检索诊断")
    parser.add_argument("--final", default=str(config.FINAL_CSV))
    parser.add_argument("--retrieval", default=str(config.RESULT_CSV))
    parser.add_argument("--output", default=str(config.EVAL_JSON))
    args = parser.parse_args(argv)

    report = {}
    final = Path(args.final)
    if final.is_file():
        frame = pd.read_csv(final, dtype=str, keep_default_na=False, encoding="utf-8-sig")
        report["classification"] = classification(frame)
        m = report["classification"]
        print(f"{'分类指标':<12}{'样本':>6}{'ACC':>9}{'F1w':>9}{'MCC':>9}{'MCCmacro':>10}")
        print(f"{'最终预测':<12}{m['rows']:>6}{m['accuracy']:>9.4f}{m['weighted_f1']:>9.4f}"
              f"{m['mcc_overall']:>9.4f}{m['mcc_macro']:>10.4f}")
    else:
        print(f"未找到 {final}，跳过分类指标")

    retrieval_path = Path(args.retrieval)
    if retrieval_path.is_file():
        report["retrieval"] = retrieval(pd.read_csv(retrieval_path, dtype=str,
                                                    keep_default_na=False, encoding="utf-8-sig"))

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n评估结果 -> {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())