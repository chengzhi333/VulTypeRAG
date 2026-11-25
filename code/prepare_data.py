"""第 1 步：数据处理（论文 4.2）。

读原始 CSV（func_before / description / ast / cwe_id）→ 清洗（去空样本、统一 CWE 标签、
去重）→ 稀有类合并（样本数 < MIN_CLASS_SAMPLES 的 CWE 类型归入 Remain Class）→
按类别分层的 8:1:1 切分 → 导出训练集标签空间。

用法：
    python code/prepare_data.py --input output_dataset/Train_with_ast.csv
    python code/prepare_data.py --input RQ2/0-100/0-100.csv --limit 300 --min-class-samples 5
"""

import argparse
import json
import re
from pathlib import Path

import pandas as pd

import config

CWE_RE = re.compile(r"(?:CWE[-\s:]*)?(\d+)", re.IGNORECASE)
CWE_ANY = re.compile(r"CWE-\d+")


def canonical_label(value):
    """'CWE-787' / 'cwe 787' / '787' -> 'CWE-787'；其它（如 Remain Class）-> None。"""
    match = CWE_RE.fullmatch(str(value).strip())
    return f"CWE-{int(match[1])}" if match and int(match[1]) > 0 else None


def pick_label(row):
    """优先 cwe_id，其次 cweid；两者都不存在时才从 cwe_ids 列表里取第一个 CWE。

    注意：build_dataset.py 已经把稀有类合并成 Remain Class，此时 cwe_ids 列仍保留原始
    CWE 列表 —— 所以只要存在 cwe_id/cweid 列，就不再看 cwe_ids，避免把 Remain Class 还原。
    """
    for column in ("cwe_id", "cweid"):
        if column in row.index and str(row.get(column, "")).strip():
            found = CWE_ANY.findall(str(row.get(column)).upper())
            return (canonical_label(found[0]) if found else None) or config.REMAIN_CLASS
    found = CWE_ANY.findall(str(row.get("cwe_ids", "")).upper())
    return canonical_label(found[0]) if found else config.REMAIN_CLASS


def load_rows(path):
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(
            f"数据文件不存在: {path}\n"
            "请先从 README 里的 Google Drive 链接下载数据集，放到 output_dataset/ 下，"
            "或用 --input 指定 CSV 路径（需含 func_before / description / ast / cwe_id 四列）。")
    frame = pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8-sig")
    missing = [c for c in ("func_before", "description", "ast") if c not in frame.columns]
    if missing:
        raise ValueError(f"{path} 缺少列: {missing}；需要 func_before/description/ast/cwe_id")
    for column in ("func_before", "description", "ast"):
        frame = frame[frame[column].str.strip().ne("")]
    frame = frame.drop_duplicates(subset=["func_before", "description"]).copy()
    frame["cwe_id"] = frame.apply(pick_label, axis=1)
    if "cve_id" not in frame.columns:
        frame["cve_id"] = ""
    return frame[list(config.CSV_COLUMNS)].reset_index(drop=True)


def group_rare_classes(frame, min_samples=config.MIN_CLASS_SAMPLES):
    """论文 4.2：样本数少于 min_samples 的 CWE 类型统一记为 Remain Class。"""
    counts = frame["cwe_id"].value_counts()
    rare = {label for label in counts.index
            if label != config.REMAIN_CLASS and counts[label] < min_samples}
    if rare:
        frame.loc[frame["cwe_id"].isin(rare), "cwe_id"] = config.REMAIN_CLASS
    return frame, sorted(rare, key=lambda cid: int(cid.split("-")[-1]))


def stratified_split(frame, val_ratio=config.VAL_RATIO, test_ratio=config.TEST_RATIO,
                     seed=config.SEED):
    """按 cwe_id 分层切分；样本数不足以同时进三个集合的类全部进训练集。"""
    parts = {"train": [], "val": [], "test": []}
    for _, group in frame.groupby("cwe_id", sort=True):
        shuffled = group.sample(frac=1.0, random_state=seed)
        total = len(shuffled)
        n_val = int(round(total * val_ratio))
        n_test = int(round(total * test_ratio))
        if total - n_val - n_test < 1:
            n_val = n_test = 0
        parts["val"].append(shuffled.iloc[:n_val])
        parts["test"].append(shuffled.iloc[n_val:n_val + n_test])
        parts["train"].append(shuffled.iloc[n_val + n_test:])
    merged = {name: (pd.concat(chunks).sample(frac=1.0, random_state=seed).reset_index(drop=True)
                     if chunks else frame.iloc[0:0])
              for name, chunks in parts.items()}
    return merged["train"], merged["val"], merged["test"]


def main(argv=None):
    parser = argparse.ArgumentParser(description="准备训练/测试数据 + 标签空间")
    parser.add_argument("--input", default="", help="单个 CSV：自动清洗 + 稀有类合并 + 8:1:1 切分")
    parser.add_argument("--train", default=str(config.TRAIN_WITH_AST), help="已切分的训练集")
    parser.add_argument("--val", default=str(config.VAL_WITH_AST), help="已切分的验证集（可选）")
    parser.add_argument("--test", default=str(config.TEST_WITH_AST), help="已切分的测试集")
    parser.add_argument("--train-csv", default=str(config.TRAIN_CSV))
    parser.add_argument("--val-csv", default=str(config.VAL_CSV))
    parser.add_argument("--test-csv", default=str(config.TEST_CSV))
    parser.add_argument("--label-space", default=str(config.LABEL_SPACE_JSON))
    parser.add_argument("--val-ratio", type=float, default=config.VAL_RATIO)
    parser.add_argument("--test-ratio", type=float, default=config.TEST_RATIO)
    parser.add_argument("--min-class-samples", type=int, default=config.MIN_CLASS_SAMPLES)
    parser.add_argument("--limit", type=int, default=0, help="单文件模式下清洗后随机抽取 N 行（0=全部）")
    parser.add_argument("--seed", type=int, default=config.SEED)
    args = parser.parse_args(argv)

    if args.input:                                   # 单文件：清洗 + 稀有类合并 + 切分
        frame = load_rows(args.input)
        if args.limit and args.limit > 0:
            frame = frame.sample(n=min(args.limit, len(frame)), random_state=args.seed)
        if len(frame) < 10:
            raise ValueError(f"有效样本只有 {len(frame)} 行，不足以切分")
        frame, rare = group_rare_classes(frame, args.min_class_samples)
        train, val, test = stratified_split(frame, args.val_ratio, args.test_ratio, args.seed)
        splits = {"train": train, "val": val, "test": test, "source": str(args.input)}
    else:                                            # 已切分：直接用 output_dataset/*_with_ast.csv
        train_path = Path(args.train)
        test_path = Path(args.test)
        if not train_path.is_file() or not test_path.is_file():
            raise FileNotFoundError(
                f"找不到数据集 {train_path} / {test_path}。\n"
                "先运行 python code/build_dataset.py（原始数据在 datasets1/），"
                "或用 --train / --test 指定已切分的 CSV。")
        train = load_rows(train_path)
        test = load_rows(test_path)
        val = load_rows(args.val) if Path(args.val).is_file() else None
        rare = []
        splits = {"train": train, "val": val, "test": test,
                  "source": f"{train_path.name} + {test_path.name}"}

    for path, part in ((args.train_csv, train), (args.val_csv, splits["val"]), (args.test_csv, test)):
        if part is None:
            continue
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        part.to_csv(path, index=False, encoding="utf-8-sig")

    labels = train["cwe_id"]
    counts = labels[labels.str.startswith("CWE-")].value_counts().to_dict()
    space = {
        "cwe_ids": sorted(counts, key=lambda cid: int(cid.split("-")[-1])),
        "counts": counts,
        "remain_class_rows": int((train["cwe_id"] == config.REMAIN_CLASS).sum()),
    }
    Path(args.label_space).write_text(json.dumps(space, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"数据来源 {splits['source']}")
    if rare:
        print(f"稀有类（<{args.min_class_samples} 样本）{len(rare)} 个已归入 {config.REMAIN_CLASS}: "
              + ", ".join(rare[:8]) + (" ..." if len(rare) > 8 else ""))
    print(f"训练 {len(train)} / 验证 {0 if splits['val'] is None else len(splits['val'])} / 测试 {len(test)}")
    print(f"标签空间 {len(space['cwe_ids'])} 个 CWE（训练集）-> {args.label_space}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())