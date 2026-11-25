"""第 0 步：原始漏洞数据集 -> output_dataset/*.csv（对应旧代码 processing.py + getast.py）。

输入（下载后解压到 datasets1/，也兼容 dataset1/）：
    原始.xlsx   至少含 cve_id / cwe_ids / func_before / description 四列
输出（output_dataset/）：
    Samples.csv / CWE_Proportion.csv
    Train.csv / Val.csv / Test.csv                 无 AST，按 cweid 分层 8:1:1
    Train_with_ast.csv / Val_with_ast.csv / Test_with_ast.csv   追加 ast 列（tree-sitter 线性化 AST）

处理流程与论文 4.2 一致：解析 cwe_ids 取首个标签 -> 去掉 CWE-Other / 空标签 ->
删除 PROHIBITED 类型 -> 样本数 <20 的类型归入 Remain Class -> 分层 8:1:1 -> 生成 AST。

用法：
    python code/build_dataset.py                       # 默认读 datasets1/原始.xlsx
    python code/build_dataset.py --raw datasets1/原始.xlsx --skip-ast
"""

import argparse
import ast as pyast
import re
from pathlib import Path

import pandas as pd

import config
import prepare_data

RAW_COLUMNS = {"cve_id": ("cve_id", "cve", "id"), "cwe_ids": ("cwe_ids", "cwe", "cwe_id"),
               "func_before": ("func_before", "code", "func", "vulnerable_code"),
               "description": ("description", "desc", "vuln_description")}


def find_input(raw_path=None):
    """定位原始数据文件：显式路径 > datasets1/原始.xlsx > dataset1/原始.xlsx > 目录里第一个 xlsx。"""
    if raw_path:
        path = Path(raw_path)
        if not path.is_file():
            raise FileNotFoundError(f"原始数据文件不存在: {path}")
        return path
    for directory in config.RAW_DIRS:
        for name in ("原始.xlsx", "原始.csv", "raw.xlsx"):
            candidate = directory / name
            if candidate.is_file():
                return candidate
        if directory.is_dir():
            batches = sorted(list(directory.glob("*.xlsx")) + list(directory.glob("*.csv")))
            if batches:
                return batches[0]
    raise FileNotFoundError(
        "找不到原始漏洞数据集。请按 README 的 Google Drive 链接下载并解压到 datasets1/，"
        "使 datasets1/原始.xlsx 存在；或用 --raw 指定文件。")


def read_raw(path):
    path = Path(path)
    frame = (pd.read_excel(path) if path.suffix.lower() in (".xlsx", ".xls")
             else pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8-sig"))
    rename = {}
    for target, aliases in RAW_COLUMNS.items():
        if target in frame.columns:
            continue
        for alias in aliases:
            match = next((c for c in frame.columns if str(c).strip().lower() == alias), None)
            if match:
                rename[match] = target
                break
    frame = frame.rename(columns=rename)
    missing = [name for name in ("func_before", "description") if name not in frame.columns]
    if missing:
        raise ValueError(f"原始数据缺少列 {missing}（需要 func_before / description / cwe_ids）")
    if "cwe_ids" not in frame.columns and "cwe_id" not in frame.columns:
        raise ValueError("原始数据缺少 CWE 标签列（cwe_ids 或 cwe_id）")
    return frame


def parse_cwe_ids(value):
    """'[\'CWE-787\', \'CWE-119\']' / 'CWE-787,CWE-119' / 'CWE-787' -> 规范化 CWE 列表。"""
    text = str(value).strip()
    if not text or text.lower() in ("nan", "none"):
        return []
    items = []
    try:
        parsed = pyast.literal_eval(text)
        items = parsed if isinstance(parsed, list) else [parsed]
    except (ValueError, SyntaxError):
        items = [part.strip().strip("'\"") for part in text.strip("[]").split(",") if part.strip()]
    return [label for label in (prepare_data.canonical_label(item) for item in items) if label]


def clean(frame, min_class_samples):
    """论文 4.2 的数据清洗：取首个 CWE、去 Other/空、删 PROHIBITED、稀有类合并。"""
    frame = frame.copy()
    if "cwe_ids" in frame.columns:
        labels = frame["cwe_ids"].apply(parse_cwe_ids)
    else:
        labels = frame["cwe_id"].apply(lambda value: [label for label in
                                                      [prepare_data.canonical_label(value)] if label])
    frame["cwe_id"] = labels.apply(lambda items: items[0] if items else "")
    frame["cwe_id"] = frame["cwe_id"].replace({"CWE-OTHER": ""})
    frame["func_before"] = frame["func_before"].astype(str)
    frame["description"] = frame["description"].astype(str)
    frame = frame[frame["cwe_id"].ne("") & frame["func_before"].str.strip().ne("")
                  & frame["description"].str.strip().ne("")]
    frame = frame[~frame["cwe_id"].isin(config.REMOVED_CWES)]
    frame = frame.drop_duplicates(subset=["func_before", "description"])
    frame, rare = prepare_data.group_rare_classes(frame, min_class_samples)
    if "cve_id" not in frame.columns:
        frame["cve_id"] = ""
    frame["cweid"] = frame["cwe_id"]
    return frame.reset_index(drop=True), rare


def build_parser(language=config.AST_LANGUAGE):
    """tree-sitter 解析器：优先用 pip 语法包（tree-sitter-<lang>）。"""
    try:
        from tree_sitter import Language, Parser
        module = __import__(f"tree_sitter_{language}")
        return Parser(Language(module.language()))
    except Exception as exc:
        raise RuntimeError(
            f"生成 AST 需要 tree-sitter 语法包：pip install tree-sitter tree-sitter-{language}\n"
            "（或在原始数据里直接提供 ast 列、或用 --skip-ast 只产出不带 AST 的 CSV）") from exc


def linearize_ast(parser, code):
    """线性化 AST：tree-sitter 的 s-expression 去掉括号与冒号，得到词元序列。"""
    node = parser.parse(str(code).encode("utf-8", "ignore")).root_node
    text = node.sexp() if hasattr(node, "sexp") else str(node)
    return " ".join(re.sub(r"[:()]", " ", text).split())


def attach_ast(frame, language=config.AST_LANGUAGE):
    if "ast" in frame.columns:
        return frame
    parser = build_parser(language)
    values = []
    for index, code in enumerate(frame["func_before"], 1):
        values.append(linearize_ast(parser, code))
        if index % 200 == 0:
            print(f"  AST {index}/{len(frame)}")
    frame = frame.copy()
    frame["ast"] = values
    return frame


def write_split(frame, directory, name):
    columns = ["cve_id", "func_before", "description", "cwe_id", "cweid"]
    frame[columns].to_csv(directory / f"{name}.csv", index=False, encoding="utf-8-sig")


def main(argv=None):
    parser = argparse.ArgumentParser(description="原始数据集 -> output_dataset/*.csv（含 AST）")
    parser.add_argument("--raw", default=None, help="原始 .xlsx/.csv 路径")
    parser.add_argument("--out-dir", default=str(config.OUTPUT_DATASET_DIR))
    parser.add_argument("--min-class-samples", type=int, default=config.MIN_CLASS_SAMPLES)
    parser.add_argument("--val-ratio", type=float, default=config.VAL_RATIO)
    parser.add_argument("--test-ratio", type=float, default=config.TEST_RATIO)
    parser.add_argument("--seed", type=int, default=config.SEED)
    parser.add_argument("--limit", type=int, default=0, help="只取前 N 行（调试用）")
    parser.add_argument("--skip-ast", action="store_true", help="不生成 AST，只产出不带 ast 列的 CSV")
    parser.add_argument("--language", default=config.AST_LANGUAGE)
    args = parser.parse_args(argv)

    raw_path = find_input(args.raw)
    print(f"原始数据: {raw_path}")
    frame = read_raw(raw_path)
    if args.limit and args.limit > 0:
        frame = frame.head(args.limit)
    frame, rare = clean(frame, args.min_class_samples)
    if len(frame) < 10:
        raise ValueError(f"清洗后只剩 {len(frame)} 行，无法切分")

    directory = Path(args.out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    frame[["cve_id", "func_before", "description", "cwe_id", "cweid"]].to_csv(
        directory / config.SAMPLES_CSV.name, index=False, encoding="utf-8-sig")
    counts = frame["cweid"].value_counts()
    pd.DataFrame({"cweid": counts.index, "proportion": (counts / len(frame)).values}).to_csv(
        directory / config.PROPORTION_CSV.name, index=False, encoding="utf-8-sig")

    train, val, test = prepare_data.stratified_split(frame, args.val_ratio, args.test_ratio, args.seed)
    for name, part in (("Train", train), ("Val", val), ("Test", test)):
        write_split(part, directory, name)

    print(f"清洗后 {len(frame)} 行 / {frame['cweid'].nunique()} 类"
          + (f"（稀有类 {len(rare)} 个归入 Remain Class）" if rare else ""))
    print(f"切分：Train {len(train)} / Val {len(val)} / Test {len(test)} -> {directory}")
    remain = int((frame["cweid"] == config.REMAIN_CLASS).sum())
    print(f"Remain Class {remain} 行（{remain / len(frame) * 100:.2f}%）")

    if not args.skip_ast:
        for name, part in (("Train", train), ("Val", val), ("Test", test)):
            with_ast = attach_ast(part, args.language)
            with_ast.to_csv(directory / f"{name}_with_ast.csv", index=False, encoding="utf-8-sig")
            print(f"  {name}_with_ast.csv：{len(with_ast)} 行（含 ast 列）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())