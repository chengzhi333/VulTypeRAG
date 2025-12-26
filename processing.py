# coding:utf-8
import os
import re
import ast
import pandas as pd
from sklearn.model_selection import train_test_split

# ================== 配置 ==================
INPUT_XLSX = "datasets1/原始.xlsx"  # 原始 Excel 文件路径
OUTPUT_DIR = "output_dataset"  # 输出目录
COLUMNS_TO_EXTRACT = ["cve_id", "cwe_ids", "func_before", "description"]
MIN_SAMPLES = 20  # 小于该数量的 CWE 会被替换为 Remain Class
TRAIN_RATIO = 0.8
VAL_RATIO = 0.1
TEST_RATIO = 0.1
RANDOM_STATE = 42

# ================== 工具函数 ==================
def ensure_dir(path: str) -> None:
    """确保输出目录存在"""
    if path:
        os.makedirs(path, exist_ok=True)

def parse_cwe_ids(value: str):
    """解析并标准化 CWE ID 列"""
    if not value:
        return []
    text = str(value).strip()
    ids = []
    try:
        parsed = ast.literal_eval(text)
        ids = [str(x) for x in parsed] if isinstance(parsed, list) else [str(parsed)]
    except Exception:
        parts = [p.strip().strip("'\"") for p in text.strip("[]").split(",") if p.strip()]
        ids = parts if parts else [text]

    norm = []
    for cid in ids:
        m = re.search(r"(CWE-)?(\d+)", str(cid), re.IGNORECASE)
        if m:
            norm.append(f"CWE-{m.group(2)}")
    return norm

def choose_primary_cwe(cwe_list):
    """选择首个 CWE 作为主标签"""
    return cwe_list[0] if cwe_list else ""

def sort_by_cwe_group(df, col_name="cweid"):
    """按 CWE 样本数量降序排列，并保证同类样本连续"""
    cwe_order = df[col_name].value_counts().index.tolist()
    df[col_name] = pd.Categorical(df[col_name], categories=cwe_order, ordered=True)
    df_sorted = df.sort_values(col_name).reset_index(drop=True)
    return df_sorted

def move_remain_to_end(dataframe, label_col="cweid"):
    """让 "Remain Class" 排到最后"""
    if "Remain Class" in dataframe[label_col].values:
        remain_df = dataframe[dataframe[label_col] == "Remain Class"]
        other_df = dataframe[dataframe[label_col] != "Remain Class"]
        return pd.concat([other_df, remain_df], ignore_index=True)
    return dataframe

# ================== 分层抽样函数 ==================
def stratified_split(df, label_col="cweid", train_ratio=0.8, val_ratio=0.1, test_ratio=0.1, random_state=42):
    """按标签分层抽样划分 train/val/test"""
    df_train, df_temp = train_test_split(
        df, test_size=(1 - train_ratio), stratify=df[label_col], random_state=random_state
    )
    relative_val_ratio = val_ratio / (val_ratio + test_ratio)
    df_val, df_test = train_test_split(
        df_temp, test_size=(1 - relative_val_ratio), stratify=df_temp[label_col], random_state=random_state
    )
    df_train = sort_by_cwe_group(df_train, label_col)
    df_val = sort_by_cwe_group(df_val, label_col)
    df_test = sort_by_cwe_group(df_test, label_col)
    return df_train, df_val, df_test

# ================== 主流程 ==================
def main():
    print(f"[INFO] 读取 Excel 数据集: {INPUT_XLSX}")
    df = pd.read_excel(INPUT_XLSX)
    print(f"[INFO] 原始数据: {len(df)} 行, {len(df.columns)} 列")

    # 提取指定列
    for col in COLUMNS_TO_EXTRACT:
        if col not in df.columns:
            raise ValueError(f"[ERROR] 缺少列: {col}")
    df = df[COLUMNS_TO_EXTRACT].copy()

    # 解析 CWE
    print("[INFO] 解析并标准化 cwe_ids 列...")
    df["_cwe_list"] = df["cwe_ids"].apply(parse_cwe_ids)

    # 删除空、 CWE-Other
    print("[INFO] 删除空、cwe-other 行...")
    df["_cwe_count"] = df["_cwe_list"].apply(len)
    df = df[
        df["_cwe_list"].apply(lambda x: len(x) > 0 and x[0].upper() != "CWE-OTHER")
    ].copy()

    # 多CWE 取第一个
    df["_cwe_list"] = df["_cwe_list"].apply(lambda x: [x[0]] if len(x) > 0 else [])

    # 生成 cwe_id
    df["cwe_id"] = df["_cwe_list"].apply(choose_primary_cwe)

    # 创建新的 cweid 列，用于替换小样本为 Remain Class
    print(f"[INFO] 创建 cweid 列，小样本 (< {MIN_SAMPLES}) 替换为 'Remain Class' ...")
    cwe_counts = df["cwe_id"].value_counts()
    small_cwes = cwe_counts[cwe_counts < MIN_SAMPLES].index.tolist()
    df["cweid"] = df["cwe_id"].apply(lambda x: "Remain Class" if x in small_cwes else x)

    # 按新的 cweid 排序
    df = sort_by_cwe_group(df, col_name="cweid")

    # 清理临时列
    df = df.drop(columns=["_cwe_list", "_cwe_count"], errors="ignore")

    # 删除禁用 CWE 类型
    REMOVE_CWE = [
        "CWE-399", "CWE-189", "CWE-254", "CWE-19",
        "CWE-388", "CWE-17", "CWE-1187", "CWE-310",
        "CWE-264", "CWE-384", "CWE-273", "CWE-276",
        "CWE-434", "CWE-611", "CWE-552", "CWE-320",
        "CWE-361"
    ]
    before = len(df)
    df = df[~df["cwe_id"].isin(REMOVE_CWE)]
    if isinstance(df["cwe_id"].dtype, pd.CategoricalDtype):
        df["cwe_id"] = df["cwe_id"].cat.remove_unused_categories()
    removed = before - len(df)
    print(f"[INFO] 已删除 {removed} 条指定 CWE 类型数据")

    # 创建输出目录
    ensure_dir(OUTPUT_DIR)

    # 保存 Samples 和比例统计
    df = move_remain_to_end(df)
    df.to_csv(os.path.join(OUTPUT_DIR, "Samples.csv"), index=False)
    total_samples = len(df)
    cwe_proportion = df["cweid"].value_counts().apply(lambda x: x / total_samples).reset_index()
    cwe_proportion.columns = ["cweid", "proportion"]
    cwe_proportion.to_csv(os.path.join(OUTPUT_DIR, "CWE_Proportion.csv"), index=False)

    # 分层抽样
    print("[INFO] 按 CWE 类型分层抽样划分 train/val/test ...")
    df_train, df_val, df_test = stratified_split(df, label_col="cweid",
                                                 train_ratio=TRAIN_RATIO,
                                                 val_ratio=VAL_RATIO,
                                                 test_ratio=TEST_RATIO,
                                                 random_state=RANDOM_STATE)

    # 保存划分后的数据集（CSV）
    df_train = move_remain_to_end(df_train, label_col="cweid")
    df_val = move_remain_to_end(df_val, label_col="cweid")
    df_test = move_remain_to_end(df_test, label_col="cweid")

    df_train.to_csv(os.path.join(OUTPUT_DIR, "Train.csv"), index=False)
    df_val.to_csv(os.path.join(OUTPUT_DIR, "Val.csv"), index=False)
    df_test.to_csv(os.path.join(OUTPUT_DIR, "Test.csv"), index=False)

    print(f"[INFO] 已保存输出文件: {OUTPUT_DIR}")
    print(f"Train: {len(df_train)}, Val: {len(df_val)}, Test: {len(df_test)}")
    print("✅ 处理完成！")

    # 统计 Remain Class 占比
    remain_count = (df["cweid"] == "Remain Class").sum()
    remain_ratio = remain_count / total_samples * 100
    print(f"[INFO] Remain Class 数量: {remain_count} ({remain_ratio:.2f}%)")
    print("✅ 处理完成！")

if __name__ == "__main__":
    main()
