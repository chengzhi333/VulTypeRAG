# coding:utf-8
import pandas as pd
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, matthews_corrcoef

# ================== 配置 ==================
# INPUT_CSV = "Discussion/discussion1/grok-4.1-fast/with-code&desc/with-code&descfinal.csv"
INPUT_CSV = "prediction_data/final.csv"
# OUTPUT_CSV = "prediction_data/test_predicted_with_correct_flag.csv"

# 读取数据
df = pd.read_csv(INPUT_CSV)

# 过滤掉 prediction 为空或空字符串的行
df_non_empty = df[df["prediction"].notna() & (df["prediction"].str.strip() != "")].copy()

# 转为大写并去除空格
df_non_empty["cweid"] = df_non_empty["cweid"].str.upper().str.strip()
df_non_empty["prediction"] = df_non_empty["prediction"].str.upper().str.strip()

if df_non_empty.empty:
    print("没有有效预测结果，无法计算指标。")
else:
    actual = df_non_empty["cweid"].tolist()
    predicted = df_non_empty["prediction"].tolist()

    # ===== 应用 Remain Class 判断逻辑 =====
    correct_flags = []
    for gt, pred in zip(actual, predicted):
        if gt == "REMAIN CLASS" and pred != "REMAIN CLASS":
            correct_flags.append(False)
        elif gt != "REMAIN CLASS" and pred == "REMAIN CLASS":
            correct_flags.append(False)
        elif gt != "REMAIN CLASS" and pred != gt:
            correct_flags.append(False)
        else:
            correct_flags.append(True)

    # 将结果写入 DataFrame
    df_non_empty["correct"] = correct_flags

    correct_count = sum(correct_flags)
    wrong_count = len(correct_flags) - correct_count

    print(f"有效预测数量: {len(actual)}")
    print(f"预测正确: {correct_count}  |  预测错误: {wrong_count}")

    # ===== 计算指标 =====
    acc = accuracy_score(actual, predicted)
    precision_ma, recall_ma, f1_ma, _ = precision_recall_fscore_support(
        actual, predicted, average='macro', zero_division=0
    )
    mcc = matthews_corrcoef(actual, predicted)

    print(f"\nAccuracy: {acc:.4f}")
    print(f"Precision (Macro): {precision_ma:.4f}")
    print(f"Recall (Macro): {recall_ma:.4f}")
    print(f"F1-score (Macro): {f1_ma:.4f}")
    print(f"MCC: {mcc:.4f}")

    # Weighted
    precision_w, recall_w, f1_w, _ = precision_recall_fscore_support(
        actual, predicted, average='weighted', zero_division=0
    )

    print(f"\nPrecision (Weighted): {precision_w:.4f}")
    print(f"Recall (Weighted): {recall_w:.4f}")
    print(f"F1-score (Weighted): {f1_w:.4f}")

    # 保存文件
    # df_non_empty.to_csv(OUTPUT_CSV, index=False)
    # print(f"\n处理完成，新文件已保存为: {OUTPUT_CSV}")
