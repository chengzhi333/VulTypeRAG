import re
import pandas as pd

# file_path = "prediction_data/60-40.csv"
file_path = "prediction_data/test_predicted_cwe1.csv"
df = pd.read_csv(file_path)

# 原始
allowed_cwe_set = {
    'CWE-787', 'CWE-125', 'CWE-476', 'CWE-119', 'CWE-416', 'CWE-20',
    'CWE-190', 'CWE-362', 'CWE-120', 'CWE-200', 'CWE-400', 'CWE-401',
    'CWE-617', 'CWE-835', 'CWE-415', 'CWE-772', 'CWE-369', 'CWE-674',
    'CWE-22', 'CWE-122', 'CWE-834', 'CWE-770', 'CWE-908', 'CWE-295',
    'CWE-74', 'CWE-284', 'CWE-404', 'CWE-287', 'CWE-78', 'CWE-79',
    'CWE-732', 'CWE-909', 'CWE-269', 'CWE-667', 'CWE-59', 'CWE-843',
    'CWE-459', 'CWE-863', 'CWE-681', 'CWE-252', 'CWE-193', 'CWE-704',
    'CWE-862', 'CWE-755', 'CWE-668', 'CWE-367', 'CWE-330', 'CWE-754',
    'CWE-89', 'CWE-203', 'CWE-1284', 'CWE-327', 'CWE-354', 'CWE-134',
    'CWE-129', 'CWE-763', 'CWE-665', 'CWE-682', 'CWE-824', 'CWE-77',
    'CWE-502', 'CWE-121', 'CWE-131', 'CWE-697', 'CWE-436', 'CWE-326',
    'CWE-345'
}

# 规范为大写集合以便比较
allowed_cwe_upper = {s.upper() for s in allowed_cwe_set}

# 提取 Predicted_CWE 中第一个 CWE-数字（如果有），并返回大写形式
cwe_pattern = re.compile(r'(CWE-\d+)', flags=re.IGNORECASE)
def extract_first_cwe(s: str):
    if not isinstance(s, str):
        return ""
    m = cwe_pattern.search(s)
    return m.group(1).upper() if m else ""

# 判定函数
def classify_row(row):
    raw_cweid = "" if pd.isna(row.get('cweid')) else str(row.get('cweid')).strip()
    raw_pred = "" if pd.isna(row.get('Predicted_CWE')) else str(row.get('Predicted_CWE')).strip()

    # 规范判断是否为 Remain Class：去掉空格并大写后比对
    if re.sub(r'\s+', '', raw_cweid).upper() == "REMAINCLASS":
        extracted = extract_first_cwe(raw_pred)
        # 如果提取出的 CWE 在允许集合内，保留原始 Predicted_CWE（原样写入）
        if extracted and extracted in allowed_cwe_upper:
            return raw_pred
        else:
            # 不在允许集合或无法提取出 CWE -> 写为 Remain Class
            return "Remain Class"
    else:
        # 非 Remain Class 行，直接写原始 Predicted_CWE
        return raw_pred

# 应用
df['prediction'] = df.apply(classify_row, axis=1)

# 保存结果
output_file = "prediction_data/final.csv"
df.to_csv(output_file, index=False)

# 打印统计信息，便于确认
total = len(df)
remain_rows = df['cweid'].astype(str).apply(lambda x: re.sub(r'\s+','',x).upper() == "REMAINCLASS").sum()
changed_to_remain = ((df['cweid'].astype(str).apply(lambda x: re.sub(r'\s+','',x).upper() == "REMAINCLASS")) & (df['prediction'] == "Remain Class")).sum()
kept_predictions = ((df['cweid'].astype(str).apply(lambda x: re.sub(r'\s+','',x).upper() == "REMAINCLASS")) & (df['prediction'] != "Remain Class")).sum()

print(f"Total rows: {total}")
print(f"Rows with cweid == Remain Class: {remain_rows}")
print(f"Among those, rows set to 'Remain Class' in prediction: {changed_to_remain}")
print(f"Among those, rows kept Predicted_CWE in prediction: {kept_predictions}")
print(f"Output saved to: {output_file}")
