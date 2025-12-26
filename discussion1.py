import os
import pandas as pd
import requests
from openai import OpenAI
import time
import json

from sympy.physics.units import temperature


def pure_llm_predict(code, desc):
    prompt = (
        "You are an expert in software vulnerability type classification. "
        "Your task is to infer the CWE type of the target vulnerability based on its source code and description.\n\n"
    )

    prompt += f"Target vulnerability:\n"
    prompt += f"- Code: {code}\n"
    prompt += f"- Description: {desc}\n"

    prompt += f"Output only a single specific CWE ID (e.g., CWE-xxx).\n"
    prompt += f"Do not output any reasoning, explanations, or additional text; only the final label should be returned.\n\n"

    print(prompt)
    # url = "https://yunwu.ai/v1/responses"
    # headers = {
    #     'Accept': 'application/json',
    #     'Authorization': 'Bearer sk-YPUFgtm5fTSaRLmraSHRG37fF4bM0HqrAEW6dcbyOJFvPoto',
    #     'Content-Type': 'application/json'
    # }
    #
    # payload = {
    #     "model": "gpt-5",
    #     "temperature": 0,
    #     "stream": False,
    #     "input": [
    #         {
    #             "role": "system",
    #             "content": "You are an expert in software vulnerability type identification."
    #         },
    #         {
    #             "role": "user",
    #             "content": prompt
    #         }
    #     ]
    # }
    #
    # response = requests.post(url, headers=headers, json=payload)
    # response_json = response.json()
    #
    # # 提取回答内容
    # content = response_json["output"][-1]["content"][0]["text"]
    #
    # return content

    # client = OpenAI(
    #     base_url="https://integrate.api.nvidia.com/v1",
    #     api_key="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"
    # )
    #
    # completion = client.chat.completions.create(
    #     model="meta/llama-3.1-8b-instruct",
    #     messages=[{"role": "user", "content": prompt}],
    #     temperature=0,
    #     stream=False
    # )
    #
    # content = completion.choices[0].message.content
    #
    # return content

    # client = OpenAI(
    #     base_url="https://api.qiyiguo.uk/v1",
    #     api_key="sk-MRL8wIO4dxfGQxKAzzk6zTPpAjWbwi5HMy0Krfjvcl1JFMKu"
    # )
    #
    # completion = client.chat.completions.create(
    #     model="[vt-按量计费]gemini-2.5-pro",
    #     messages=[
    #         {
    #             "role": "system",
    #             "content": "You are an expert in software vulnerability type identification."
    #         },
    #         {
    #             "role": "user",
    #             "content": prompt
    #         }
    #     ],
    #     temperature=0,
    #     stream=False
    # )
    # content = completion.choices[0].message.content
    #
    # return content

    # client = OpenAI(
    #     base_url='https://api-inference.modelscope.cn/v1',
    #     api_key='ms-d7634d70-b5ff-4150-8eb5-f40c171fc6da',  # ModelScope Token
    # )
    #
    # response = client.chat.completions.create(
    #     model='Qwen/Qwen3-Coder-30B-A3B-Instruct',
    #     messages=[
    #         {
    #             'role': 'system',
    #             'content': 'You are an expert in software vulnerability type identification.'
    #         },
    #         {
    #             'role': 'user',
    #             'content': prompt
    #         }
    #     ],
    #     stream=False,
    #     temperature=0
    # )
    # done_reasoning = False
    # content = response.choices[0].message.content

    # return content
    response = requests.post(
        url="https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": "Bearer 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",
            "Content-Type": "application/json"
        },
        data=json.dumps({
            "model": "x-ai/grok-4.1-fast:free",
            "temperature": 0,
            "reasoning": {
                "enabled": False # 禁止 reasoning
             },
            "messages": [
                {
                    "role": "system",
                    "content": "You are an expert AI assistant specialized in software vulnerability classification."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        })
    )
    response_json = response.json()
    content = response_json["choices"][0]["message"]["content"]

    return content


if __name__ == "__main__":
    input_file = "output_dataset/Test_with_ast.csv"
    output_file = "prediction_data/test_predicted_cwe1.csv"
    temp_file = "prediction_data/test_predicted_cwe_temp.csv"


    # output_file_with_set = "prediction_data/test_predicted_cwe_with_set.csv"

    if os.path.exists(output_file):
        df = pd.read_csv(output_file)
        print(f"🔁 继续运行：已加载 {output_file}")
    else:
        df = pd.read_csv(input_file)
        if "Predicted_CWE" not in df.columns:
            df["Predicted_CWE"] = ""
        print(f"🆕 新运行：加载 {input_file}")

    print(df["Predicted_CWE"].unique())
    rows_to_predict = df[
        df["Predicted_CWE"].isna() | (df["Predicted_CWE"].astype(str).str.strip() == "")
        ].index

    if len(rows_to_predict) == 0:
        print("✅ 所有行都已经预测完成！")
    else:
        print(f"🔍 共有 {len(rows_to_predict)} 条样本需要继续预测。")

        for idx in rows_to_predict:
            # time.sleep(3)
            row = df.loc[idx]
            code = row.get("func_before", "")
            desc = row.get("description", "")

            try:
                pred = pure_llm_predict(code, desc)
                print(f"[{idx}] Predicted CWE: {pred} (truth: {row['cwe_id']})")
            except Exception as e:
                print(f"❌ Error at row {idx}: {e}")
                pred = ""

            # 写入预测结果
            df.at[idx, "Predicted_CWE"] = pred

            # 保存到临时文件后再覆盖，防止写入中断损坏
            df.to_csv(temp_file, index=False)
            os.replace(temp_file, output_file)

        print(f"✅ 预测完成，结果已保存到 {output_file}")
