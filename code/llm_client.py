"""最小 LLM 客户端：OpenAI 兼容 /chat/completions，只做一次请求。

配置来源（后者覆盖前者）：
    1. code/llm_config.json   {"base_url", "api_key", "model", "timeout"}
    2. 环境变量 LITELLM_BASE_URL / LITELLM_API_KEY / LITELLM_MODEL
"""

import json
from pathlib import Path

import requests

import config


def load_config(path=config.LLM_CONFIG_PATH):
    data = {}
    path = Path(path)
    if path.is_file():
        data = json.loads(path.read_text(encoding="utf-8"))
    for key, env in config.LLM_ENV.items():
        value = __import__("os").environ.get(env)
        if value:
            data[key] = value
    missing = [k for k in ("base_url", "api_key", "model") if not str(data.get(k, "")).strip()]
    if missing:
        raise ValueError(
            f"LLM 配置缺少 {missing}。请复制 code/llm_config.example.json 为 code/llm_config.json，"
            "或设置环境变量 LITELLM_BASE_URL / LITELLM_API_KEY / LITELLM_MODEL。")
    data["timeout"] = float(data.get("timeout", 120))
    return data


def chat(messages, *, cfg=None, max_tokens=512, temperature=0.0):
    """返回 assistant 的文本内容；HTTP 失败抛 RuntimeError（已脱敏 api_key）。"""
    cfg = cfg or load_config()
    url = cfg["base_url"].rstrip("/")
    if not url.endswith("/chat/completions"):
        url += "/chat/completions"
    payload = {"model": cfg["model"], "messages": messages,
               "temperature": temperature, "max_tokens": int(max_tokens), "stream": False}
    response = requests.post(
        url, json=payload, timeout=cfg["timeout"],
        headers={"Authorization": f"Bearer {cfg['api_key']}", "Content-Type": "application/json"})
    if not response.ok:
        message = response.text[:500].replace(cfg["api_key"], "[redacted]")
        raise RuntimeError(f"LLM HTTP {response.status_code}: {message}")
    try:
        content = response.json()["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise RuntimeError("LLM 返回结构异常，缺少 choices[0].message.content") from exc
    if not isinstance(content, str) or not content.strip():
        raise RuntimeError("LLM 返回了空内容（检查 max_tokens / thinking 设置）")
    return content.strip()