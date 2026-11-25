from dotenv import load_dotenv
from openai import OpenAI
import os
import tiktoken

#OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
load_dotenv()
OPENAI_API_KEY_KTH = os.getenv("OPENAI_API_KEY_KTH")
client = OpenAI(api_key=OPENAI_API_KEY_KTH)

'''
def send_message(messages, append_response=False, verbose=False):
    f = open('logs/context_last_message.json', 'w')
    f.write(str(messages))
    comp = client.chat.completions.create(
        model="gpt-4-1106-preview",
        messages=messages,
        response_format={ "type": "json_object" }
    )

    if append_response:
        messages.append(comp.choices[0].message)

    if verbose:
        print("Reply\n---\n" + comp.choices[0].message.content + '\n---')
    return comp.choices[0].message.content
'''

def load_prompts(directory_path):
    prompts = {}

    # Check if the directory exists
    if not os.path.exists(directory_path):
        print(f"Directory '{directory_path}' does not exist.")
        return prompts

    # Iterate through files in the directory
    for filename in os.listdir(directory_path):
        filepath = os.path.join(directory_path, filename)

        # Check if the item is a file and ends with '.txt'
        if os.path.isfile(filepath) and filename.endswith('.txt'):
            with open(filepath, 'r') as file:
                prompt_text = file.read()
                prompts[filename.split('.')[0]] = prompt_text

    return prompts


def create_message(content, role='user'):
  return {"role": role, "content": content}

def count_tokens(text: str, model: str = "gpt-4", echo=False) -> int:
    """Count tokens for OpenAI models using tiktoken"""
    try:
        encoding = tiktoken.encoding_for_model(model)
        if echo:
            print("Finished encoding using model:", model)
    except KeyError:
        print("invalid input model:", model + ".", "Defaulting to cl100k_base")
        encoding = tiktoken.get_encoding("cl100k_base")  # Fallback for most models
    return len(encoding.encode(text))

def count_chat_tokens(messages, model="gpt-4", echo=False):
    try:
        encoding = tiktoken.encoding_for_model(model)
        if echo:
            print("Finished encoding using model:", model)

    except KeyError:
        print("invalid input model:", model + ".", "Defaulting to cl100k_base")
        encoding = tiktoken.get_encoding("cl100k_base")

    tokens_per_message = 3
    tokens_per_name = 1

    total_tokens = 0
    for msg in messages:
        total_tokens += tokens_per_message
        for key, value in msg.items():
            total_tokens += len(encoding.encode(value))
            if key == "name":
                total_tokens += tokens_per_name
    total_tokens += 3  # priming
    return total_tokens