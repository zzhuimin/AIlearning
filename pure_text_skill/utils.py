import re
import json5 as json  # 使用json5兼容更多格式（如单引号、注释）

def clean_special_chars(text: str) -> str:
    """清洗文本中的特殊字符和格式符号"""
    if not isinstance(text, str):
        text = str(text)
    
    # 移除JSON格式符号、转义字符
    clean_rules = [
        (r'\[\"|\"]|\[\{|\}\]|\[|\]', ''),  # 移除括号和引号
        (r'\\', ''),  # 移除转义符
        (r"{'type': 'text', 'text': '|\"type\": \"text\", \"text\": \"", ''),  # 移除格式包装
        (r"\'|\"", ''),  # 移除残留引号
    ]
    
    for pattern, replace in clean_rules:
        text = re.sub(pattern, replace, text)
    
    return text.strip()

def parse_nested_content(content: str) -> dict | list | str:
    """解析嵌套内容（兼容单引号/双引号JSON）"""
    try:
        # 替换单引号为双引号（兼容Python字典格式）
        content = re.sub(r"(?<!\\)'", '"', content.strip())
        return json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return content