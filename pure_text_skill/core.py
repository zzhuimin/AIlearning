from typing import Any, Optional
from .utils import clean_special_chars, parse_nested_content

class PureTextOutputSkill:
    """
    OpenClaw 纯文本输出Skill
    核心功能：
    1. 解析嵌套的JSON/字典格式输出
    2. 提取核心纯文本内容
    3. 清洗特殊字符和格式包装
    4. 输出纯文本结果
    """
    
    def __init__(self, target_field: str = "text"):
        """
        初始化Skill
        :param target_field: 需要提取的核心字段名，默认"text"
        """
        self.target_field = target_field

    def _recursive_extract(self, data: Any) -> Optional[str]:
        """递归提取核心文本字段"""
        if isinstance(data, list):
            for item in data:
                result = self._recursive_extract(item)
                if result:
                    return result
        elif isinstance(data, dict):
            # 优先提取目标字段
            if self.target_field in data:
                return clean_special_chars(data[self.target_field])
            # 遍历字典值继续提取
            for value in data.values():
                result = self._recursive_extract(value)
                if result:
                    return result
        elif isinstance(data, str):
            # 字符串先尝试解析为JSON，再提取
            parsed_data = parse_nested_content(data)
            if parsed_data != data:  # 解析成功
                return self._recursive_extract(parsed_data)
            return clean_special_chars(data)
        return None

    def process_output(self, raw_output: Any) -> str:
        """
        处理OpenClaw原始输出，返回纯文本
        :param raw_output: OpenClaw原始输出内容（支持字符串/列表/字典）
        :return: 纯文本字符串
        """
        # 统一解析输入内容
        parsed_content = parse_nested_content(raw_output)
        # 递归提取文本
        pure_text = self._recursive_extract(parsed_content)
        # 兜底：提取失败则返回清洗后的原内容
        return pure_text if pure_text else clean_special_chars(str(raw_output))