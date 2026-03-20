from pure_text_skill import PureTextOutputSkill

# 初始化Skill
skill = PureTextOutputSkill()

# 模拟OpenClaw原始输出
raw_output = '[{\'type\': \'text\', \'text\': "[{\'type\': \'text\', \'text\': \'测试JSON嵌套逃逸。这个回复应该只包含纯文本，没有JSON结构。\'}]"}]'

# 处理输出
pure_text = skill.process_output(raw_output)

# 输出结果
print("=== 原始输出 ===")
print(raw_output)
print("\n=== 纯文本输出 ===")
print(pure_text)

# ================== OpenClaw集成示例 ==================
def openclaw_chat_output_hook(original_output):
    """
    OpenClaw输出钩子函数
    可直接集成到OpenClaw的聊天输出流程中
    """
    skill = PureTextOutputSkill()
    return skill.process_output(original_output)

# 集成到OpenClaw的示例（替换为实际输出函数）
def send_chat_message_to_client(message):
    """OpenClaw发送消息到客户端的函数"""
    # 调用Skill处理格式
    pure_text_message = openclaw_chat_output_hook(message)
    # 发送纯文本到客户端
    # client.send(pure_text_message)
    return pure_text_message

# 测试集成效果
test_message = send_chat_message_to_client(raw_output)
print("\n=== 集成后输出 ===")
print(test_message)