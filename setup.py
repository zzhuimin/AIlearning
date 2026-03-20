from setuptools import setup, find_packages

setup(
    name="openclaw-pure-text-skill",
    version="1.0.0",
    description="OpenClaw JSON嵌套格式转纯文本输出Skill，解决JSON逃逸和格式嵌套问题",
    author="Dev Team",
    author_email="dev@example.com",
    packages=find_packages(),
    install_requires=[
        "json5>=0.9.14",  # 增强JSON解析兼容性
        "regex>=2023.12.25"  # 增强正则处理能力
    ],
    python_requires=">=3.6",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)