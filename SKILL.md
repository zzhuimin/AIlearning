# RustScan Port Scanner Skill

一个基于 RustScan 的高速端口扫描 OpenClaw Skill，可在几秒钟内完成全端口扫描，并支持自动调用 Nmap 进行深度分析。

## 功能特性

- **极速扫描**：基于 Rust 异步引擎，扫描 65,535 个端口仅需数秒
- **智能联动**：扫描完成后自动调用 Nmap 进行服务识别和版本探测
- **灵活配置**：支持全端口、指定端口范围、常用端口等多种扫描模式
- **结果解析**：支持 Greppable 格式输出，便于程序化解析处理
- **性能可调**：可调节批处理大小、超时时间、重试次数等参数

## 适用场景

- 快速发现目标主机的开放端口
- 渗透测试前期的信息收集
- 网络安全审计和漏洞评估
- 服务器端口暴露面检查
- 内网资产发现和梳理

## 安装

### 前置要求

- RustScan 工具
- Python 3.x（用于结果解析）
- Nmap（可选，用于深度扫描）

### 安装 RustScan

#### 方式一：使用 Cargo 安装（推荐）

```bash
# 检查 Rust 环境
cargo --version

# 安装 RustScan
cargo install rustscan

# 或使用 --locked 确保依赖兼容
cargo install rustscan --locked
```

#### 方式二：使用 Docker

```bash
# 拉取镜像
docker pull rustscan/rustscan:latest

# 运行扫描
docker run -it --rm --network host rustscan/rustscan:latest -a <target>
```

#### 方式三：从源码编译

```bash
# 克隆仓库
git clone https://github.com/RustScan/RustScan.git
cd RustScan

# 编译
cargo build --release

# 使用编译后的二进制文件
./target/release/rustscan -a <target>
```

### 验证安装

```bash
rustscan --version
```

## 使用方法

### 基本语法

```bash
rustscan [参数] [目标]
```

### 常用参数

| 参数 | 简写 | 说明 | 示例 |
|------|------|------|------|
| `--addresses` | `-a` | 目标地址（IP 或域名） | `-a 192.168.1.1` |
| `--ports` | `-p` | 指定端口（逗号分隔或范围） | `-p 80,443` 或 `-p 1-1000` |
| `--range` | `-r` | 端口范围 | `-r 1-65535` |
| `--timeout` | `-t` | 连接超时（毫秒） | `-t 1500` |
| `--batch-size` | `-b` | 并发连接数 | `-b 1500` |
| `--greppable` | `-g` | Greppable 格式输出 | `-g` |
| `--output` | `-o` | 输出到文件 | `-o result.txt` |
| `--no-nmap` | - | 禁用自动 Nmap | `--no-nmap` |
| `--ulimit` | - | 设置系统 ulimit | `--ulimit 5000` |
| `--tries` | - | 重试次数 | `--tries 1` |
| `--scan-order` | - | 扫描顺序 | `--scan-order random` |

## 使用示例

### 示例 1：基础全端口扫描

```bash
# 扫描目标的所有端口（1-65535）
rustscan -a scanme.nmap.org

# 扫描多个目标
rustscan -a "192.168.1.1,192.168.1.2"
```

**输出示例：**
```
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.

[~] Starting Portscan!
Open 45.33.32.156:22
Open 45.33.32.156:80
[~] Scan completed in 3 seconds
```

### 示例 2：扫描指定端口范围

```bash
# 扫描 1-1000 端口
rustscan -a 192.168.1.1 -p 1-1000

# 扫描特定端口列表
rustscan -a 192.168.1.1 -p 22,80,443,3306,5432,6379,8080,8443

# 使用范围参数
rustscan -a 192.168.1.1 -r 1-10000
```

### 示例 3：扫描常用服务端口

```bash
# 扫描最常用的服务端口
rustscan -a 192.168.1.1 -p 21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,9200,27017
```

### 示例 4：扫描后自动调用 Nmap 深度分析

```bash
# 扫描后自动执行 Nmap 服务识别和版本探测
rustscan -a 192.168.1.1 -- -A -sV -sC

# 执行 Nmap 漏洞扫描脚本
rustscan -a 192.168.1.1 -- --script vuln

# 自定义 Nmap 参数
rustscan -a 192.168.1.1 -- -sV -sC -A --top-ports 100 -oN nmap_result.txt
```

### 示例 5：使用 Python 解析扫描结果

```python
import re
import subprocess

# 执行扫描并捕获输出
result = subprocess.run(
    ['rustscan', '-a', '192.168.1.1', '-g'],
    capture_output=True,
    text=True
)

# 解析 Greppable 格式输出
open_ports = []
for line in result.stdout.split('\n'):
    match = re.search(r'Open\s+[\d\.]+:(\d+)', line)
    if match:
        open_ports.append(match.group(1))

print(f"发现的开放端口: {', '.join(open_ports)}")

# 生成端口列表字符串
port_list = ",".join(open_ports)
print(f"端口列表: {port_list}")
```

### 示例 6：高级配置扫描

```bash
# 调整扫描速度（增大并发数）
rustscan -a 192.168.1.1 -b 3000

# 随机扫描顺序（降低被检测概率）
rustscan -a 192.168.1.1 --scan-order random -t 2000

# 保存结果到文件
rustscan -a 192.168.1.1 -g -o scan_result.txt

# 综合优化参数
rustscan -a 192.168.1.1 -b 2500 -t 800 --tries 1 --scan-order random
```

## 输出格式

### 标准输出

```
[~] Starting Portscan!
Open 192.168.1.1:22
Open 192.168.1.1:80
Open 192.168.1.1:443
[~] Scan completed in 2 seconds
```

### Greppable 格式（-g）

使用 `-g` 参数输出便于解析的格式：

```
Open 192.168.1.1:22
Open 192.168.1.1:80
Open 192.168.1.1:443
```

## 性能优化

### 提高扫描速度

```bash
# 增大批处理大小（可能增加被检测风险）
rustscan -a 192.168.1.1 -b 3000

# 减少重试次数
rustscan -a 192.168.1.1 --tries 1

# 降低超时时间（适用于低延迟网络）
rustscan -a 192.168.1.1 -t 500
```

### 调整系统限制

```bash
# 查看当前限制
ulimit -n

# 临时提高限制
ulimit -n 65535

# 或在 RustScan 中设置
rustscan -a 192.168.1.1 --ulimit 5000
```

## 故障排除

### 常见问题

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| `ulimit` 错误 | 文件描述符限制过低 | `ulimit -n 65535` 或 `--ulimit 5000` |
| 连接超时 | 网络延迟高 | 增加 `-t` 参数值 |
| 权限被拒绝 | 扫描特权端口 | 使用 `sudo` 运行 |
| 扫描速度慢 | 批处理大小过小 | 增加 `-b` 参数 |
| 结果不准确 | 防火墙/IDS | 调整 `--tries` 和 `-t` |
| Nmap 未找到 | 未安装 Nmap | `apt install nmap` 或 `--no-nmap` |

### Docker 运行问题

```bash
# 如果网络模式不兼容，使用桥接模式
docker run -it --rm rustscan/rustscan:latest -a <target>

# 挂载当前目录保存结果
docker run -it --rm -v $(pwd):/output rustscan/rustscan:latest -a <target> -o /output/result.txt
```

## 注意事项

### 权限要求

- 扫描 0-1024 特权端口需要 root 权限
- 大规模扫描可能需要调整系统 ulimit

### 法律合规

> ⚠️ **重要警告**
> 
> - **授权要求**：仅扫描您拥有明确授权的目标系统
> - **法律合规**：未经授权的端口扫描可能违反当地法律法规
> - **责任声明**：使用者需自行承担因未授权扫描导致的法律后果
> - **测试环境**：建议在隔离的测试环境中学习和练习

### 最佳实践

1. 在授权范围内进行扫描
2. 生产环境扫描前先在测试环境验证
3. 合理设置扫描速率，避免对目标系统造成影响
4. 保存扫描结果用于后续分析和报告

## 相关资源

- [RustScan GitHub](https://github.com/RustScan/RustScan)
- [RustScan 文档](https://github.com/RustScan/RustScan/wiki)
- [Nmap 官方文档](https://nmap.org/book/)
- [OpenClaw 文档](https://openclaw.dev)

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

## 贡献

欢迎提交 Issue 和 Pull Request！

## 致谢

- [RustScan](https://github.com/RustScan/RustScan) - 极速端口扫描器
- [Nmap](https://nmap.org/) - 网络扫描和安全审计工具
