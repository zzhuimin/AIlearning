# 企业级中间件漏洞情报收集系统

## 1. 漏洞情报维度表格

### 1.1 完整情报收集维度

| 情报类型 | 具体内容 | 来源要求 | 查询URL模板 | 优先级 |
|---------|---------|---------|------------|--------|
| **基础信息** | CVE编号、发布日期、最后修改日期 | CVE.org, NVD | `https://www.cve.org/CVERecord?id={{cve_id}}` | P0 |
| **漏洞描述** | 技术描述、影响范围、攻击向量 | CVE.org, NVD | `https://nvd.nist.gov/vuln/detail/{{cve_id}}` | P0 |
| **CVSS评分** | CVSS v3.1/v4.0 基础/ temporal/环境评分 | NVD | `https://nvd.nist.gov/vuln/detail/{{cve_id}}` | P0 |
| **CWE分类** | 弱点类型编号及描述 | NVD, MITRE | `https://cwe.mitre.org/data/definitions/{{cwe_id}}.html` | P1 |
| **厂商公告** | 官方安全公告、补丁说明 | 厂商Security Advisory | 见下方厂商URL模板 | P0 |
| **CISA KEV** | 已知被利用漏洞清单状态 | CISA | `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` | P0 |
| **EPSS评分** | 被利用概率预测分数 | FIRST EPSS | `https://api.first.org/data/v1/epss?cve={{cve_id}}` | P1 |
| **复现文档** | 技术原理、利用条件、复现步骤 | Seebug, Vulhub, GitHub | 见下方社区URL模板 | P1 |
| **PoC/EXP** | 概念验证代码、利用脚本 | GitHub, Exploit-DB | `https://github.com/search?q={{cve_id}}+poc` | P1 |
| **解决方案** | 补丁版本、缓解措施、升级路径 | 厂商Patch公告 | 见下方厂商URL模板 | P0 |
| **威胁情报** | 在野利用情况、APT关联 | 威胁情报平台 | MISP, ThreatFox等 | P2 |
| **社区讨论** | 安全研究员分析、技术博客 | Twitter/X, Reddit, 安全客 | `https://twitter.com/search?q={{cve_id}}` | P2 |

### 1.2 中间件关注清单

| 中间件类型 | 具体组件 | 厂商公告URL |
|-----------|---------|------------|
| **Web服务器** | Nginx | `https://nginx.org/en/security_advisories.html` |
| | Apache HTTP Server | `https://httpd.apache.org/security/` |
| **应用服务器** | Apache Tomcat | `https://tomcat.apache.org/security.html` |
| | Oracle WebLogic | `https://www.oracle.com/security-alerts/` |
| | IBM WebSphere | `https://www.ibm.com/support/pages/security-bulletins` |
| | JBoss/WildFly | `https://access.redhat.com/security/cve/` |
| **消息队列** | Apache Kafka | `https://kafka.apache.org/cve-list` |
| | RabbitMQ | `https://www.rabbitmq.com/news.html` |
| | Apache ActiveMQ | `https://activemq.apache.org/security-advisories` |
| **搜索引擎** | Elasticsearch | `https://discuss.elastic.co/c/announcements/security-announcements/` |
| **数据库** | Redis | `https://github.com/redis/redis/security/advisories` |
| | MongoDB | `https://www.mongodb.com/alerts` |
| | MySQL | `https://www.oracle.com/security-alerts/` |
| | PostgreSQL | `https://www.postgresql.org/support/security/` |
| **协调服务** | Apache ZooKeeper | `https://zookeeper.apache.org/security.html` |
| **容器编排** | Kubernetes | `https://kubernetes.io/docs/reference/issues-security/security/` |
| | Docker | `https://docs.docker.com/engine/security/` |

---

## 2. 热度指标定义

### 2.1 高热度漏洞筛选标准（满足至少2项）

| 指标名称 | 阈值定义 | 查询方法 | 权重 |
|---------|---------|---------|------|
| **CVSS v3.1评分** | ≥ 7.0 (High及以上) | NVD API: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={{cve_id}}` | 高 |
| **EPSS评分** | ≥ 0.1 (10%) | EPSS API: `https://api.first.org/data/v1/epss?cve={{cve_id}}` | 高 |
| **CISA KEV状态** | 在清单中 | CISA JSON: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | 极高 |
| **GitHub PoC Stars** | ≥ 50 stars | GitHub API: `https://api.github.com/search/repositories?q={{cve_id}}+poc` | 中 |
| **Exploit-DB收录** | 有公开EXP | `searchsploit --cve {{cve_id}}` | 中 |
| **Vulhub环境** | 有Docker环境 | `https://github.com/vulhub/vulhub/tree/master/*/{{cve_id}}` | 低 |
| **Metasploit模块** | 有MSF模块 | `msfconsole -q -x "search {{cve_id}}"` | 高 |
| **公开披露时间** | ≤ 30天 | NVD发布日期 | 中 |

### 2.2 热度评分计算公式

```
热度总分 = (CVSS≥7.0 ? 25 : CVSS≥5.0 ? 15 : 5) +
          (EPSS≥0.3 ? 25 : EPSS≥0.1 ? 15 : EPSS≥0.01 ? 5 : 0) +
          (CISA KEV ? 30 : 0) +
          (GitHub Stars≥100 ? 10 : Stars≥50 ? 5 : 0) +
          (Exploit-DB ? 5 : 0) +
          (Metasploit ? 10 : 0)

热度等级:
- 极高: 80-100分 (立即响应)
- 高: 60-79分 (24小时内响应)
- 中: 40-59分 (72小时内响应)
- 低: 20-39分 (一周内响应)
- 极低: 0-19分 (常规跟踪)
```

---

## 3. 情报来源优先级

### 3.1 官方权威源 (P0 - 最高优先级)

| 排名 | 来源 | 用途 | 更新频率 | 可靠性 |
|-----|------|------|---------|--------|
| 1 | **CVE.org** | CVE基础信息、官方描述 | 实时 | ★★★★★ |
| 2 | **NVD (NIST)** | CVSS评分、CWE分类、CPE | 每日同步 | ★★★★★ |
| 3 | **厂商安全公告** | 补丁信息、官方修复方案 | 按发布 | ★★★★★ |
| 4 | **CISA KEV** | 已知被利用漏洞确认 | 每日更新 | ★★★★★ |

### 3.2 安全研究机构 (P1 - 高优先级)

| 排名 | 来源 | 用途 | 特点 | 可靠性 |
|-----|------|------|------|--------|
| 5 | **Seebug (知道创宇)** | 中文复现分析、PoC | 国内领先 | ★★★★☆ |
| 6 | **长亭科技** | 漏洞分析、检测工具 | 企业级 | ★★★★☆ |
| 7 | **奇安信** | 威胁情报、APT分析 | 国内权威 | ★★★★☆ |
| 8 | **Vulhub** | Docker复现环境 | 开源社区 | ★★★★☆ |
| 9 | **Tenable/Qualys** | 漏洞扫描验证 | 商业工具 | ★★★★☆ |

### 3.3 开源社区 (P1 - 高优先级)

| 排名 | 来源 | 用途 | 查询方式 | 可靠性 |
|-----|------|------|---------|--------|
| 10 | **GitHub** | PoC代码、技术讨论 | 搜索CVE编号 | ★★★☆☆ |
| 11 | **Exploit-DB** | 公开EXP代码 | searchsploit工具 | ★★★☆☆ |
| 12 | **Metasploit** | 自动化利用模块 | msfconsole搜索 | ★★★★☆ |
| 13 | **Packet Storm** | 安全公告、EXP | 网站搜索 | ★★★☆☆ |

### 3.4 安全媒体 (P2 - 参考优先级)

| 排名 | 来源 | 用途 | 语言 | 可靠性 |
|-----|------|------|------|--------|
| 14 | **FreeBuf** | 中文安全资讯 | 中文 | ★★★☆☆ |
| 15 | **安全客** | 中文技术分析 | 中文 | ★★★☆☆ |
| 16 | **The Hacker News** | 国际安全新闻 | 英文 | ★★★☆☆ |
| 17 | **BleepingComputer** | 漏洞新闻报道 | 英文 | ★★★☆☆ |

---

## 4. 查询URL模板

### 4.1 官方数据库查询URL

```yaml
# CVE.org - CVE基础信息
CVE_ORG_RECORD: "https://www.cve.org/CVERecord?id={{cve_id}}"
CVE_ORG_JSON: "https://cveawg.mitre.org/api/cve/{{cve_id}}"

# NVD - 美国国家漏洞数据库
NVD_DETAIL: "https://nvd.nist.gov/vuln/detail/{{cve_id}}"
NVD_API_20: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={{cve_id}}"
NVD_API_20_MULTI: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={{cve_id_1}},{{cve_id_2}}"
NVD_CPE_MATCH: "https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch={{product_name}}"

# CISA KEV - 已知被利用漏洞
CISA_KEV_CATALOG: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
CISA_KEV_JSON: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_KEV_RSS: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog.xml"

# EPSS - 被利用概率评分
EPSS_API: "https://api.first.org/data/v1/epss?cve={{cve_id}}"
EPSS_API_MULTI: "https://api.first.org/data/v1/epss?cve={{cve_id_1}},{{cve_id_2}}"
EPSS_API_FILTER: "https://api.first.org/data/v1/epss?epss-gt=0.1&date={{yyyy-mm-dd}}"
EPSS_WEB: "https://www.first.org/epss/api"

# MITRE CWE - 弱点分类
MITRE_CWE: "https://cwe.mitre.org/data/definitions/{{cwe_id}}.html"
MITRE_CWE_TOP25: "https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html"
```

### 4.2 厂商安全公告查询URL

```yaml
# Oracle (WebLogic, MySQL)
ORACLE_CPU: "https://www.oracle.com/security-alerts/"
ORACLE_ALERT: "https://www.oracle.com/security-alerts/alert-cve-{{year}}-{{number}}.html"

# Apache (Tomcat, Kafka, ActiveMQ, HTTP Server)
APACHE_SECURITY: "https://security.apache.org/"
TOMCAT_SECURITY: "https://tomcat.apache.org/security.html"
KAFKA_SECURITY: "https://kafka.apache.org/cve-list"
HTTPD_SECURITY: "https://httpd.apache.org/security/"

# Nginx
NGINX_SECURITY: "https://nginx.org/en/security_advisories.html"

# Elastic (Elasticsearch)
ELASTIC_SECURITY: "https://discuss.elastic.co/c/announcements/security-announcements/"

# Redis
REDIS_SECURITY: "https://github.com/redis/redis/security/advisories"

# MongoDB
MONGODB_ALERTS: "https://www.mongodb.com/alerts"

# IBM (WebSphere)
IBM_SECURITY: "https://www.ibm.com/support/pages/security-bulletins"

# RedHat (JBoss/WildFly)
REDHAT_CVE: "https://access.redhat.com/security/cve/{{cve_id}}"

# Kubernetes
K8S_SECURITY: "https://kubernetes.io/docs/reference/issues-security/security/"
K8S_CVE_FEED: "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json"
```

### 4.3 社区与开源查询URL

```yaml
# GitHub - PoC搜索
GITHUB_SEARCH_CVE: "https://github.com/search?q={{cve_id}}&type=repositories"
GITHUB_SEARCH_POC: "https://github.com/search?q={{cve_id}}+poc&type=repositories"
GITHUB_SEARCH_EXPLOIT: "https://github.com/search?q={{cve_id}}+exploit&type=repositories"
GITHUB_ADVISORY: "https://github.com/advisories/{{ghsa_id}}"

# Vulhub - Docker复现环境
VULHUB_REPO: "https://github.com/vulhub/vulhub"
VULHUB_CVE: "https://github.com/vulhub/vulhub/tree/master/{{product}}/{{cve_id}}"
VULHUB_SEARCH: "https://vulhub.org/#/search/?keyword={{cve_id}}"

# Seebug - 知道创宇漏洞库
SEEBUG_SEARCH: "https://seebug.org/search/?keywords={{cve_id}}"
SEEBUG_VULN: "https://seebug.org/vuldb/ssvid-{{ssvid}}"

# Exploit-DB
EXPLOITDB_SEARCH: "https://www.exploit-db.com/search?cve={{cve_id}}"
EXPLOITDB_CLI: "searchsploit --cve {{cve_id}}"

# Packet Storm
PACKETSTORM_SEARCH: "https://packetstormsecurity.com/search/?q={{cve_id}}"

# Vulmon
VULMON_SEARCH: "https://vulmon.com/search?q={{cve_id}}"

# Rapid7 (Metasploit)
RAPID7_DB: "https://www.rapid7.com/db/?q={{cve_id}}"
MSF_SEARCH: "msfconsole -q -x 'search {{cve_id}}'"
```

### 4.4 威胁情报查询URL

```yaml
# MISP
MISP_CVE: "https://www.circl.lu/services/cve-search/"

# ThreatFox
THREATFOX_SEARCH: "https://threatfox.abuse.ch/browse.php?search={{cve_id}}"

# AlienVault OTX
OTX_CVE: "https://otx.alienvault.com/indicator/cve/{{cve_id}}"

# VirusTotal
VT_SEARCH: "https://www.virustotal.com/gui/search/{{cve_id}}"

# GreyNoise
GREYNOISE_CVE: "https://viz.greynoise.io/query/?query={{cve_id}}"
```

---

## 5. 漏洞信息表格模板

### 5.1 漏洞基本信息表

| 字段名称 | 字段说明 | 数据类型 | 示例值 |
|---------|---------|---------|--------|
| **CVE编号** | 标准CVE ID | String | CVE-2023-4911 |
| **漏洞名称** | 简短描述性名称 | String | GNU C Library ld.so本地权限提升 |
| **影响组件** | 受影响的软件/组件 | String | glibc (GNU C Library) |
| **影响版本** | 受影响版本范围 | String | 2.34 - 2.38 |
| **修复版本** | 官方修复版本 | String | 2.39 |
| **CVSS v3.1** | NVD CVSS评分 | Float | 7.8 |
| **CVSS等级** | 严重程度等级 | Enum | HIGH |
| **EPSS评分** | 被利用概率 | Float | 0.00123 |
| **EPSS百分位** | 相对排名 | Float | 0.45 |
| **CISA KEV** | 已知被利用状态 | Boolean | false |
| **CWE编号** | 弱点分类 | String | CWE-787 |
| **漏洞类型** | 攻击类型分类 | String | 缓冲区溢出 |
| **发布日期** | CVE发布日期 | Date | 2023-10-03 |
| **最后修改** | 最后更新日期 | Date | 2023-10-15 |

### 5.2 漏洞详细分析表

| 字段名称 | 字段说明 | 数据类型 | 示例值 |
|---------|---------|---------|--------|
| **攻击向量(AV)** | 攻击路径 | Enum | LOCAL |
| **攻击复杂度(AC)** | 利用难度 | Enum | LOW |
| **所需权限(PR)** | 前置权限要求 | Enum | NONE |
| **用户交互(UI)** | 是否需要用户交互 | Enum | NONE |
| **影响范围(S)** | 影响边界 | Enum | UNCHANGED |
| **机密性影响(C)** | 信息泄露程度 | Enum | HIGH |
| **完整性影响(I)** | 数据篡改程度 | Enum | HIGH |
| **可用性影响(A)** | 服务中断程度 | Enum | HIGH |
| **利用条件** | 成功利用的前提条件 | Text | 需要本地访问权限 |
| **技术原理** | 漏洞根因分析 | Text | GLIBC_TUNABLES环境变量处理不当 |
| **影响评估** | 业务影响分析 | Text | 可导致本地权限提升至root |

### 5.3 解决方案与响应表

| 字段名称 | 字段说明 | 数据类型 | 示例值 |
|---------|---------|---------|--------|
| **补丁状态** | 官方补丁发布状态 | Enum | Available |
| **补丁URL** | 官方补丁下载链接 | URL | https://sourceware.org/git/?p=glibc.git |
| **升级路径** | 版本升级建议 | Text | 升级至glibc 2.39或更高版本 |
| **缓解措施** | 临时防护方案 | Text | 移除GLIBC_TUNABLES环境变量 |
| **缓解措施有效性** | 临时方案可靠程度 | Enum | Partial |
| **PoC可用性** | 公开PoC状态 | Enum | Public |
| **PoC来源** | PoC代码来源 | String | GitHub, Exploit-DB |
| **EXP可用性** | 武器化EXP状态 | Enum | Public |
| **检测规则** | IDS/IPS检测规则 | Text | Snort/Suricata规则 |
| **扫描脚本** | 漏洞扫描脚本 | String | Nuclei, Nessus插件 |

### 5.4 威胁情报关联表

| 字段名称 | 字段说明 | 数据类型 | 示例值 |
|---------|---------|---------|--------|
| **在野利用** | 是否观察到主动利用 | Boolean | false |
| **APT关联** | 已知APT组织利用 | String | 无 |
| **勒索软件关联** | 勒索软件利用情况 | String | 无 |
| **僵尸网络关联** | 僵尸网络利用情况 | String | 无 |
| **暗网讨论** | 暗网中讨论热度 | Enum | Low |
| **Twitter热度** | 社交媒体讨论量 | Integer | 150 |
| **GitHub Stars** | PoC仓库关注数 | Integer | 230 |
| **Metasploit模块** | MSF模块可用性 | Boolean | true |
| **Metasploit路径** | MSF模块路径 | String | exploit/linux/local/cve_2023_4911 |

### 5.5 完整漏洞信息JSON模板

```json
{
  "basic_info": {
    "cve_id": "CVE-2023-4911",
    "vuln_name": "GNU C Library ld.so Local Privilege Escalation",
    "affected_component": "glibc (GNU C Library)",
    "affected_versions": "2.34 - 2.38",
    "fixed_version": "2.39",
    "cvss_v31_score": 7.8,
    "cvss_v31_severity": "HIGH",
    "cvss_v31_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "epss_score": 0.00123,
    "epss_percentile": 0.45,
    "cisa_kev": false,
    "cwe_id": "CWE-787",
    "vuln_type": "缓冲区溢出",
    "published_date": "2023-10-03",
    "last_modified": "2023-10-15"
  },
  "technical_analysis": {
    "attack_vector": "LOCAL",
    "attack_complexity": "LOW",
    "privileges_required": "LOW",
    "user_interaction": "NONE",
    "scope": "UNCHANGED",
    "confidentiality_impact": "HIGH",
    "integrity_impact": "HIGH",
    "availability_impact": "HIGH",
    "exploit_conditions": "需要本地用户权限",
    "technical_details": "GLIBC_TUNABLES环境变量处理不当导致缓冲区溢出",
    "business_impact": "可导致本地权限提升至root"
  },
  "solution": {
    "patch_status": "Available",
    "patch_url": "https://sourceware.org/git/?p=glibc.git",
    "upgrade_path": "升级至glibc 2.39或更高版本",
    "mitigation": "移除GLIBC_TUNABLES环境变量",
    "mitigation_effectiveness": "Partial"
  },
  "exploit_info": {
    "poc_available": true,
    "poc_sources": ["GitHub", "Exploit-DB"],
    "exp_available": true,
    "github_stars": 230,
    "metasploit_module": true,
    "metasploit_path": "exploit/linux/local/cve_2023_4911"
  },
  "threat_intelligence": {
    "in_the_wild": false,
    "apt_association": null,
    "ransomware_association": null,
    "botnet_association": null,
    "darkweb_mentions": "Low",
    "twitter_mentions": 150
  },
  "data_sources": {
    "cve_org": "https://www.cve.org/CVERecord?id=CVE-2023-4911",
    "nvd": "https://nvd.nist.gov/vuln/detail/CVE-2023-4911",
    "epss": "https://api.first.org/data/v1/epss?cve=CVE-2023-4911",
    "github_poc": "https://github.com/search?q=CVE-2023-4911+poc",
    "vendor_advisory": "https://sourceware.org/git/?p=glibc.git"
  },
  "metadata": {
    "created_at": "2023-10-03T00:00:00Z",
    "updated_at": "2023-10-15T00:00:00Z",
    "data_quality_score": 95,
    "confidence_level": "High"
  }
}
```

---

## 6. 自动化查询脚本模板

### 6.1 Python查询示例

```python
#!/usr/bin/env python3
"""
中间件漏洞情报收集脚本
支持CVE基础信息、CVSS评分、EPSS评分、CISA KEV状态查询
"""

import requests
import json
from typing import Dict, Optional

class VulnIntelligenceCollector:
    """漏洞情报收集器"""
    
    def __init__(self):
        self.nvd_api = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.epss_api = "https://api.first.org/data/v1/epss"
        self.cisa_kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.cve_org_api = "https://cveawg.mitre.org/api/cve"
        
    def get_nvd_info(self, cve_id: str) -> Optional[Dict]:
        """从NVD获取CVE详细信息"""
        try:
            response = requests.get(
                f"{self.nvd_api}?cveId={cve_id}",
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            if data.get("vulnerabilities"):
                return data["vulnerabilities"][0]
            return None
        except Exception as e:
            print(f"NVD查询失败: {e}")
            return None
    
    def get_epss_score(self, cve_id: str) -> Optional[Dict]:
        """从EPSS获取被利用概率评分"""
        try:
            response = requests.get(
                f"{self.epss_api}?cve={cve_id}",
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            if data.get("data"):
                return data["data"][0]
            return None
        except Exception as e:
            print(f"EPSS查询失败: {e}")
            return None
    
    def check_cisa_kev(self, cve_id: str) -> bool:
        """检查CVE是否在CISA KEV清单中"""
        try:
            response = requests.get(self.cisa_kev_url, timeout=30)
            response.raise_for_status()
            data = response.json()
            for vuln in data.get("vulnerabilities", []):
                if vuln.get("cveID") == cve_id:
                    return True
            return False
        except Exception as e:
            print(f"CISA KEV查询失败: {e}")
            return False
    
    def get_cve_org_info(self, cve_id: str) -> Optional[Dict]:
        """从CVE.org获取CVE基础信息"""
        try:
            response = requests.get(
                f"{self.cve_org_api}/{cve_id}",
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"CVE.org查询失败: {e}")
            return None
    
    def calculate_heat_score(self, cvss: float, epss: float, 
                            cisa_kev: bool, github_stars: int = 0) -> Dict:
        """计算漏洞热度评分"""
        score = 0
        details = []
        
        # CVSS评分
        if cvss >= 7.0:
            score += 25
            details.append("CVSS≥7.0: +25")
        elif cvss >= 5.0:
            score += 15
            details.append("CVSS≥5.0: +15")
        else:
            score += 5
            details.append("CVSS<5.0: +5")
        
        # EPSS评分
        if epss >= 0.3:
            score += 25
            details.append("EPSS≥0.3: +25")
        elif epss >= 0.1:
            score += 15
            details.append("EPSS≥0.1: +15")
        elif epss >= 0.01:
            score += 5
            details.append("EPSS≥0.01: +5")
        
        # CISA KEV
        if cisa_kev:
            score += 30
            details.append("CISA KEV: +30")
        
        # GitHub Stars
        if github_stars >= 100:
            score += 10
            details.append("GitHub Stars≥100: +10")
        elif github_stars >= 50:
            score += 5
            details.append("GitHub Stars≥50: +5")
        
        # 热度等级
        if score >= 80:
            level = "极高"
        elif score >= 60:
            level = "高"
        elif score >= 40:
            level = "中"
        elif score >= 20:
            level = "低"
        else:
            level = "极低"
        
        return {
            "score": score,
            "level": level,
            "details": details
        }

# 使用示例
if __name__ == "__main__":
    collector = VulnIntelligenceCollector()
    
    # 查询CVE-2023-4911
    cve_id = "CVE-2023-4911"
    
    print(f"正在收集 {cve_id} 的情报...")
    
    # 获取NVD信息
    nvd_info = collector.get_nvd_info(cve_id)
    if nvd_info:
        print(f"NVD信息获取成功")
        cvss_score = nvd_info.get("cve", {}).get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", 0)
    else:
        cvss_score = 0
    
    # 获取EPSS评分
    epss_info = collector.get_epss_score(cve_id)
    if epss_info:
        epss_score = float(epss_info.get("epss", 0))
        print(f"EPSS评分: {epss_score}")
    else:
        epss_score = 0
    
    # 检查CISA KEV
    is_kev = collector.check_cisa_kev(cve_id)
    print(f"CISA KEV状态: {is_kev}")
    
    # 计算热度评分
    heat = collector.calculate_heat_score(cvss_score, epss_score, is_kev)
    print(f"热度评分: {heat['score']} ({heat['level']})")
    print(f"评分详情: {heat['details']}")
```

### 6.2 Shell查询示例

```bash
#!/bin/bash
# 中间件漏洞情报快速查询脚本

CVE_ID="${1:-CVE-2023-4911}"

echo "========================================"
echo "漏洞情报收集 - ${CVE_ID}"
echo "========================================"

# 1. CVE.org 查询
echo -e "\n[1] CVE.org 基础信息:"
echo "URL: https://www.cve.org/CVERecord?id=${CVE_ID}"
curl -s "https://cveawg.mitre.org/api/cve/${CVE_ID}" | jq -r '.cveMetadata | "状态: \(.state), 发布: \(.datePublished)"' 2>/dev/null || echo "查询失败"

# 2. NVD 查询
echo -e "\n[2] NVD CVSS评分:"
echo "URL: https://nvd.nist.gov/vuln/detail/${CVE_ID}"
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${CVE_ID}" | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData | "CVSS v3.1: \(.baseScore) (\(.baseSeverity))"' 2>/dev/null || echo "查询失败"

# 3. EPSS 查询
echo -e "\n[3] EPSS被利用概率:"
curl -s "https://api.first.org/data/v1/epss?cve=${CVE_ID}" | jq -r '.data[0] | "EPSS: \(.epss), 百分位: \(.percentile)"' 2>/dev/null || echo "查询失败"

# 4. CISA KEV 检查
echo -e "\n[4] CISA KEV状态:"
kev_result=$(curl -s "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" | jq -r --arg cve "${CVE_ID}" '.vulnerabilities[] | select(.cveID == $cve) | "在KEV清单中: 截止日期 \(.dateAdded), 所需操作: \(.requiredAction)"' 2>/dev/null)
if [ -n "$kev_result" ]; then
    echo "$kev_result"
else
    echo "不在CISA KEV清单中"
fi

# 5. GitHub PoC搜索
echo -e "\n[5] GitHub PoC搜索:"
echo "URL: https://github.com/search?q=${CVE_ID}+poc&type=repositories"

# 6. Vulhub检查
echo -e "\n[6] Vulhub复现环境:"
echo "URL: https://github.com/vulhub/vulhub/search?q=${CVE_ID}"

# 7. Exploit-DB检查
echo -e "\n[7] Exploit-DB检查:"
if command -v searchsploit &> /dev/null; then
    searchsploit --cve "${CVE_ID}" 2>/dev/null | head -5 || echo "无Exploit-DB记录"
else
    echo "URL: https://www.exploit-db.com/search?cve=${CVE_ID}"
fi

echo -e "\n========================================"
echo "情报收集完成"
echo "========================================"
```

---

## 7. 数据质量与置信度评估

### 7.1 数据质量评分标准

| 评分项 | 说明 | 分值 |
|-------|------|------|
| 官方源确认 | CVE.org和NVD均有记录 | +20 |
| CVSS评分完整 | 有CVSS v3.1评分 | +15 |
| EPSS评分可用 | 有EPSS评分数据 | +10 |
| 厂商公告 | 有官方安全公告 | +15 |
| PoC可用 | 有公开PoC代码 | +10 |
| 解决方案完整 | 有补丁或缓解措施 | +15 |
| 威胁情报 | 有CISA KEV或威胁情报 | +10 |
| 社区验证 | 有安全社区验证 | +5 |

### 7.2 置信度等级

| 等级 | 分数范围 | 说明 | 建议操作 |
|-----|---------|------|---------|
| **极高** | 90-100 | 多源交叉验证，信息完整 | 可直接用于决策 |
| **高** | 75-89 | 主要来源确认，信息较完整 | 建议用于决策 |
| **中** | 50-74 | 部分来源确认，信息待补充 | 需进一步验证 |
| **低** | 25-49 | 单一来源，信息不完整 | 需谨慎使用 |
| **极低** | 0-24 | 信息缺失严重 | 不建议使用 |

---

## 附录A: 常用中间件CVE查询速查表

| 中间件 | 最新CVE查询 | 安全公告 |
|-------|------------|---------|
| Nginx | `https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&search_type=all&isCpeNameSearch=false&query=nginx` | `https://nginx.org/en/security_advisories.html` |
| Tomcat | `https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&search_type=all&isCpeNameSearch=false&query=tomcat` | `https://tomcat.apache.org/security.html` |
| WebLogic | `https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&search_type=all&isCpeNameSearch=false&query=weblogic` | `https://www.oracle.com/security-alerts/` |
| Redis | `https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&search_type=all&isCpeNameSearch=false&query=redis` | `https://github.com/redis/redis/security/advisories` |
| Kafka | `https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&search_type=all&isCpeNameSearch=false&query=kafka` | `https://kafka.apache.org/cve-list` |
| Elasticsearch | `https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&search_type=all&isCpeNameSearch=false&query=elasticsearch` | `https://discuss.elastic.co/c/announcements/security-announcements/` |
| Kubernetes | `https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&search_type=all&isCpeNameSearch=false&query=kubernetes` | `https://kubernetes.io/docs/reference/issues-security/security/` |

---

*文档版本: 1.0*
*最后更新: 2025年*
*适用场景: 企业级中间件漏洞情报收集与分析*
