# ============================================================================
# Skill: middleware-vuln-intelligence
# Description: 面向信息安全运营人员的企业级中间件漏洞情报自动化收集与处置系统
# Version: 1.0.0
# Author: Security Operations Team
# Target Users: SOC分析师、漏洞管理工程师、应急响应人员
# ============================================================================

name: middleware-vuln-intelligence
description: >
  企业级中间件漏洞情报自动化收集与处置系统。
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

# ============================================================================
# 配置参数
# ============================================================================
parameters:
  # 目标中间件组件（支持多选）
  target_components:
    type: array
    description: 需要监控的中间件组件列表
    default:
      - WebLogic
      - Tomcat
      - Nginx
      - Redis
      - Kafka
      - Elasticsearch
      - WebSphere
      - JBoss
      - RabbitMQ
      - ActiveMQ
      - MongoDB
      - MySQL
      - PostgreSQL
      - Kubernetes
      - Zookeeper
    enum:
      - WebLogic
      - Tomcat
      - Nginx
      - Redis
      - Kafka
      - Elasticsearch
      - WebSphere
      - JBoss
      - RabbitMQ
      - ActiveMQ
      - MongoDB
      - MySQL
      - PostgreSQL
      - Docker
      - Kubernetes
      - Zookeeper

  # 时间范围
  time_range:
    type: string
    description: 漏洞发现时间范围
    default: "last 30 days"
    enum:
      - "last 7 days"
      - "last 30 days"
      - "last 90 days"
      - "last 6 months"
      - "last 1 year"

  # 最低CVSS评分阈值
  min_cvss_score:
    type: number
    description: 最低CVSS评分阈值（仅收集高于此值的漏洞）
    default: 7.0
    minimum: 0.0
    maximum: 10.0

  # 输出格式
  output_format:
    type: string
    description: 报告输出格式
    default: markdown
    enum:
      - markdown
      - json
      - html

  # 是否包含PoC
  include_poc:
    type: boolean
    description: 是否生成检测PoC代码
    default: true

  # 是否生成Sigma规则
  generate_sigma:
    type: boolean
    description: 是否生成Sigma检测规则
    default: true

# ============================================================================
# 搜索词模板库
# ============================================================================
search_templates:
  # 基础漏洞搜索模板
  base_vuln_search:
    template: "{{component}} vulnerability CVE {{time_range}}"
    description: 基础漏洞搜索

  # 高危漏洞搜索模板
  critical_vuln_search:
    template: "{{component}} critical vulnerability RCE exploit {{time_range}}"
    description: 高危漏洞搜索（RCE相关）

  # CISA KEV搜索模板
  cisa_kev_search:
    template: "{{component}} CISA KEV known exploited vulnerability"
    description: CISA已知利用漏洞搜索

  # GitHub PoC搜索模板
  github_poc_search:
    template: "{{component}} CVE PoC exploit GitHub {{time_range}}"
    description: GitHub公开PoC搜索

  # 技术分析搜索模板
  technical_analysis_search:
    template: "{{component}} vulnerability analysis technical writeup {{time_range}}"
    description: 技术分析文章搜索

  # 厂商公告搜索模板
  vendor_advisory_search:
    template: "{{component}} security advisory patch {{time_range}}"
    description: 厂商安全公告搜索

  # 组件特定搜索词映射
  component_specific:
    WebLogic:
      - "Oracle WebLogic Server CVE vulnerability"
      - "WebLogic T3 deserialization RCE"
      - "WebLogic Console unauthorized access"
    Tomcat:
      - "Apache Tomcat CVE vulnerability"
      - "Tomcat AJP connector Ghostcat"
      - "Tomcat manager upload exploit"
    Nginx:
      - "Nginx CVE vulnerability"
      - "Nginx ingress controller RCE"
      - "Nginx reverse proxy bypass"
    Redis:
      - "Redis unauthorized access"
      - "Redis Lua sandbox escape"
      - "Redis replication command injection"
    Kafka:
      - "Apache Kafka CVE vulnerability"
      - "Kafka Connect RCE"
      - "Kafka ACL bypass"
    Elasticsearch:
      - "Elasticsearch CVE vulnerability"
      - "Elasticsearch scripting engine RCE"
      - "Kibana prototype pollution"
    WebSphere:
      - "IBM WebSphere CVE vulnerability"
      - "WebSphere ND deserialization"
      - "WebSphere Portal XSS"
    JBoss:
      - "JBoss WildFly CVE vulnerability"
      - "JBoss invoker servlet RCE"
      - "WildFly Undertow HTTP request smuggling"
    RabbitMQ:
      - "RabbitMQ CVE vulnerability"
      - "RabbitMQ management plugin XSS"
      - "RabbitMQ federation plugin RCE"
    ActiveMQ:
      - "Apache ActiveMQ CVE vulnerability"
      - "ActiveMQ OpenWire deserialization"
      - "ActiveMQ web console RCE"
    MongoDB:
      - "MongoDB CVE vulnerability"
      - "MongoDB unauthorized access"
      - "MongoDB injection attack"
    MySQL:
      - "MySQL CVE vulnerability"
      - "MySQL authentication bypass"
      - "MySQL privilege escalation"
    PostgreSQL:
      - "PostgreSQL CVE vulnerability"
      - "PostgreSQL arbitrary code execution"
      - "PostgreSQL privilege escalation"
    Kubernetes:
      - "Kubernetes CVE vulnerability"
      - "K8s API server unauthorized access"
      - "Container escape vulnerability"
    Zookeeper:
      - "Apache Zookeeper CVE vulnerability"
      - "Zookeeper unauthorized access"
      - "Zookeeper quorum authentication bypass"

# ============================================================================
# 筛选条件表达式
# ============================================================================
filter_criteria:
  # 包含条件（满足至少2项）
  inclusion_rules:
    description: "漏洞需满足以下至少2项条件才纳入关注范围"
    logic: "COUNT_MATCH >= 2"
    conditions:
      - id: github_popularity
        name: "GitHub项目热度"
        expression: "github_stars >= 50 OR github_forks >= 20"
        weight: 1

      - id: cisa_kev
        name: "CISA KEV收录"
        expression: "in_cisa_kev_catalog == true"
        weight: 2  # CISA KEV权重更高，单独满足即可

      - id: cvss_score
        name: "CVSS评分"
        expression: "cvss_v3_score >= 7.0 OR cvss_v2_score >= 7.0"
        weight: 1

      - id: public_exploit
        name: "公开EXP可用"
        expression: "has_public_exploit == true OR exploitdb_id != null OR metasploit_module != null"
        weight: 1

      - id: poc_available
        name: "PoC代码可用"
        expression: "has_github_poc == true OR poc_url != null"
        weight: 1

      - id: active_exploitation
        name: "活跃利用证据"
        expression: "threat_intel.exploitation_detected == true OR honeypot_hits > 0"
        weight: 1

      - id: vendor_priority
        name: "厂商优先级"
        expression: "vendor_severity IN ['Critical', 'High'] OR vendor_priority == 'P1'"
        weight: 1

  # 排除条件（满足任意1项即过滤）
  exclusion_rules:
    description: "满足以下任意条件的漏洞将被自动过滤"
    logic: "ANY_MATCH"
    conditions:
      - id: outdated_vuln
        name: "过时漏洞"
        expression: "publish_date < NOW() - 2_years AND cvss_v3_score < 8.0"

      - id: false_positive
        name: "已知误报"
        expression: "tags CONTAINS 'false-positive' OR cve_status == 'Rejected'"

      - id: not_applicable
        name: "不适用环境"
        expression: "affected_versions DISJOINT deployed_versions"

      - id: already_patched
        name: "已修复版本"
        expression: "patch_available == true AND all_systems_patched == true"

      - id: low_impact
        name: "低影响漏洞"
        expression: "cvss_v3_score < 5.0 AND attack_complexity == 'High' AND privileges_required == 'High'"

      - id: duplicate_cve
        name: "重复CVE"
        expression: "cve_id IN processed_cve_list"

# ============================================================================
# 情报来源优先级
# ============================================================================
source_priority:
  tier_1_official:
    priority: 1
    sources:
      - "cve.mitre.org"
      - "nvd.nist.gov"
      - "cisa.gov/known-exploited-vulnerabilities"
    reliability: "官方权威"

  tier_2_vendor:
    priority: 2
    sources:
      - "Oracle Security Advisory"
      - "Apache Security"
      - "IBM Security Bulletin"
      - "Red Hat Security"
      - "VMware Security"
    reliability: "厂商官方"

  tier_3_research:
    priority: 3
    sources:
      - "rapid7.com"
      - "tenable.com"
      - "qualys.com"
      - "paloaltonetworks.com"
    reliability: "安全厂商"

  tier_4_community:
    priority: 4
    sources:
      - "github.com"
      - "exploit-db.com"
      - "packetstormsecurity.com"
      - "securityfocus.com"
    reliability: "社区开源"

# ============================================================================
# 工作流定义
# ============================================================================
workflow:
  name: "中间件漏洞情报收集与处置工作流"
  version: "1.0.0"

  # ==========================================================================
  # Phase 1: 漏洞发现与初筛
  # ==========================================================================
  phase_1_discovery:
    name: "漏洞发现与初筛"
    description: "通过多维度搜索发现潜在漏洞，并进行初步筛选"
    enabled: true
    tools:
      - web_search

    steps:
      - step: 1.1
        name: "生成搜索词"
        action: generate_search_queries
        input:
          components: "{{parameters.target_components}}"
          time_range: "{{parameters.time_range}}"
        output: search_queries[]
        logic: |
          FOR each component IN target_components:
            ADD "{{component}} vulnerability CVE {{time_range}}" TO search_queries
            ADD "{{component}} critical RCE exploit {{time_range}}" TO search_queries
            ADD "{{component}} CISA KEV" TO search_queries
            ADD "{{component}} PoC GitHub {{time_range}}" TO search_queries

      - step: 1.2
        name: "执行批量搜索"
        action: batch_web_search
        input:
          queries: "{{step_1_1.search_queries}}"
          max_results_per_query: 20
        output: raw_search_results[]

      - step: 1.3
        name: "提取CVE标识"
        action: extract_cve_identifiers
        input:
          search_results: "{{step_1_2.raw_search_results}}"
        output: cve_candidates[]
        pattern: "CVE-[0-9]{4}-[0-9]{4,}"

      - step: 1.4
        name: "初步筛选"
        action: apply_inclusion_filter
        input:
          cve_list: "{{step_1_3.cve_candidates}}"
          filter_rules: "{{filter_criteria.inclusion_rules}}"
        output: filtered_cves[]
        logic: |
          FOR each cve IN cve_candidates:
            match_count = 0
            IF cve.github_stars >= 50 THEN match_count += 1
            IF cve.in_cisa_kev == true THEN match_count += 2
            IF cve.cvss_score >= 7.0 THEN match_count += 1
            IF cve.has_public_exploit == true THEN match_count += 1
            IF match_count >= 2 THEN ADD cve TO filtered_cves

      - step: 1.5
        name: "应用排除规则"
        action: apply_exclusion_filter
        input:
          cve_list: "{{step_1_4.filtered_cves}}"
          exclusion_rules: "{{filter_criteria.exclusion_rules}}"
        output: qualified_cves[]
        logic: |
          FOR each cve IN filtered_cves:
            exclude = false
            IF cve.publish_date < NOW() - 2_years AND cve.cvss < 8.0 THEN exclude = true
            IF cve.status == 'Rejected' THEN exclude = true
            IF cve.cvss < 5.0 AND cve.complexity == 'High' THEN exclude = true
            IF NOT exclude THEN ADD cve TO qualified_cves

    output:
      qualified_cves: "{{step_1_5.qualified_cves}}"
      discovery_summary: |
        发现候选漏洞: {{step_1_3.cve_candidates | length}} 个
        通过初筛: {{step_1_4.filtered_cves | length}} 个
        最终合格: {{step_1_5.qualified_cves | length}} 个

  # ==========================================================================
  # Phase 2: 情报深度收集
  # ==========================================================================
  phase_2_intelligence:
    name: "情报深度收集"
    description: "收集CVE详情、厂商公告、技术分析和PoC链接"
    enabled: true
    depends_on: phase_1_discovery
    tools:
      - web_search
      - browser_visit

    steps:
      - step: 2.1
        name: "CVE官方信息收集"
        action: collect_cve_official_info
        input:
          cve_list: "{{phase_1_discovery.qualified_cves}}"
        output: cve_details[]
        sources:
          - "https://cve.mitre.org/cgi-bin/cvename.cgi?name={{cve_id}}"
          - "https://nvd.nist.gov/vuln/detail/{{cve_id}}"
        logic: |
          FOR each cve IN qualified_cves:
            FETCH cve.mitre.org FOR description, references
            FETCH nvd.nist.gov FOR cvss_v3, cvss_v2, cpe, published_date
            MERGE INTO cve_details

      - step: 2.2
        name: "厂商公告收集"
        action: collect_vendor_advisories
        input:
          cve_list: "{{phase_1_discovery.qualified_cves}}"
          components: "{{parameters.target_components}}"
        output: vendor_advisories[]
        search_templates:
          - "{{component}} security advisory {{cve_id}}"
          - "{{component}} patch {{cve_id}}"
        logic: |
          FOR each cve IN qualified_cves:
            FOR each component IN affected_components:
              SEARCH "{{component}} security advisory {{cve.cve_id}}"
              PRIORITIZE vendor official sources
              EXTRACT: patch_version, workaround, affected_versions

      - step: 2.3
        name: "技术分析收集"
        action: collect_technical_analysis
        input:
          cve_list: "{{phase_1_discovery.qualified_cves}}"
        output: technical_analysis[]
        search_templates:
          - "{{cve_id}} analysis technical writeup"
          - "{{cve_id}} root cause analysis"
          - "{{cve_id}} exploitation technique"
        logic: |
          FOR each cve IN qualified_cves:
            SEARCH "{{cve.cve_id}} analysis technical writeup"
            PRIORITIZE: trusted security blogs, research papers
            EXTRACT: vulnerability_type, attack_vector, impact_analysis

      - step: 2.4
        name: "PoC/EXP链接收集"
        action: collect_poc_resources
        input:
          cve_list: "{{phase_1_discovery.qualified_cves}}"
        output: poc_resources[]
        search_templates:
          - "{{cve_id}} PoC GitHub"
          - "{{cve_id}} exploit ExploitDB"
          - "{{cve_id}} Metasploit module"
        logic: |
          FOR each cve IN qualified_cves:
            SEARCH "{{cve.cve_id}} PoC GitHub"
            SEARCH "{{cve.cve_id}} exploit exploit-db"
            COLLECT:
              - github_url, stars, language
              - exploitdb_id, verified_status
              - metasploit_path

      - step: 2.5
        name: "CISA KEV状态验证"
        action: verify_cisa_kev_status
        input:
          cve_list: "{{phase_1_discovery.qualified_cves}}"
        output: cisa_kev_status[]
        source: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        logic: |
          FOR each cve IN qualified_cves:
            CHECK cisa_kev_catalog FOR cve.cve_id
            IF found:
              RECORD: date_added, due_date, required_action

      - step: 2.6
        name: "情报聚合与评分"
        action: aggregate_intelligence
        input:
          cve_details: "{{step_2_1.cve_details}}"
          vendor_advisories: "{{step_2_2.vendor_advisories}}"
          technical_analysis: "{{step_2_3.technical_analysis}}"
          poc_resources: "{{step_2_4.poc_resources}}"
          cisa_kev: "{{step_2_5.cisa_kev_status}}"
        output: enriched_vulnerabilities[]
        scoring_logic: |
          FOR each vuln IN enriched_vulnerabilities:
            # 计算综合威胁评分 (0-100)
            threat_score = 0
            threat_score += vuln.cvss_v3_score * 5  # CVSS基础分 (0-50)
            IF vuln.in_cisa_kev THEN threat_score += 20
            IF vuln.has_public_exploit THEN threat_score += 15
            IF vuln.github_stars > 100 THEN threat_score += 10
            IF vuln.exploit_verified THEN threat_score += 5
            vuln.threat_score = MIN(threat_score, 100)

    output:
      enriched_vulnerabilities: "{{step_2_6.enriched_vulnerabilities}}"
      intelligence_summary: |
        已收集情报: {{step_2_6.enriched_vulnerabilities | length}} 个漏洞
        CISA KEV收录: {{step_2_6.enriched_vulnerabilities | where: 'in_cisa_kev', true | length}} 个
        公开EXP可用: {{step_2_6.enriched_vulnerabilities | where: 'has_public_exploit', true | length}} 个

  # ==========================================================================
  # Phase 3: 检测方案生成
  # ==========================================================================
  phase_3_detection:
    name: "检测方案生成"
    description: "为每个漏洞生成Python POC、Nuclei模板、Sigma规则和Yara规则"
    enabled: "{{parameters.include_poc}}"
    depends_on: phase_2_intelligence
    tools:
      - code_generation

    steps:
      - step: 3.1
        name: "生成Python POC"
        action: generate_python_poc
        input:
          vulnerabilities: "{{phase_2_intelligence.enriched_vulnerabilities}}"
        output: python_pocs[]
        template: |
          """
          POC for {{cve_id}} - {{vulnerability_name}}
          Affected: {{affected_component}} {{affected_versions}}
          CVSS: {{cvss_score}} | Threat Score: {{threat_score}}
          """
          import requests
          import sys
          import argparse
          
          class {{cve_id}}_POC:
              def __init__(self, target):
                  self.target = target
                  self.vulnerable = False
              
              def check(self):
                  # Implementation based on vulnerability type
                  {{detection_logic}}
                  return self.vulnerable
          
          if __name__ == "__main__":
              parser = argparse.ArgumentParser()
              parser.add_argument("--target", required=True)
              args = parser.parse_args()
              poc = {{cve_id}}_POC(args.target)
              result = poc.check()
              print(f"Vulnerable: {result}")
        logic: |
          FOR each vuln IN enriched_vulnerabilities:
            IF vuln.vulnerability_type == 'RCE':
              GENERATE RCE detection logic
            IF vuln.vulnerability_type == 'SQLi':
              GENERATE SQL injection detection logic
            IF vuln.vulnerability_type == 'SSRF':
              GENERATE SSRF detection logic
            IF vuln.vulnerability_type == 'Deserialization':
              GENERATE deserialization detection logic

      - step: 3.2
        name: "生成Nuclei模板"
        action: generate_nuclei_template
        input:
          vulnerabilities: "{{phase_2_intelligence.enriched_vulnerabilities}}"
        output: nuclei_templates[]
        template: |
          id: {{cve_id | lower}}-{{component | lower}}
          
          info:
            name: "{{vulnerability_name}}"
            author: "auto-generated"
            severity: {{cvss_to_severity(cvss_score)}}
            description: |
              {{description}}
            reference:
              - {{reference_url}}
            classification:
              cvss-metrics: {{cvss_vector}}
              cvss-score: {{cvss_score}}
              cve-id: {{cve_id}}
              cwe-id: {{cwe_id}}
            metadata:
              verified: {{exploit_verified}}
            tags: cve,{{cve_year}},{{component | lower}},{{vulnerability_type | lower}}
          
          http:
            - method: {{http_method}}
              path:
                - "{{endpoint}}"
              {{request_details}}
              matchers:
                {{matchers}}
        logic: |
          FOR each vuln IN enriched_vulnerabilities:
            MAP vuln.vulnerability_type TO nuclei_matcher_type
            GENERATE http/tcp/dns template based on attack_vector

      - step: 3.3
        name: "生成Sigma规则"
        action: generate_sigma_rule
        input:
          vulnerabilities: "{{phase_2_intelligence.enriched_vulnerabilities}}"
        output: sigma_rules[]
        enabled: "{{parameters.generate_sigma}}"
        template: |
          title: "{{vulnerability_name}} Detection"
          id: {{generate_uuid}}
          status: experimental
          description: |
            Detects exploitation attempts for {{cve_id}}
            {{description}}
          references:
            - {{reference_url}}
          author: "auto-generated"
          date: {{current_date}}
          tags:
            - attack.{{mitre_technique}}
            - cve.{{cve_year}}.{{cve_number}}
          logsource:
            category: {{log_category}}
            product: {{target_product}}
          detection:
            selection:
              {{detection_fields}}
            condition: selection
          falsepositives:
            - Unknown
          level: {{sigma_level}}
        logic: |
          FOR each vuln IN enriched_vulnerabilities:
            DETERMINE logsource based on affected_component
            MAP attack_vector TO sigma_detection_fields
            SET level based on cvss_score:
              cvss >= 9.0 -> critical
              cvss >= 7.0 -> high
              cvss >= 4.0 -> medium
              else -> low

      - step: 3.4
        name: "生成Yara规则"
        action: generate_yara_rule
        input:
          vulnerabilities: "{{phase_2_intelligence.enriched_vulnerabilities}}"
        output: yara_rules[]
        template: |
          rule {{rule_name}}
          {
              meta:
                  description = "{{vulnerability_name}}"
                  author = "auto-generated"
                  reference = "{{reference_url}}"
                  date = "{{current_date}}"
                  cve = "{{cve_id}}"
              
              strings:
                  {{yara_strings}}
              
              condition:
                  {{yara_condition}}
          }
        logic: |
          FOR each vuln IN enriched_vulnerabilities:
            IF vuln.has_malware_samples:
              EXTRACT known malicious strings/signatures
              GENERATE yara_strings section
              SET condition based on string combinations

      - step: 3.5
        name: "检测方案整合"
        action: consolidate_detection_schemes
        input:
          python_pocs: "{{step_3_1.python_pocs}}"
          nuclei_templates: "{{step_3_2.nuclei_templates}}"
          sigma_rules: "{{step_3_3.sigma_rules}}"
          yara_rules: "{{step_3_4.yara_rules}}"
        output: detection_schemes[]
        logic: |
          FOR each vuln IN enriched_vulnerabilities:
            CREATE detection_scheme:
              cve_id: vuln.cve_id
              coverage:
                - proactive: nuclei_template
                - reactive: sigma_rule
                - forensic: yara_rule
                - validation: python_poc
              deployment_priority: CALCULATE based on threat_score

    output:
      detection_schemes: "{{step_3_5.detection_schemes}}"
      detection_summary: |
        已生成检测方案:
        - Python POC: {{step_3_1.python_pocs | length}} 个
        - Nuclei模板: {{step_3_2.nuclei_templates | length}} 个
        - Sigma规则: {{step_3_3.sigma_rules | length}} 个
        - Yara规则: {{step_3_4.yara_rules | length}} 个

  # ==========================================================================
  # Phase 4: 报告整合与输出
  # ==========================================================================
  phase_4_reporting:
    name: "报告整合与输出"
    description: "生成结构化Markdown报告，包含漏洞信息、检测方案和修复建议"
    enabled: true
    depends_on:
      - phase_2_intelligence
      - phase_3_detection

    steps:
      - step: 4.1
        name: "生成漏洞信息表"
        action: generate_vulnerability_table
        input:
          vulnerabilities: "{{phase_2_intelligence.enriched_vulnerabilities}}"
        output: vuln_table_markdown
        template: |
          ## 漏洞信息汇总表
          
          | CVE ID | 组件 | 漏洞类型 | CVSS | 威胁评分 | CISA KEV | 公开EXP | 状态 |
          |--------|------|----------|------|----------|----------|---------|------|
          {{#each vulnerabilities}}
          | {{cve_id}} | {{component}} | {{vuln_type}} | {{cvss_score}} | {{threat_score}} | {{cisa_kev_status}} | {{exploit_status}} | {{status}} |
          {{/each}}

      - step: 4.2
        name: "生成详细漏洞分析"
        action: generate_detailed_analysis
        input:
          vulnerabilities: "{{phase_2_intelligence.enriched_vulnerabilities}}"
        output: detailed_analysis[]
        template: |
          ### {{cve_id}} - {{vulnerability_name}}
          
          **基本信息**
          - 受影响组件: {{affected_component}}
          - 受影响版本: {{affected_versions}}
          - CVSS v3评分: {{cvss_v3_score}} ({{cvss_severity}})
          - 威胁综合评分: {{threat_score}}/100
          
          **漏洞描述**
          {{description}}
          
          **利用条件**
          - 攻击向量: {{attack_vector}}
          - 攻击复杂度: {{attack_complexity}}
          - 所需权限: {{privileges_required}}
          
          **情报来源**
          - CVE官方: {{cve_url}}
          - NVD详情: {{nvd_url}}
          - 厂商公告: {{vendor_advisory_url}}
          - CISA KEV: {{cisa_kev_url}}
          
          **公开资源**
          {{#if github_poc}}
          - GitHub PoC: {{github_poc_url}} (⭐{{github_stars}})
          {{/if}}
          {{#if exploitdb_id}}
          - ExploitDB: https://www.exploit-db.com/exploits/{{exploitdb_id}}
          {{/if}}
          {{#if metasploit_module}}
          - Metasploit: {{metasploit_module}}
          {{/if}}

      - step: 4.3
        name: "生成修复建议"
        action: generate_remediation_advice
        input:
          vulnerabilities: "{{phase_2_intelligence.enriched_vulnerabilities}}"
        output: remediation_advice[]
        template: |
          ### {{cve_id}} 修复建议
          
          **紧急程度**: {{urgency_level}}
          
          **官方修复方案**
          {{#if patch_available}}
          - 升级至版本: {{patched_version}}
          - 补丁下载: {{patch_url}}
          {{else}}
          - 暂无官方补丁
          {{/if}}
          
          **临时缓解措施**
          {{#each workarounds}}
          - {{this}}
          {{/each}}
          
          **CISA要求**
          {{#if in_cisa_kev}}
          - 联邦机构截止日期: {{cisa_due_date}}
          - 必需行动: {{cisa_required_action}}
          {{/if}}
          
          **检测建议**
          1. 使用Nuclei模板进行主动扫描
          2. 部署Sigma规则进行日志监控
          3. 定期运行Python POC进行验证

      - step: 4.4
        name: "生成风险评估"
        action: generate_risk_assessment
        input:
          vulnerabilities: "{{phase_2_intelligence.enriched_vulnerabilities}}"
        output: risk_assessment
        template: |
          ## 风险评估总结
          
          ### 整体风险概况
          - 高危漏洞数量: {{critical_count}} (CVSS >= 9.0)
          - 中高危漏洞数量: {{high_count}} (CVSS 7.0-8.9)
          - CISA KEV收录: {{cisa_kev_count}}
          - 公开EXP可用: {{public_exploit_count}}
          
          ### 优先级排序
          {{#each prioritized_vulns}}
          {{@index}}. **{{cve_id}}** - 威胁评分: {{threat_score}}
             - 原因: {{priority_reason}}
          {{/each}}
          
          ### 建议处置时间线
          | 优先级 | CVE数量 | 建议完成时间 |
          |--------|---------|--------------|
          | P0-紧急 | {{p0_count}} | 24小时内 |
          | P1-高危 | {{p1_count}} | 7天内 |
          | P2-中危 | {{p2_count}} | 30天内 |
          | P3-低危 | {{p3_count}} | 90天内 |

      - step: 4.5
        name: "整合最终报告"
        action: consolidate_final_report
        input:
          vuln_table: "{{step_4_1.vuln_table_markdown}}"
          detailed_analysis: "{{step_4_2.detailed_analysis}}"
          remediation_advice: "{{step_4_3.remediation_advice}}"
          risk_assessment: "{{step_4_4.risk_assessment}}"
          detection_schemes: "{{phase_3_detection.detection_schemes}}"
        output: final_report
        report_structure: |
          # 中间件漏洞情报报告
          
          **生成时间**: {{current_timestamp}}
          **报告周期**: {{parameters.time_range}}
          **监控组件**: {{parameters.target_components | join: ', '}}
          
          ---
          
          ## 执行摘要
          
          本次扫描共发现 {{vulnerabilities_count}} 个符合条件的中间件漏洞，
          其中 {{critical_count}} 个为高危漏洞（CVSS >= 9.0），
          {{cisa_kev_count}} 个被CISA KEV收录，
          {{public_exploit_count}} 个存在公开利用代码。
          
          ---
          
          {{vuln_table}}
          
          ---
          
          {{risk_assessment}}
          
          ---
          
          ## 详细漏洞分析
          
          {{#each detailed_analysis}}
          {{this}}
          
          ---
          {{/each}}
          
          ## 修复建议
          
          {{#each remediation_advice}}
          {{this}}
          
          ---
          {{/each}}
          
          ## 检测方案
          
          {{#each detection_schemes}}
          ### {{cve_id}} 检测方案
          
          **部署优先级**: {{deployment_priority}}
          
          **检测覆盖**
          - 主动检测: Nuclei模板
          - 被动检测: Sigma规则
          - 取证分析: Yara规则
          - 验证工具: Python POC
          
          **快速部署命令**
          ```bash
          # Nuclei扫描
          nuclei -t {{nuclei_template_path}} -u <target>
          
          # Sigma规则测试
          sigma convert -t splunk {{sigma_rule_path}}
          
          # Python POC验证
          python3 {{poc_filename}} --target <target>
          ```
          
          ---
          {{/each}}
          
          ## 附录
          
          ### A. 参考资料
          - [CISA KEV目录](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
          - [NVD漏洞数据库](https://nvd.nist.gov/)
          - [CVE官方列表](https://cve.mitre.org/)
          
          ### B. 工具链接
          - [Nuclei](https://github.com/projectdiscovery/nuclei)
          - [Sigma](https://github.com/SigmaHQ/sigma)
          - [Yara](https://github.com/VirusTotal/yara)

    output:
      final_report: "{{step_4_5.final_report}}"
      report_metadata:
        format: "{{parameters.output_format}}"
        generated_at: "{{current_timestamp}}"
        vuln_count: "{{phase_2_intelligence.enriched_vulnerabilities | length}}"
        cisa_kev_count: "{{phase_2_intelligence.enriched_vulnerabilities | where: 'in_cisa_kev', true | length}}"

# ============================================================================
# 输出定义
# ============================================================================
outputs:
  - name: vulnerability_report
    description: "结构化漏洞情报报告"
    type: markdown
    source: "phase_4_reporting.final_report"

  - name: detection_schemes
    description: "检测方案集合"
    type: json
    source: "phase_3_detection.detection_schemes"

  - name: enriched_vulnerabilities
    description: "富化的漏洞数据"
    type: json
    source: "phase_2_intelligence.enriched_vulnerabilities"

  - name: executive_summary
    description: "执行摘要"
    type: text
    source: "phase_4_reporting.report_metadata"

# ============================================================================
# 错误处理
# ============================================================================
error_handling:
  on_search_failure:
    action: retry_with_backoff
    max_retries: 3
    backoff_strategy: exponential

  on_parse_failure:
    action: log_and_continue
    fallback_value: null

  on_empty_results:
    action: notify_and_exit
    message: "未发现符合条件的漏洞情报"

# ============================================================================
# 通知配置
# ============================================================================
notifications:
  on_complete:
    enabled: true
    channels:
      - type: console
        message: "漏洞情报收集完成，共发现 {{vuln_count}} 个漏洞"

  on_critical_vuln_found:
    enabled: true
    threshold: "cvss >= 9.0 OR in_cisa_kev == true"
    channels:
      - type: console
        message: "发现高危漏洞，请立即关注！"
