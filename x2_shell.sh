#!/usr/bin/env bash
# =============================================================================
#  x2shell-check.sh — Java、NGINX 与 Apache 主机暴露面自查
#  单文件 · 只读 · 无 Python/Go 依赖（仅 bash + coreutils/grep/awk）
#
#  无参同时执行三个专项，报告上游版本参考和可见的本地主机证据。
#    Java4Shell (CVE-2026-114938)：JVM 构建、CPU 和 Base64 intrinsic 缓解。
#    Nginx2Root：CVE-2026-123007 / 123633 / 123634 / 121810 / 113425，
#       检查 HTTP/2、HTTP/3、解析器、邮件代理与独立的 SCTP 内核线索。
#    Apache2Root (CVE-2026-119618)：httpd、mod_http2 映射和 h2/h2c 线索。
#
#  Java 专项参考以下开源检查器：
#    1) ubitquity/cve-2026-114938-java4shell-remediation
#       scripts/check-java4shell.sh        —— 架构/CPU 特性/运行时进程 + 缓解参数
#    2) Mahgal/java4shell-check
#       java4shell_check.py                —— 精确受影响版本表、--json、CI 退出码
#    3) nu0l/Java4Shell-LocalScanner
#       java4shell.go                      —— JDK 目录发现、release 元数据解析、
#                                             进程内 libjvm.so 设备号/inode 校验、
#                                             容器线索、厂商/产品补丁规则、CSV/JSON 报告
#
#  判定原则：版本、磁盘配置与运行证据分别报告，厂商回补需独立核验。
#    * 只读：不发送检测载荷，不联网，默认仅写临时报告数据；
#    * 只采集证据、不猜：证据不足时给出 unknown，而不是猜 affected / safe；
#    * JSON 的 result 用于判读。退出码区分风险、执行错误和待核查。
#    * 退出码：0 已检查范围未命中门禁，1 命中风险（即使有覆盖缺口），
#      2 参数错误或执行失败，3 未命中但证据不足。全量优先级为 2、1、3、0。
# =============================================================================

set -u

CVE="CVE-2026-114938"
RULES_AS_OF="2026-11-18"
PROG=${0##*/}
SCRIPT_VERSION="1.2.0"

OS=$(uname -s 2>/dev/null || echo unknown)
ARCH_RAW=$(uname -m 2>/dev/null || echo unknown)
ARCH_NORM=$(printf '%s' "$ARCH_RAW" | tr '[:upper:]' '[:lower:]')

# ---------------------------------------------------------------------------
# 默认参数
# ---------------------------------------------------------------------------
NO_PROC=0
PROC_ONLY=0
JCMD=0
ROOT_DEPTH=8
PROCESS_SCAN_LIMIT=1024
MAP_SCAN_MAX_BYTES=1048576
MAP_SCAN_TOTAL_BYTES=67108864
APACHE_MAP_SCAN_MAX_BYTES=1048576
APACHE_MAP_SCAN_TOTAL_BYTES=67108864
DIRECTORY_SCAN_LIMIT=5000
DIRECTORY_SCAN_SECONDS=20
SCAN_TIMEOUT_SECONDS=60
SCAN_DEADLINE_ACTIVE=0
PID_ARGS=()
ROOT_ARGS=()

WORK=""
FIND_FILE=""
WARN_FILE=""
ACTIVE_FILE=""
CPU_STATE="unknown"
CPU_SOURCE=""
CPU_COUNTS="0 0 0"
ROOT_COVERAGE_FILE=""
ROOT_DEPTH_BOUNDARIES=0
ROOT_SCAN_ERRORS=0
LIMITED_PROCS=0
JAVA_PROC_SCAN_UNAVAILABLE=false
JAVA_PROC_VISIBILITY_LIMITED=false
JAVA_PROC_ENTRIES=0
JAVA_PROC_BUDGET_REACHED=false
JAVA_MAP_BYTES_READ=0
JAVA_MAP_BUDGET_REACHED=false
JAVA_ROOT_BUDGET_REACHED=false

# 必需的 CPU 特性（x86-64）
REQ_FEATURES="avx512f avx512bw avx512vbmi bmi2"

# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

lower() { printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]'; }

trim() { printf '%s' "${1:-}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'; }

# 已知执行错误通过标准输出的 JSON 报告。
die() {
    local message
    message=$(json_escape "$1" 2>/dev/null) || message='Check the supplied options, paths and file permissions.'
    printf '{"result":"pending","result_reason":"invalid_arguments_or_io_failure","exit_code":2,"error":"invalid_arguments_or_io_failure","message":"%s"}\n' "$message"
    exit 2
}

scan_exit_code() {
    case $1 in
        no_risk) printf 0 ;;
        risk) printf 1 ;;
        pending) printf 3 ;;
        *) printf 2 ;;
    esac
}

run_timed_command() {
    local timer=$1
    shift
    if ((SCAN_DEADLINE_ACTIVE)); then
        # Keep nested commands in the group controlled by the scan deadline.
        "$timer" --foreground "$@"
    else
        "$timer" "$@"
    fi
}

# 追加一条采集提示（写文件，跨子 shell 安全）
warn() {
    printf '%s\n' "$*" >> "$WARN_FILE"
}

# 把可能破坏 TSV 的字符压平
san_field() {
    printf '%s' "${1:-}" | tr '\t\n' '  ' | tr -d '\037'
}

# 解析符号链接（相对目标也能处理）
resolve_symlinks() {
    local p=${1:-} t d i=0
    while [ -L "$p" ]; do
        i=$((i + 1))
        [ "$i" -gt 20 ] && break
        t=$(readlink "$p" 2>/dev/null) || break
        [ -n "$t" ] || break
        case $t in
            /*) p=$t ;;
            *) d=$(dirname "$p"); p="$d/$t" ;;
        esac
    done
    printf '%s' "$p"
}

# 规范化父目录（不解析最后一段，用于保留可能不存在的路径）
real_path() {
    local p=${1:-} d b
    [ -n "$p" ] || { printf ''; return; }
    b=${p##*/}
    d=${p%/*}
    [ -n "$d" ] || d=/
    if cd "$d" 2>/dev/null; then
        printf '%s/%s' "$(pwd -P)" "$b"
    else
        printf '%s' "$p"
    fi
}

# ---------------------------------------------------------------------------
# 版本号比较（纯数字元组，右补 0）
#   vcmp A B -> -1 / 0 / 1
# ---------------------------------------------------------------------------
vcmp() {
    awk -v a="${1:-0}" -v b="${2:-0}" 'BEGIN{
        na = split(a, A, ".")
        nb = split(b, B, ".")
        n = (na > nb) ? na : nb
        for (i = 1; i <= n; i++) {
            pa = (i <= na) ? (A[i] + 0) : 0
            pb = (i <= nb) ? (B[i] + 0) : 0
            if (pa > pb) { print 1; exit }
            if (pa < pb) { print -1; exit }
        }
        print 0
    }'
}
vgt() { [ "$(vcmp "$1" "$2")" = 1 ]; }
vge() { [ "$(vcmp "$1" "$2")" != -1 ]; }
vlt() { [ "$(vcmp "$1" "$2")" = -1 ]; }
vle() { [ "$(vcmp "$1" "$2")" != 1 ]; }

# ---------------------------------------------------------------------------
# CPU 条件
#   cpu_from_text : stdin 为 cpuinfo 文本，输出 "state with without procs"
# ---------------------------------------------------------------------------
cpu_from_text() {
    awk '
    {
        line = $0
        sub(/\r$/, "", line)
        if (line ~ /^[ \t]*processor[ \t]*:/) {
            procs++
        } else if (line ~ /^[ \t]*flags[ \t]*:/) {
            sub(/^[^:]*:/, "", line)
            n = split(line, a, /[ \t]+/)
            has_f = 0; has_bw = 0; has_vbmi = 0; has_bmi2 = 0
            for (i = 1; i <= n; i++) {
                f = a[i]
                if (f == "avx512f") has_f = 1
                else if (f == "avx512bw") has_bw = 1
                else if (f == "avx512vbmi" || f == "avx512_vbmi") has_vbmi = 1
                else if (f == "bmi2") has_bmi2 = 1
            }
            if (has_f && has_bw && has_vbmi && has_bmi2) withf++; else without++
            flags++
        }
    }
    END {
        if (flags == 0 || procs == 0)            print "unknown 0 0 " procs + 0
        else if (flags != procs)                 print "unknown " withf + 0 " " without + 0 " " procs + 0
        else if (withf > 0 && without > 0)       print "mixed " withf + 0 " " without + 0 " " procs + 0
        else if (withf > 0)                      print "present " withf + 0 " " without + 0 " " procs + 0
        else                                     print "absent " withf + 0 " " without + 0 " " procs + 0
    }'
}

cpu_probe_darwin() {
    local complete=1 f
    if [ "$ARCH_NORM" = "arm64" ]; then printf 'absent 0 0 0'; return; fi
    if [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = "1" ]; then
        printf 'absent 0 0 0'; return
    fi
    for f in hw.optional.avx512f hw.optional.avx512bw hw.optional.avx512vbmi hw.optional.bmi2; do
        case $(sysctl -n "$f" 2>/dev/null || echo "") in
            0) printf 'absent 0 0 0'; return ;;
            1) : ;;
            *) complete=0 ;;
        esac
    done
    if [ "$complete" -eq 1 ]; then printf 'present 1 0 1'; else printf 'unknown 0 0 0'; fi
}

cpu_probe() {
    local raw
    if [ -r /proc/cpuinfo ] && grep -q . /proc/cpuinfo 2>/dev/null; then
        raw=$(cpu_from_text < /proc/cpuinfo)
        CPU_SOURCE=/proc/cpuinfo
    elif [ "$OS" = "Darwin" ] && have sysctl; then
        raw=$(cpu_probe_darwin)
        CPU_SOURCE="sysctl"
    else
        CPU_STATE="unknown"
        CPU_SOURCE="CPU conditions are unknown because /proc/cpuinfo is unavailable."
        CPU_COUNTS="0 0 0"
        return
    fi
    CPU_STATE=$(printf '%s' "$raw" | cut -d' ' -f1)
    CPU_COUNTS=$(printf '%s' "$raw" | cut -d' ' -f2-)
}

# 归一化架构名
norm_arch() {
    case $(lower "${1:-}") in
        amd64|x86_64|x64)      printf 'amd64' ;;
        arm64|aarch64)         printf 'arm64' ;;
        386|x86|i386|i686)     printf '386' ;;
        arm|arm32|riscv64|s390x|ppc64|ppc64le|loong64|loongarch64|sparcv9)
                               lower "${1:-}" ;;
        *)                     printf '' ;;
    esac
}

# 结合架构与 CPU 采集结果 -> present|absent|mixed|unknown
cpu_assess() {
    local arch st
    arch=$(norm_arch "${1:-}")
    st=${2:-unknown}
    if [ -z "$arch" ]; then printf 'unknown'; return; fi
    if [ "$arch" != "amd64" ]; then printf 'absent'; return; fi
    case $st in
        present|absent|mixed) printf '%s' "$st" ;;
        *) printf 'unknown' ;;
    esac
}

# ---------------------------------------------------------------------------
# JDK release 元数据
# ---------------------------------------------------------------------------
release_is_jdk() {
    local f=$1
    [ -f "$f" ] || return 1
    grep -q '^JAVA_VERSION=' "$f" 2>/dev/null && return 0
    grep -q '^JAVA_RUNTIME_VERSION=' "$f" 2>/dev/null && return 0
    return 1
}

release_get() {
    local f=$1 key=$2
    [[ -f $f && -r $f ]] || return 0
    awk -v k="$key" '
        {
            line = $0
            sub(/\r$/, "", line)
            i = index(line, "=")
            if (i <= 0) next
            key = substr(line, 1, i - 1)
            val = substr(line, i + 1)
            gsub(/^[ \t]+|[ \t]+$/, "", key)
            gsub(/^[ \t]+|[ \t]+$/, "", val)
            gsub(/^"|"$/, "", val)
            if (key == k) { print val; exit }
        }' "$f" 2>/dev/null
}

# 旧版 JRE 仅在父目录确有可读 release 时归一化，避免丢失独立 JRE 的文件证据。
normalize_java_root() {
    local root=${1%/}
    if [ "${root##*/}" = "jre" ] && [ ! -r "$root/release" ] &&
       [ -r "${root%/*}/release" ]; then
        root=${root%/*}
    fi
    printf '%s' "$root"
}

# java 可执行文件 -> JDK/JRE Home（兼容 .../jre/bin/java 的旧布局）。
java_root_of() {
    local p=${1:-} root
    root=$(dirname "$(dirname "$p")")
    normalize_java_root "$root"
}

# 缺少 release 版本时，读取本机实际运行库/启动器所属的 OpenJDK 8 RPM 包。
# 不执行 java，不根据目录名称推测；仅供磁盘安装清点，不能证明进程运行版本。
installation_rpm_metadata() {
    local root=$1 file row name version vendor pattern timeout_bin
    have rpm && timeout_bin=$(type -P timeout || type -P gtimeout) || return 1
    pattern='^1\.8\.0\.([0-9]+)\.b([0-9]+)$'
    for file in "$root"/lib/libjvm.so "$root"/lib/*/libjvm.so \
        "$root"/lib/*/*/libjvm.so "$root"/jre/lib/*/libjvm.so \
        "$root"/jre/lib/*/*/libjvm.so "$root/bin/java" "$root/jre/bin/java"; do
        [ -f "$file" ] || continue
        file=$(real_path "$(resolve_symlinks "$file")")
        row=$(LC_ALL=C run_timed_command "$timeout_bin" -k 1s 2s rpm -qf --qf '%{NAME}\t%{VERSION}\t%{VENDOR}\n' -- "$file" 2>/dev/null) || continue
        # 多包归属或非预期包名不作为确定版本证据。
        [[ $row != *$'\n'* ]] || continue
        IFS=$'\t' read -r name version vendor <<< "$row"
        case $name in java-1.8.0-openjdk|java-1.8.0-openjdk-headless|java-1.8.0-openjdk-devel) ;; *) continue ;; esac
        [[ $version =~ $pattern ]] || continue
        version="1.8.0_${BASH_REMATCH[1]}-b${BASH_REMATCH[2]}"
        # RPM 的包名明确标识 OpenJDK；保留真实厂商，不伪造发行商信息。
        printf '%s\t%s\t%s\t%s' "$version" "$vendor" "$name" "$file"
        return 0
    done
    return 1
}

java_name() {
    [[ ${1##*/} =~ ^[Jj][Aa][Vv][Aa][Ww]?(\.[Ee][Xx][Ee])?$ ]]
}

# 列出待盘点的 JDK Home
# 从 .../lib/server/libjvm.so 反推运行时根目录（不含 /proc 前缀）
root_of_lib() { jvm_root_from_lib "" "$1"; }

take_directory_entries() {
    local remaining=$1 entry
    while ((remaining > 0)) && LC_ALL=C IFS= read -r -d '' entry; do
        printf '%s\0' "$entry"
        remaining=$((remaining - 1))
    done
}

bounded_directory_entries() {
    local directory=$1 depth=$2 limit=$3 seconds=$4
    local -a status
    if ((seconds <= 0)); then
        printf 'root_limit\n' >> "$ROOT_COVERAGE_FILE"
        return
    fi
    if ! have timeout || ! have find; then
        printf 'error\n' >> "$ROOT_COVERAGE_FILE"
        return
    fi
    run_timed_command timeout -k 1s "$seconds" find "$directory" -xdev -maxdepth "$depth" -print0 2>/dev/null |
        take_directory_entries "$((limit + 1))"
    status=("${PIPESTATUS[@]}")
    case ${status[0]} in
        0|141) ;;
        124|137) printf 'root_limit\n' >> "$ROOT_COVERAGE_FILE" ;;
        *) printf 'error\n' >> "$ROOT_COVERAGE_FILE" ;;
    esac
}

# --root：在给定目录里找嵌入式运行时的 libjvm.so，反推 Home
scan_root_dirs() {
    local r entry home relative separators remaining=$DIRECTORY_SCAN_LIMIT
    local deadline=$((SECONDS + DIRECTORY_SCAN_SECONDS))
    [ ${#ROOT_ARGS[@]} -gt 0 ] || return 0
    for r in "${ROOT_ARGS[@]}"; do
        if ((remaining == 0 || SECONDS >= deadline)); then
            printf 'root_limit\n' >> "$ROOT_COVERAGE_FILE"
            break
        fi
        if [ ! -d "$r" ]; then
            printf 'error\n' >> "$ROOT_COVERAGE_FILE"
            warn "Cannot search installation directory $r."
            continue
        fi
        r=$(real_path "$r")
        while LC_ALL=C IFS= read -r -d '' entry; do
            if ((remaining == 0 || SECONDS >= deadline)); then
                printf 'root_limit\n' >> "$ROOT_COVERAGE_FILE"
                break
            fi
            remaining=$((remaining - 1))
            if [ -d "$entry" ] && [ ! -L "$entry" ]; then
                relative=${entry#"${r%/}/"}
                separators=${relative//[^\/]/}
                if { [ "$entry" = "$r" ] && [ "$ROOT_DEPTH" -eq 0 ]; } ||
                   { [ "$entry" != "$r" ] && [ "$((${#separators} + 1))" -eq "$ROOT_DEPTH" ]; }; then
                    printf 'boundary\n' >> "$ROOT_COVERAGE_FILE"
                fi
                continue
            fi
            [[ ${entry##*/} == libjvm.so && ( -f $entry || -L $entry ) ]] || continue
            home=$(root_of_lib "$entry")
            [ -n "$home" ] && [ -d "$home" ] || continue
            printf '%s\n' "$(real_path "$home")"
        done < <(bounded_directory_entries "$r" "$ROOT_DEPTH" "$remaining" "$((deadline - SECONDS))")
    done
}

list_roots() {
    local j pat f

    if [ -n "${JAVA_HOME:-}" ] && [ -d "${JAVA_HOME:-}" ]; then
        printf '%s\n' "$(real_path "$(resolve_symlinks "$JAVA_HOME")")"
    fi

    if j=$(command -v java 2>/dev/null); then
        j=$(resolve_symlinks "$j")
        if [ "$OS" != "Darwin" ] || [ "$j" != "/usr/bin/java" ]; then
            printf '%s\n' "$(real_path "$(resolve_symlinks "$(java_root_of "$j")")")"
        fi
    fi

    case $OS in
        Darwin)
            pat="/Library/Java/JavaVirtualMachines/*/Contents/Home/release"
            [ -n "${HOME:-}" ] && pat="$pat $HOME/Library/Java/JavaVirtualMachines/*/Contents/Home/release"
            ;;
        Linux)
            pat="/usr/lib/jvm/*/release /usr/lib64/jvm/*/release /usr/java/*/release \
/opt/java/*/release /opt/jdk*/release /opt/*/release /usr/local/*/release /usr/local/java/*/release"
            ;;
        *)
            pat=""
            ;;
    esac

    for f in $pat; do
        [ -f "$f" ] || continue
        release_is_jdk "$f" || continue
        printf '%s\n' "$(real_path "$(resolve_symlinks "$(dirname "$f")")")"
    done

    scan_root_dirs
}

# ---------------------------------------------------------------------------
# 构建判定（版本 -> fixed|unfixed|outside_scope|candidate|unknown + 依据）
# ---------------------------------------------------------------------------
range_assess() {
    local v=$1 base major first last fixed fixed_note
    if [[ $v =~ ^[0-9]+$ ]]; then
        printf 'unknown\tJava major version %s alone is insufficient to assess the build.' "$v"
        return
    fi
    base=${v%%+*}
    major=${base%%.*}
    major=${major//[!0-9]/}
    case $major in
        17) first="17.0.6";    last="17.0.21.0.3";  fixed="17.0.21.1"
            fixed_note="17.0.21.1 (Oracle) or 17.0.21.1.2 (Corretto)" ;;
        21) first="21.0.0";          last="21.0.13.0.3";  fixed="21.0.13.1"
            fixed_note="21.0.13.1 (Oracle) or 21.0.13.1.2 (Corretto)" ;;
        25) first="25.0.0";          last="25.0.5.0.3";   fixed="25.0.5.1"
            fixed_note="25.0.5.1 (Oracle) or 25.0.5.1.2 (Corretto)" ;;
        27) first="27.0.0";          last="27.0.1.0.3";   fixed="27.0.1.1"
            fixed_note="27.0.1.1 (Oracle) or 27.0.1.1.4 (Corretto)" ;;
        8|11)
            printf 'outside_scope\tOracle does not list standard Java %s builds as affected.' "$major"
            return ;;
        '')
            printf 'unknown\tCannot read the major version from the version string.'
            return ;;
        *)
            printf 'unknown\tThe assessed ranges cover Java 17, 21, 25, and 27. Check the vendor advisory for Java %s.' "$major"
            return ;;
    esac

    if [ "$major" = 17 ] && [ "$(vcmp "$base" "$first")" = 0 ]; then
        local build_number=""
        local build_pattern='\+([0-9]+)'
        if [[ $v =~ $build_pattern ]]; then build_number=${BASH_REMATCH[1]}; fi
        if [ -z "$build_number" ] || ! vge "$build_number" 10; then
            printf 'unknown\tCannot verify that the Java 17.0.6 build meets the affected baseline of +10.'
            return
        fi
    fi

    if vge "$base" "$fixed"; then
        printf 'candidate\tCheck the vendor and full build number against the fixed builds (%s).' "$fixed_note"
    elif [ -n "$first" ] && vlt "$base" "$first"; then
        printf 'outside_scope\tThe version predates the first published affected version (%s).' "$first"
    elif vle "$base" "$last"; then
        printf 'unfixed\tThe version is in the published affected range through %s. Fixed builds are %s.' "$last" "$fixed_note"
    else
        printf 'unknown\tThe version falls between the last known affected build %s and first known fixed build %s. Upgrade to %s.' \
            "$last" "$fixed" "$fixed_note"
    fi
}

recognized_jdk_vendor() {
    local v vm
    v=$(lower "${1:-}")
    vm=$(lower "${2:-}")
    if [ -n "$vm" ]; then
        case $vm in
            *hotspot*|*openjdk*) : ;;
            *) return 1 ;;
        esac
    fi
    case $v in
        openjdk|debian|ubuntu|canonical|"eclipse adoptium"|temurin|"amazon.com inc."|"amazon.com inc"|\
        microsoft|"azul systems, inc."|azul|"red hat, inc."|"red hat"|bellsoft|"sap se"|\
        "eclipse foundation"|"oracle corporation"|oracle)
            return 0 ;;
    esac
    case $vm in
        *openjdk*) return 0 ;;
    esac
    return 1
}

build_assess() {
    local version=${1:-} vendor=${2:-} product=${3:-} vm=${4:-}
    local v vl pl vml base major

    v=$(lower "$(trim "$version")")
    vl=$(lower "$(trim "$vendor")")
    pl=$(lower "$(trim "$product")")
    vml=$(lower "$(trim "$vm")")

    if [ -z "$v" ]; then
        printf 'unknown\tJava version metadata is unavailable from the release file or version output.'
        return
    fi

    case $vml in
        *openj9*)
            printf 'outside_scope\tThe identified VM is OpenJ9. This CVE affects a HotSpot intrinsic.'
            return ;;
    esac

    base=${v%%+*}
    major=${base%%.*}
    major=${major//[!0-9]/}

    # Oracle Java 8 Performance Pack boundaries come from the vendor advisory.
    local legacy_pattern='^(1\.8\.0_[0-9]+(-[A-Za-z0-9.-]+)?|8u[0-9]+(-?b[0-9]+)?(-perf)?)$'
    if [[ $v =~ $legacy_pattern ]]; then
        if [[ $vl == oracle || $vl == "oracle corporation" ]]; then
            case $v in
                8u511b33-perf|1.8.0_511-perf-b33)
                    printf 'unfixed\tThe affected builds include Oracle Java SE 8u511b33-perf.'
                    return ;;
                8u513-perf|1.8.0_513-perf-b4|1.8.0_513-perf-b04)
                    printf 'fixed\tOracle Java SE 8u513-perf is a fixed build.'
                    return ;;
            esac
        fi
        local update legacy_update_pattern='^(1\.8\.0_|8u)([0-9]+)(-b[0-9]+|b[0-9]+)?$'
        if [[ $v =~ $legacy_update_pattern ]]; then
            update=${BASH_REMATCH[2]}
            # 明确的 OpenJDK 产品证据支持 RPM 厂商为 CentOS/Rocky 等发行方的旧构建。
            if [ "$pl" = openjdk ]; then
                printf 'outside_scope\tThe identified standard OpenJDK 8 build is outside the disclosed affected range.'
                return
            fi
            case $vl in
                openjdk|debian|ubuntu|canonical|"eclipse adoptium"|temurin|"amazon.com inc."|"amazon.com inc"|\
                "azul systems, inc."|azul|"red hat, inc."|"red hat")
                    printf 'outside_scope\tThe identified standard OpenJDK 8 build is outside the disclosed affected range.'
                    return ;;
                oracle|"oracle corporation")
                    if vlt "$update" 511; then
                        printf 'outside_scope\tThe identified older standard Oracle Java 8 build is outside the disclosed affected range.'
                        return
                    fi ;;
            esac
        fi
        printf 'unknown\tNo vendor rule applies to this Java 8 build.'
        return
    fi

    # ---- 精确规则：OpenJDK / Oracle OpenJDK 构建 ----
    if [[ ( $vl == openjdk && ( -z $pl || $pl == openjdk ) ) ||
          ( ( $vl == oracle || $vl == "oracle corporation" ) && $pl == openjdk ) ]]; then
        case $v in
            17.0.21.1+2|21.0.13.1+2|25.0.5.1+2|27.0.1.1+4)
                printf 'fixed\tFixed OpenJDK GA tag (%s).' "${base}"
                return ;;
            17.0.21|17.0.21.0.3|21.0.13|21.0.13.0.3|25.0.5|25.0.5.0.3|27.0.1|27.0.1.0.3)
                printf 'unfixed\tAffected OpenJDK GA tag (%s). The build lacks the fix from JDK-8393212.' "${base}"
                return ;;
        esac
    fi

    # ---- 精确规则：Oracle 产品线 ----
    if [ "$vl" = "oracle" ] || [ "$vl" = "oracle corporation" ]; then
        case $pl in
            "oracle java se")
                case $base in
                    8u511b33-perf|1.8.0_511-perf-b33|17.0.21.0.3|21.0.13.0.3|25.0.5.0.3|27.0.1.0.3)
                        printf 'unfixed\tAffected Oracle Java SE build (%s).' "$base"
                        return ;;
                    17.0.21.1|21.0.13.1|25.0.5.1|27.0.1.1)
                        case $v in
                            "$base+4") printf 'fixed\tFixed Oracle Java SE build (%s+4).' "$base"; return ;;
                            "$base"+*)
                                local oracle_lts_pattern='^\+4-lts(-[0-9]+)?$'
                                if [[ ${v#"$base"} =~ $oracle_lts_pattern ]]; then
                                    printf 'fixed\tFixed Oracle Java SE build (%s).' "$v"
                                    return
                                fi ;;
                        esac
                        printf 'unknown\tCannot verify the full fixed build number for Oracle Java SE %s.' "$v"
                        return
                        ;;
                esac ;;
            "oracle graalvm for jdk")
                case $base in
                    17.0.21.0.3|21.0.13.0.3)
                        printf 'unfixed\tAffected Oracle GraalVM for JDK build (%s).' "$base"; return ;;
                esac ;;
            "oracle graalvm enterprise edition")
                case $base in
                    21.3.20.0.3)
                        printf 'unfixed\tAffected Oracle GraalVM Enterprise Edition build (%s).' "$base"; return ;;
                esac ;;
        esac
    fi

    if [[ $vl == "amazon.com inc." || $vl == "amazon.com inc" ]]; then
        local distribution
        distribution=$(lower "${5:-}")
        distribution=${distribution#corretto-}
        case "$v:$distribution" in
            17.0.21.1.2:*|21.0.13.1.2:*|25.0.5.1.2:*|27.0.1.1.4:*|\
            17.0.21.1+2:17.0.21.1.2|17.0.21.1+2-lts:17.0.21.1.2|\
            21.0.13.1+2:21.0.13.1.2|21.0.13.1+2-lts:21.0.13.1.2|\
            25.0.5.1+2:25.0.5.1.2|25.0.5.1+2-lts:25.0.5.1.2|\
            27.0.1.1+4:27.0.1.1.4|27.0.1.1+4-fr:27.0.1.1.4)
                printf 'fixed\tVerified fixed Amazon Corretto release.'
                return ;;
        esac
    fi

    # ---- 精确规则：Debian 构建 ----
    if [ "$vl" = "debian" ]; then
        case $v in
            17.0.19+10-1~deb12u2|17.0.21+9-1~deb12u1|17.0.21.0.3+1-1|\
21.0.12.1+1-1~deb13u1|21.0.13+9-1~deb13u2|21.0.13+9-1-deb13u2-debian|21.0.13.0.3+1-1|\
25.0.3+9-2~deb13u1|25.0.5+8-1~deb13u1|25.0.5+8-1|25.0.5.0.3+1-3|27.0.1.0.3+1-1)
                printf 'unfixed\tThe Debian Security Tracker lists package version %s as affected.' "$v"
                return ;;
        esac
    fi

    case $pl in
        *graalvm*)
            printf 'candidate\tCheck the patch evidence for this GraalVM product and build.'
            return ;;
    esac

    # ---- 版本形态校验 ----
    local version_pattern='^[0-9]{1,3}(\.[0-9]+){0,4}(\+[0-9]+([.-][A-Za-z0-9.~+_-]+)?)?$'
    if [[ ! $v =~ $version_pattern ]]; then
        printf 'unknown\tJava version metadata is unavailable for %s.' "$version"
        return
    fi
    if [ -z "$major" ] || [ "$major" -lt 8 ] || [ "$major" -gt 27 ]; then
        printf 'unknown\tJava %s is outside the assessed version range (8 through 27).' "${major:-?}"
        return
    fi

    # ---- 范围兜底 ----
    local r assess evidence extra=""
    r=$(range_assess "$v")
    assess=${r%%	*}
    evidence=${r#*	}
    if ! recognized_jdk_vendor "$vendor" "$vm"; then
        extra=" The assessment uses the published OpenJDK range because the vendor or product is unverified."
        case $assess in
            fixed|unfixed) assess="candidate" ;;
        esac
    fi
    printf '%s\t%s%s' "$assess" "$evidence" "$extra"
}

# ---------------------------------------------------------------------------
# 缓解参数
#   多次出现按最后一个生效；-XX:UseAVX<=2 视为已缓解
# ---------------------------------------------------------------------------
flag_assessment() {
    local base64=$1 avx=$2
    if [[ $base64 == false || $avx =~ ^0*[0-2]$ ]]; then
        printf 'mitigated'
    elif [[ $base64 == true && $avx =~ ^0*3$ ]]; then
        printf 'unmitigated'
    else
        printf 'unknown'
    fi
}

# ---------------------------------------------------------------------------
# 状态合成
#   classify build cpu mitigated arch -> status
# ---------------------------------------------------------------------------
classify() {
    local build=$1 cpu=$2 mit=$3 feff=$4 arch=$5
    case $build in
        fixed|outside_scope) printf 'not_affected'; return ;;
    esac
    if [ "$cpu" = "absent" ]; then printf 'not_affected'; return; fi
    if [ "$build" = "unknown" ]; then printf 'unknown'; return; fi
    if [ "${6:-process}" != "process" ]; then printf 'potential'; return; fi
    if [ "$mit" -eq 1 ] && [ "$feff" -eq 1 ] && [ "$arch" = "amd64" ]; then printf 'mitigated'; return; fi
    if [ "$build" = "unfixed" ] && [ "$cpu" = "present" ] && [ "$mit" -eq 0 ] && [ "$feff" -eq 1 ]; then
        printf 'affected'; return
    fi
    if [ "$build" = "unfixed" ] && [ "$cpu" = "present" ]; then
        printf 'unknown'
    else
        printf 'potential'
    fi
}

# 生成判定依据
make_reason() {
    local status=$1 build=$2 bevid=$3 cpu=$4 mit=$5 arch=$6
    local reason=""
    case $status in
        not_affected)
            case $build in
                fixed)        reason="The version meets the fixed build requirement." ;;
                outside_scope) reason="Outside the affected range. $bevid" ;;
                *)            reason="The affected path requires x86-64 and all four CPU features (avx512f, avx512bw, avx512vbmi, and bmi2)." ;;
            esac ;;
        unknown)
            reason="Evidence is insufficient. Check the build, CPU, and effective JVM options. $bevid" ;;
        mitigated)
            reason="Effective JVM options disable the Base64 intrinsic or limit AVX to level 2 or lower." ;;
        affected)
            reason="The running JVM build and CPU meet the affected conditions. Effective JVM options leave the affected path enabled. $bevid" ;;
        potential)
            reason="The evidence indicates a potential risk. $bevid"
            [ "$mit" -eq 1 ] && reason="$reason The observed mitigation options still need runtime verification."
            [ "$cpu" = "mixed" ] && reason="$reason Visible logical CPUs report different AVX-512 features."
            [ "$build" = "unfixed" ] && [ "$cpu" = "unknown" ] && reason="$reason CPU conditions are unknown."
            ;;
    esac
    printf '%s' "$reason"
}

# ---------------------------------------------------------------------------
# 资产记录：写入 FIND_FILE（以 ASCII 单元分隔符分隔）
#  1 id 2 kind 3 status 4 reason 5 build 6 build_evidence 7 cpu
#  8 version 9 java_home 10 vendor 11 product 12 vm 13 arch
#  14 flags 15 flags_effective 16 container 17 notes
#  18 identity_confidence 19 disk_version 20 disk_vendor 21 disk_product 22 disk_build
# ---------------------------------------------------------------------------
emit_finding() {
    local id kind status reason build bevid cpu version jhome vendor product vm arch flags feff container notes
    id=$(san_field "${1:-}")
    kind=$(san_field "${2:-}")
    status=$(san_field "${3:-}")
    reason=$(san_field "${4:-}")
    build=$(san_field "${5:-}")
    bevid=$(san_field "${6:-}")
    cpu=$(san_field "${7:-}")
    version=$(san_field "${8:-}")
    jhome=$(san_field "${9:-}")
    vendor=$(san_field "${10:-}")
    product=$(san_field "${11:-}")
    vm=$(san_field "${12:-}")
    arch=$(san_field "${13:-}")
    flags=$(san_field "${14:-}")
    feff=$(san_field "${15:-}")
    container=$(san_field "${16:-}")
    notes=$(san_field "${17:-}")
    local identity_confidence disk_hint_version disk_hint_vendor disk_hint_product disk_hint_build
    identity_confidence=$(san_field "${18:-}")
    disk_hint_version=$(san_field "${19:-}")
    disk_hint_vendor=$(san_field "${20:-}")
    disk_hint_product=$(san_field "${21:-}")
    disk_hint_build=$(san_field "${22:-}")

    printf '%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\n' \
        "$id" "$kind" "$status" "$reason" "$build" "$bevid" "$cpu" "$version" \
        "$jhome" "$vendor" "$product" "$vm" "$arch" "$flags" "$feff" "$container" "$notes" \
        "$identity_confidence" "$disk_hint_version" "$disk_hint_vendor" "$disk_hint_product" "$disk_hint_build" \
        >> "$FIND_FILE"
}

add_note() { NOTES="${NOTES:+$NOTES | }$1"; }

# ---------------------------------------------------------------------------
# 采集：JDK 安装目录
# ---------------------------------------------------------------------------
file_id() {
  local raw device inode
  raw=$(stat -Lc '%d %i' -- "$1" 2>/dev/null) || return 1
  read -r device inode <<< "$raw"
  [[ $device =~ ^[0-9]+$ && $inode =~ ^[0-9]+$ ]] || return 1
  # Decode Linux st_dev. Keep inode as text to preserve all 64 bits.
  printf '%s %s %s' "$(( (device >> 8 & 0xfff) | (device >> 32 & 0xfffff000) ))" \
    "$(( (device & 0xff) | (device >> 12 & 0xffffff00) ))" "$inode"
}

jdk_product() {
    local home=$1 vendor=$2 label graal edition
    case $(lower "$vendor") in
        openjdk) printf 'OpenJDK' ;;
        oracle|"oracle corporation")
            graal=$(release_get "$home/release" GRAALVM_VERSION)
            edition=$(lower "$(release_get "$home/release" GRAALVM_EDITION)")
            label=$(lower "$(printf '%s %s %s' "$edition" \
                "$(release_get "$home/release" IMPLEMENTOR_VERSION)" \
                "$(release_get "$home/release" JAVA_RUNTIME_NAME)")")
            case "$label" in
                *"enterprise edition"*|*"graalvm enterprise"*)
                    printf 'Oracle GraalVM Enterprise Edition'
                    return ;;
            esac
            if [[ $edition == ee && $graal == 21.3.* ]]; then
                printf 'Oracle GraalVM Enterprise Edition'
                return
            fi
            case "$graal $label" in
                *graalvm*) printf 'Oracle GraalVM for JDK'; return ;;
            esac
            if [ -n "$graal" ]; then printf 'Oracle GraalVM for JDK'; return; fi
            case $label in
                *"java(tm)"*|*"java se"*) printf 'Oracle Java SE' ;;
                *openjdk*) printf 'OpenJDK' ;;
                *)
                    if [ -f "$home/README" ] &&
                       head -c 65536 "$home/README" 2>/dev/null | grep -q 'Thank you for using the Oracle JDK.'; then
                        printf 'Oracle Java SE'
                    fi ;;
            esac ;;
    esac
}

assess_jdk_build() {
    local home=$1 version=$2 vendor=$3 product=$4 vm=$5 distribution="" graal=""
    if [ -n "$home" ]; then
        distribution=$(release_get "$home/release" IMPLEMENTOR_VERSION)
        if [ "$product" = "Oracle GraalVM Enterprise Edition" ]; then
            graal=$(release_get "$home/release" GRAALVM_VERSION)
            local graal_pattern='^[0-9]+(\.[0-9]+){1,4}$'
            if [[ $graal =~ $graal_pattern ]]; then
                version=$graal
            fi
        fi
    fi
    build_assess "$version" "$vendor" "$product" "$vm" "$distribution"
}

scan_installations() {
    local root version vendor product vm arch notes build cpu status mit flags feff vmname vmtext openj9
    local bevid reason bevid_and_build lib lib_id matched rpm_meta rpm_name rpm_file

    while IFS= read -r root; do
        [ -n "$root" ] || continue
        matched=0
        for lib in "$root"/lib/libjvm.so "$root"/lib/*/libjvm.so                    "$root"/lib/*/*/libjvm.so "$root"/jre/lib/*/libjvm.so "$root"/jre/lib/*/*/libjvm.so; do
            [ -f "$lib" ] || continue
            lib_id=$(file_id "$lib") || continue
            if grep -Fxq -- "$lib_id" "$ACTIVE_FILE"; then matched=1; break; fi
        done
        [ "$matched" -eq 0 ] || continue
        NOTES=""
        version=""; vendor=""; product=""; vm=""; arch=""; vmname=""
        build="unknown"; bevid=""

        if [ -r "$root/release" ]; then
            version=$(release_get "$root/release" JAVA_RUNTIME_VERSION)
            [ -n "$version" ] || version=$(release_get "$root/release" JAVA_VERSION)
            vendor=$(release_get "$root/release" IMPLEMENTOR)
            vm=$(release_get "$root/release" JVM_VARIANT)
            vmname=$(release_get "$root/release" JAVA_VM_NAME)
            arch=$(release_get "$root/release" OS_ARCH)
            [ -n "$version" ] || add_note "The release file lacks JAVA_VERSION and JAVA_RUNTIME_VERSION."
        else
            add_note "The release file is missing. This directory can be an incomplete JDK or an embedded JRE."
        fi

        product=$(jdk_product "$root" "$vendor")
        # 老版 CentOS/RHEL OpenJDK 8 可无 release，按实际文件的 RPM 归属补充磁盘版本。
        if [ -z "$version" ]; then
            rpm_meta=$(installation_rpm_metadata "$root") || rpm_meta=""
            if [ -n "$rpm_meta" ]; then
                IFS=$'\t' read -r version vendor rpm_name rpm_file <<< "$rpm_meta"
                product="OpenJDK"
                add_note "RPM file ownership supplies the disk version. Package=$rpm_name Vendor=$vendor File=$rpm_file"
            else
                add_note "Cannot obtain the version from OpenJDK 8 RPM file ownership."
            fi
        fi

        if [ -z "$arch" ]; then
            arch=$ARCH_RAW
            add_note "The release file lacks OS_ARCH. The assessment uses the host architecture ($ARCH_RAW)."
        fi

        cpu=$(cpu_assess "$arch" "$CPU_STATE")
        bevid_and_build=$(assess_jdk_build "$root" "$version" "$vendor" "$product" "$vm")
        build=$(printf '%s' "$bevid_and_build" | cut -f1)
        bevid=$(printf '%s' "$bevid_and_build" | cut -f2-)

        flags=""
        feff="false"
        mit=0
        [ "$build" = "" ] && build="unknown"

        vmtext=$(lower "${vm:-} ${vmname:-}")
        case $vmtext in *openj9*) openj9=1 ;; *) openj9=0 ;; esac
        if [ "$openj9" -eq 1 ]; then
            build="outside_scope"
            bevid="Eclipse OpenJ9 supplies its own Base64 implementation."
            status="not_affected"
            reason="OpenJ9 is outside the scope of this HotSpot CVE."
            add_note "OpenJ9 supplies its own Base64 implementation. Check the vendor advisory for OpenJ9."
        else
            status=$(classify "$build" "$cpu" "$mit" 0 "$(norm_arch "$arch")" installation)
            reason=$(make_reason "$status" "$build" "$bevid" "$cpu" "$mit" "$(norm_arch "$arch")")
        fi

        emit_finding "install:$root" "installation" "$status" "$reason" "$build" "$bevid" \
            "$cpu" "$version" "$root" "$vendor" "$product" "$vm" "$arch" "$flags" "$feff" "" "$NOTES"
    # 先归一化再去重，避免 JAVA_HOME 指向 jre 时与父 JDK 重复清点。
    done < <(list_roots | while IFS= read -r root; do
        normalize_java_root "$root"
        printf '\n'
    done | LC_ALL=C sort -u)
}

# ---------------------------------------------------------------------------
# 采集：进程
# ---------------------------------------------------------------------------
linux_process_paths() {
    local -a status
    find /proc -ignore_readdir_race -mindepth 1 -maxdepth 1 -name '[0-9]*' -print 2>/dev/null |
        head -n "$((PROCESS_SCAN_LIMIT + 1))"
    status=("${PIPESTATUS[@]}")
    [[ ${status[1]} == 0 && ( ${status[0]} == 0 || ${status[0]} == 141 ) ]]
}

process_visibility_limited() {
    local proc_status
    [[ $OS == Linux && -r /proc/self/mountinfo ]] || return 0
    [[ -r /proc/1/comm ]] || return 0
    [[ -z $(container_hint /proc/self) ]] || return 0
    proc_status=$(awk '
        $5 == "/proc" {
            for (i = 7; i <= NF && $i != "-"; i++) {}
            if ($(i + 1) != "proc") next
            found = 1
            if ($4 != "/") limited = 1
            n = split($6 "," $(i + 3), options, ",")
            for (j = 1; j <= n; j++)
                if (options[j] ~ /^hidepid=/ && options[j] !~ /^hidepid=(0|off)$/) limited = 1
        }
        END { if (found && !limited) print "full" }
    ' /proc/self/mountinfo 2>/dev/null) || return 0
    [[ $proc_status != full ]]
}

java_budget_reached() {
    [[ $JAVA_PROC_BUDGET_REACHED == true || $JAVA_MAP_BUDGET_REACHED == true ||
       $JAVA_ROOT_BUDGET_REACHED == true ]]
}

java_process_start() {
    sed 's/^.*) //' "/proc/$1/stat" 2>/dev/null | awk '{print $20}'
}

libjvm_meta() {
    local LC_ALL=C used limit remaining data read_rc=0
    IFS= read -r used < "$WORK/map-bytes" || return 1
    remaining=$((MAP_SCAN_TOTAL_BYTES - used))
    if ((remaining <= 0)); then
        : > "$WORK/map-total-limit"
        return 1
    fi
    limit=$MAP_SCAN_MAX_BYTES
    if ((remaining < limit)); then limit=$remaining; fi
    # The sentinel preserves the trailing newline so the byte count includes it.
    data=$(head -c "$limit" -- "$1/maps" 2>/dev/null; read_rc=$?; printf '.'; exit "$read_rc") || read_rc=$?
    data=${data%.}
    used=$((used + ${#data}))
    printf '%s\n' "$used" > "$WORK/map-bytes" || return 1
    if ((${#data} >= limit)); then
        if ((used >= MAP_SCAN_TOTAL_BYTES)); then
            : > "$WORK/map-total-limit"
        else
            printf 'map_limit\n' >> "$ROOT_COVERAGE_FILE"
        fi
        return 1
    fi
    ((read_rc == 0)) || return 1
    awk '
        /\/libjvm\.so( \(deleted\))?$/ && $5 != "0" {
            dev = $4; inode = $5; path = $0
            for (i = 0; i < 5; i++) sub(/^[[:space:]]*[^[:space:]]+/, "", path)
            sub(/^[[:space:]]+/, "", path)
            if (path !~ /^\//) next
            row = dev "\037" inode "\037" path
            if (!seen[row]++) print row "\037" $1
        }
    ' <<< "$data"
}

mapping_identity() {
    local proc=$1 range=$2 expected=$3 disk=$4 mapped
    if [[ $disk == "$expected" ]]; then
        printf 'maps'
        return
    fi
    [[ ${disk##* } == "${expected##* }" && $range =~ ^[[:xdigit:]]+-[[:xdigit:]]+$ ]] || return 1
    mapped=$(file_id "$proc/map_files/$range") || return 2
    [[ $mapped == "$disk" ]] || return 1
    printf 'map_files'
}

jcmd_version() {
    local pid=$1 jc=$2 out
    have timeout || return 1
    out=$(run_timed_command timeout -k 1s 3s "$jc" "$pid" VM.version 2>/dev/null) || return 1
    printf '%s\n' "$out" | awk '
        / VM version / {
            for (i = 1; i < NF; ++i) {
                if ($i == "version" && $(i+1) ~ /^[0-9]+([._][0-9]+)*\+([0-9]+)([-.][A-Za-z0-9._~+-]+)?$/) {
                    full = $(i+1)
                    exit
                }
            }
        }
        $1 == "JDK" && $2 ~ /^[0-9]+([._][0-9]+)*$/ { short = $2 }
        END {
            if (full != "") print full
            else if (short != "") print short
            else exit 1
        }
    '
}

runtime_version_conflicts() {
    local runtime=$1 disk=$2
    [[ $runtime == *+* && -n $disk ]] || return 1
    if [[ $disk == *+* ]]; then
        [[ $(lower "$runtime") != "$(lower "$disk")" ]]
    else
        [[ ${runtime%%+*} != "$disk" ]]
    fi
}

jcmd_bin() {
    type -P jcmd || :
}

# JVM 是否注册了 SIGQUIT 处理器（attach 监听器的前提）
handles_sigquit() {
    local f=$1/status mask
    [ -r "$f" ] || return 1
    mask=$(awk '$1 == "SigCgt:" { print $2; exit }' "$f" 2>/dev/null)
    [ -n "$mask" ] || return 1
    case ${mask: -1} in
        [0-9a-fA-F]) ;;
        *) return 1 ;;
    esac
    [ $(( 16#${mask: -1} & 4 )) -ne 0 ]
}

# 用 jcmd 读真实生效 flags，输出 "UseBASE64Intrinsics UseAVX"（未知为 unknown）
jcmd_flags() {
    local pid=$1 jc=$2 out="" b64="" avx=""
    have timeout || return 1
    out=$(run_timed_command timeout -k 1s 3s "$jc" "$pid" VM.flags -all 2>/dev/null) || return 1
    [ -n "$out" ] || return 1
    b64=$(printf '%s\n' "$out" | awk '$2 == "UseBASE64Intrinsics" && ($3 == "=" || $3 == ":=") { print $4; exit }')
    avx=$(printf '%s\n' "$out" | awk '$2 == "UseAVX" && ($3 == "=" || $3 == ":=") { print $4; exit }')
    [ -n "$b64" ] || [ -n "$avx" ] || return 1
    printf '%s %s\n' "${b64:-unknown}" "${avx:-unknown}"
}

jvm_root_from_lib() {
    local proc=$1 lib=$2 server libdir root
    server=${lib%/*}
    [ "${server##*/}" = "server" ] || { printf ''; return; }
    libdir=${server%/*}
    case ${libdir##*/} in
        amd64|i386) libdir=${libdir%/*} ;;
    esac
    [ "${libdir##*/}" = "lib" ] || { printf ''; return; }
    root="${libdir%/*}"
    if [ -n "$proc" ]; then root="$proc/root$root"; fi
    normalize_java_root "$root"
}

container_hint() {
    local proc=$1 line ns initns
    if [ -r "$proc/cgroup" ]; then
        while IFS= read -r line; do
            case $(lower "$line") in
                *kubepods*)   printf 'kubepods (cgroup hint)'; return ;;
                *docker*)     printf 'docker (cgroup hint)'; return ;;
                *libpod*)     printf 'libpod (cgroup hint)'; return ;;
                *containerd*) printf 'containerd (cgroup hint)'; return ;;
                */lxc*)       printf 'lxc (cgroup hint)'; return ;;
                *cri-o*|*crio-*) printf 'cri-o (cgroup hint)'; return ;;
            esac
        done < "$proc/cgroup"
    fi
    if [ -e "$proc/root/.dockerenv" ]; then printf 'docker (root marker)'; return; fi
    if [ -e "$proc/root/run/.containerenv" ]; then printf 'container (root marker)'; return; fi
    ns=$(readlink "$proc/ns/pid" 2>/dev/null || echo "")
    initns=$(readlink /proc/1/ns/pid 2>/dev/null || echo "")
    if [ -n "$ns" ] && [ -n "$initns" ] && [ "$ns" != "$initns" ]; then
        printf 'Separate PID namespace'
        return
    fi
    printf ''
}

# 从 cmdline 提取启动参数（跳过 -cp/-jar 等及其值）
launcher_flags() {
    local f=$1 arg i=1 n out="" args=()
    [ -r "$f" ] || { printf ''; return; }
    while IFS= read -r -d '' arg; do
        args[${#args[@]}]="$arg"
    done < "$f" 2>/dev/null
    n=${#args[@]}
    while [ "$i" -lt "$n" ]; do
        arg=${args[$i]}
        case $arg in
            -cp|-classpath|--class-path|-p|--module-path|--upgrade-module-path|\
--add-modules|--limit-modules|--add-exports|--add-opens|--add-reads|\
--patch-module|--source|--enable-native-access)
                i=$((i + 2)); continue ;;
        esac
        case $arg in
            -jar|-m|--module|--module=*|--) break ;;
            -*)
                case $arg in
                    -XX:-UseBASE64Intrinsics|-XX:+UseBASE64Intrinsics) out="$out $arg" ;;
                    -XX:UseAVX=*) out="$out $arg" ;;
                esac ;;
            *) break ;;
        esac
        i=$((i + 1))
    done
    printf '%s' "${out# }"
}

scan_processes() {
    local pid proc exe exe_clean comm named has_jvm maps_ok explicit=0
    local libmeta libpath libdev libino st mhex nhex verified range expected identity_source identity_rc
    local root root_disp version vendor product vm arch build bevid cpu status reason
    local flags feff mit fn notes container start1 start2
    local measured_state b64 eavx reported_version
    local bevid_and_build verify_problem libmeta2 libmeta3 jc jcf vmname vmtext
    local runtime_version disk_version version_conflict weak_identity
    local identity_confidence disk_hint_version disk_hint_vendor disk_hint_product disk_hint_build

    local pidlist
    if [ ${#PID_ARGS[@]} -gt 0 ]; then
        explicit=1
        pidlist=$(printf '%s\n' ${PID_ARGS[@]+"${PID_ARGS[@]}"})
    elif [ "$OS" = "Linux" ]; then
        pidlist=$(linux_process_paths) || JAVA_PROC_SCAN_UNAVAILABLE=true
    else
        return
    fi

    while IFS= read -r pid; do
        [ -n "$pid" ] || continue
        if ((JAVA_PROC_ENTRIES >= PROCESS_SCAN_LIMIT)); then
            JAVA_PROC_BUDGET_REACHED=true
            break
        fi
        if [[ -f $WORK/map-total-limit ]]; then break; fi
        JAVA_PROC_ENTRIES=$((JAVA_PROC_ENTRIES + 1))
        pid=${pid#/proc/}
        proc="/proc/$pid"
        NOTES=""

        if [ ! -d "$proc" ]; then
            if [ "$explicit" -eq 1 ]; then
                emit_finding "pid:$pid" "process" "unknown" \
                    "The process is absent or has exited. No evidence is available." "unknown" "Process is absent" \
                    "$(cpu_assess "$ARCH_RAW" "$CPU_STATE")" "" "" "" "" "" "$ARCH_RAW" "" "false" "" ""
            fi
            continue
        fi

        start1=$(java_process_start "$pid")

        exe=$(readlink "$proc/exe" 2>/dev/null || echo "")
        exe_clean=${exe% (deleted)}
        named=0
        java_name "$exe_clean" && named=1
        if [ "$named" -eq 0 ] && [ -r "$proc/comm" ]; then
            comm=$(tr -d '\n' < "$proc/comm" 2>/dev/null)
            java_name "$comm" && named=1
        fi

        has_jvm=0
        maps_ok=1
        if libmeta=$(libjvm_meta "$proc"); then
            [ -z "$libmeta" ] || has_jvm=1
        else
            maps_ok=0
            if [ -d "$proc" ]; then LIMITED_PROCS=$((LIMITED_PROCS + 1)); fi
        fi
        if [ "$maps_ok" -eq 0 ] && { [ "$explicit" -eq 1 ] || [ "$named" -eq 1 ]; }; then
            emit_finding "pid:$pid" "process" "unknown" "Cannot verify the running JVM because its process maps are unreadable." \
                "unknown" "Unreadable process maps" "$(cpu_assess "$ARCH_RAW" "$CPU_STATE")" \
                "" "" "" "" "" "$ARCH_RAW" "" "false" "" ""
            continue
        fi

        if [ "$named" -eq 0 ] && [ "$has_jvm" -eq 0 ]; then
            if [ "$explicit" -eq 1 ]; then
                emit_finding "pid:$pid" "process" "unknown" \
                    "Cannot identify a Java launcher or HotSpot mapping for this PID." "unknown" "Java process unverified" \
                    "$(cpu_assess "$ARCH_RAW" "$CPU_STATE")" "" "" "" "" "" "$ARCH_RAW" "" "false" "" ""
            fi
            continue
        fi

        # File identity and JVM version evidence have independent lifetimes.
        verified=0
        weak_identity=0
        version_conflict=0
        identity_source=""
        runtime_version=""
        disk_version=""
        root=""
        libpath=""
        st=""
        verify_problem=""
        if [[ -n $libmeta && $libmeta != *$'\n'* ]]; then
            IFS=$'\037' read -r libdev libino libpath range <<< "$libmeta"
            mhex=${libdev%%:*}
            nhex=${libdev##*:}
            if [[ $libpath == *" (deleted)" ]]; then
                verify_problem="The mapped HotSpot library was deleted. Cannot check the disk file."
            elif ! st=$(file_id "$proc/root$libpath"); then
                verify_problem="Cannot read the identity of the corresponding libjvm.so file on disk."
            elif [[ $mhex =~ ^[[:xdigit:]]+$ && $nhex =~ ^[[:xdigit:]]+$ ]]; then
                expected="$((16#$mhex)) $((16#$nhex)) $libino"
                identity_rc=0
                identity_source=$(mapping_identity "$proc" "$range" "$expected" "$st") || identity_rc=$?
                case $identity_rc in
                    0) verified=1 ;;
                    2) weak_identity=1 ;;
                    *) verify_problem="Cannot match the running mapping to a disk file." ;;
                esac
                if [ "$identity_source" = map_files ] || [ "$weak_identity" -eq 1 ] ||
                   [ "$identity_rc" -ne 0 ]; then
                    add_note "Mapping device and inode $expected. Disk stat $st."
                fi
                if [ "$weak_identity" -eq 1 ]; then
                    add_note "The inodes match, and the device numbers differ. Cannot read map_files to verify the identity."
                fi
                if [ "$verified" -eq 1 ] || [ "$weak_identity" -eq 1 ]; then
                    root=$(jvm_root_from_lib "$proc" "$libpath")
                fi
            fi
        elif [[ -n $libmeta ]]; then
            verify_problem="The process maps several distinct HotSpot libraries. Cannot identify the active build."
        fi

        version=""; vendor=""; product=""; vm=""; arch=""
        if [ -n "$root" ] && [ -r "$root/release" ]; then
            version=$(release_get "$root/release" JAVA_RUNTIME_VERSION)
            [ -n "$version" ] || version=$(release_get "$root/release" JAVA_VERSION)
            vendor=$(release_get "$root/release" IMPLEMENTOR)
            vm=$(release_get "$root/release" JVM_VARIANT)
            vmname=$(release_get "$root/release" JAVA_VM_NAME)
            arch=$(release_get "$root/release" OS_ARCH)
            product=$(jdk_product "$root" "$vendor")
            disk_version=$version
            if [ "$weak_identity" -eq 1 ]; then
                add_note "Unverified build from the disk release file (${disk_version:-unknown})."
            fi
            case $identity_source in
                maps) add_note "The HotSpot mapping and disk JDK file have the same device number and inode." ;;
                map_files) add_note "The device number and inode from map_files match the disk file." ;;
            esac
            root_disp=${root#"$proc/root"}
            [ -n "$root_disp" ] || root_disp=$root
            if ! libmeta2=$(libjvm_meta "$proc") || [ "$libmeta2" != "$libmeta" ]; then
                verify_problem="The process mappings changed during collection."
            fi
        else
            root_disp=""
            if [ -n "$verify_problem" ]; then
                add_note "$verify_problem The disk launcher version cannot verify the running build."
            else
                add_note "Cannot verify the JVM identity or release metadata. Check process ownership, deleted files, and /proc access."
            fi
        fi
        [ -n "$arch" ] || arch=$ARCH_RAW

        if { [ "$verified" -ne 1 ] && [ "$weak_identity" -ne 1 ]; } || [ -n "$verify_problem" ]; then
            verify_problem=${verify_problem:-Cannot verify the running JVM image.}
            container=$(container_hint "$proc")
            start2=$(java_process_start "$pid")
            [ "$start1" = "$start2" ] || verify_problem="The process exited or its identity changed during collection."
            emit_finding "pid:$pid" "process" "unknown" "$verify_problem" "unknown" "$verify_problem" \
                "$(cpu_assess "$arch" "$CPU_STATE")" "$version" "$root_disp" "$vendor" "$product" "$vm" "$arch" \
                "" "false" "$container" "$NOTES"
            continue
        fi

        # --- 缓解参数 ---
        flags=""
        if [ "$named" -eq 1 ] || [ "$has_jvm" -eq 1 ]; then
            flags=$(launcher_flags "$proc/cmdline")
        fi
        feff="false"
        if [ -n "$flags" ]; then
            # 启动参数是可信的"启动证据"，但 JVM 有效值仍需按实际进程确认
            add_note "Startup option hints (${flags}). The effective JVM options are unverified."
        fi

        # --- 生效参数（--jcmd，可选）：读 JVM 真实生效值，而不是启动器写法 ---
        measured_state=
        if [ "$JCMD" -eq 1 ] && [ "$has_jvm" -eq 1 ]; then
            jc=$(jcmd_bin)
            if [ -z "$jc" ]; then
                add_note "Cannot query effective JVM options because jcmd is absent from PATH."
            elif [ "$(stat -c %u "$proc" 2>/dev/null)" != "$(id -u)" ]; then
                add_note "The target JVM has a different owner. jcmd cannot attach."
            elif ! handles_sigquit "$proc"; then
                add_note "The target JVM has no SIGQUIT handler. The scan skips jcmd."
            elif [ -n "$start1" ] && [ "$(java_process_start "$pid")" = "$start1" ] &&
                 [ "$(libjvm_meta "$proc")" = "$libmeta" ]; then
                if jcf=$(jcmd_flags "$pid" "$jc"); then
                    read -r b64 eavx <<< "$jcf"
                    measured_state=$(flag_assessment "$b64" "$eavx")
                    if [ "$measured_state" != unknown ]; then feff=true; fi
                    add_note "Effective JVM options from jcmd (UseBASE64Intrinsics=$b64 UseAVX=$eavx)."
                    if [ "$measured_state" = unknown ]; then
                        add_note "The effective JVM options are insufficient to verify mitigation."
                    fi
                else
                    add_note "The jcmd options query failed. The startup options are unverified hints."
                fi
                if [ "$(java_process_start "$pid")" = "$start1" ] &&
                   [ "$(libjvm_meta "$proc")" = "$libmeta" ] &&
                   reported_version=$(jcmd_version "$pid" "$jc"); then
                    if [[ $reported_version == *+* ]]; then
                        runtime_version=$reported_version
                        add_note "Running build from jcmd ($runtime_version). Disk release build (${disk_version:-unknown})."
                        if runtime_version_conflicts "$runtime_version" "$disk_version"; then
                            version_conflict=1
                        fi
                    else
                        add_note "jcmd reports a short version ($reported_version). Cannot verify the running build number."
                    fi
                fi
            else
                add_note "The jcmd query failed or timed out. The startup options are unverified hints."
            fi
        fi

        container=$(container_hint "$proc")

        # --- 采集期间身份是否变化 ---
        start2=$(java_process_start "$pid")
        if [ -z "$start1" ] || [ "$start1" != "$start2" ] || [ ! -d "$proc" ] ||
           ! libmeta3=$(libjvm_meta "$proc") ||
           [ "$libmeta3" != "$libmeta" ] || [ "$(file_id "$proc/root$libpath")" != "$st" ] ||
           { [ "$identity_source" = map_files ] && [ "$(file_id "$proc/map_files/$range")" != "$st" ]; }; then
            emit_finding "pid:$pid" "process" "unknown" "The process exited or its identity changed during collection." \
                "unknown" "Process exited" "$(cpu_assess "$arch" "$CPU_STATE")" "" "" "" "" "" "$arch" "" "false" "" ""
            continue
        fi

        if [ "$verified" -eq 1 ] && [ "$version_conflict" -eq 0 ]; then
            printf '%s\n' "$st" >> "$ACTIVE_FILE"
        fi

        cpu=$(cpu_assess "$arch" "$CPU_STATE")
        bevid_and_build=$(assess_jdk_build "$root" "$version" "$vendor" "$product" "$vm")
        build=$(printf '%s' "$bevid_and_build" | cut -f1)
        bevid=$(printf '%s' "$bevid_and_build" | cut -f2-)
        [ -n "$build" ] || build="unknown"

        vmtext=$(lower "${vm:-} ${vmname:-}")
        case $vmtext in *openj9*) openj9=1 ;; *) openj9=0 ;; esac

        fn=0
        mit=0
        case $measured_state in
            mitigated) fn=1; mit=1 ;;
            unmitigated) fn=1 ;;
        esac
        identity_confidence=strong
        [ "$weak_identity" -eq 0 ] || identity_confidence=weak
        disk_hint_version="" disk_hint_vendor="" disk_hint_product="" disk_hint_build=""
        if [ "$weak_identity" -eq 1 ] || [ "$version_conflict" -eq 1 ]; then
            disk_hint_version=$disk_version
            disk_hint_vendor=$vendor
            disk_hint_product=$product
            disk_hint_build=$build
        fi

        if [ "$version_conflict" -eq 1 ]; then
            status=unknown
            reason="The running build from jcmd differs from the build in the disk release file."
            build=unknown
            bevid=$reason
            version=$runtime_version
            vendor="" product="" vm=""
        elif [ "$weak_identity" -eq 1 ]; then
            status=potential
            reason="The inodes match, and the device numbers differ. The disk build is an unverified hint."
            if [ "$disk_hint_build" = unfixed ]; then
                reason="$reason The disk build is in the affected range."
            fi
            build=candidate
            bevid=$reason
            if [ -n "$runtime_version" ]; then
                version=$runtime_version
                vendor="" product=""
            else
                version=$disk_hint_version
                vendor=$disk_hint_vendor
                product=$disk_hint_product
            fi
            vm=""
        elif [ "$openj9" -eq 1 ]; then
            build="outside_scope"
            bevid="Eclipse OpenJ9 supplies its own Base64 implementation."
            status="not_affected"
            reason="OpenJ9 is outside the scope of this HotSpot CVE."
            add_note "OpenJ9 supplies its own Base64 implementation. Check the vendor advisory for OpenJ9."
        else
            status=$(classify "$build" "$cpu" "$mit" "$fn" "$(norm_arch "$arch")")
            reason=$(make_reason "$status" "$build" "$bevid" "$cpu" "$mit" "$(norm_arch "$arch")")
        fi

        emit_finding "pid:$pid" "process" "$status" "$reason" "$build" "$bevid" \
            "$cpu" "$version" "$root_disp" "$vendor" "$product" "$vm" "$arch" \
            "$flags" "$feff" "$container" "$NOTES" \
            "$identity_confidence" "$disk_hint_version" "$disk_hint_vendor" "$disk_hint_product" "$disk_hint_build"
    done <<< "$pidlist"
}

# 非 Linux 平台：仅能做启动器级别的线索（Go 版在 macOS 上同样不校验运行库）
scan_processes_other() {
    local pid exe root notes version vendor product vm arch cpu build bevid status reason bevid_and_build
    product=""
    if ! have ps; then JAVA_PROC_SCAN_UNAVAILABLE=true; return; fi
    while read -r pid exe; do
        [ -n "$pid" ] || continue
        [ -n "$exe" ] || continue
        if ((JAVA_PROC_ENTRIES >= PROCESS_SCAN_LIMIT)); then
            JAVA_PROC_BUDGET_REACHED=true
            break
        fi
        JAVA_PROC_ENTRIES=$((JAVA_PROC_ENTRIES + 1))
        java_name "$exe" || continue
        NOTES=""
        root=$(java_root_of "$exe")
        version=""; vendor=""; vm=""; arch=""
        if [ -r "$root/release" ]; then
            version=$(release_get "$root/release" JAVA_RUNTIME_VERSION)
            [ -n "$version" ] || version=$(release_get "$root/release" JAVA_VERSION)
            vendor=$(release_get "$root/release" IMPLEMENTOR)
            vm=$(release_get "$root/release" JVM_VARIANT)
            arch=$(release_get "$root/release" OS_ARCH)
            add_note "The scan uses the disk launcher version because the running library is unverified."
        else
            add_note "The release file is missing."
        fi
        [ -n "$arch" ] || arch=$ARCH_RAW
        cpu=$(cpu_assess "$arch" "$CPU_STATE")
        bevid_and_build=$(build_assess "$version" "$vendor" "$product" "$vm")
        build=$(printf '%s' "$bevid_and_build" | cut -f1)
        bevid=$(printf '%s' "$bevid_and_build" | cut -f2-)
        [ -n "$build" ] || build="unknown"
        status=$(classify "$build" "$cpu" 0 0 "$(norm_arch "$arch")" installation)
        reason=$(make_reason "$status" "$build" "$bevid" "$cpu" 0 "$(norm_arch "$arch")")
        emit_finding "pid:$pid" "process" "$status" "$reason" "$build" "$bevid" \
            "$cpu" "$version" "$root" "$vendor" "$product" "$vm" "$arch" "" "false" "" "$NOTES"
    done < <(ps -axww -o pid=,comm= 2>/dev/null | head -n "$((PROCESS_SCAN_LIMIT + 1))")
}

# ---------------------------------------------------------------------------
# 报告
# ---------------------------------------------------------------------------
total_count() { wc -l < "$FIND_FILE" 2>/dev/null | tr -d ' '; }
status_count() { awk -F'\037' -v s="$1" '$3 == s { c++ } END { print c + 0 }' "$FIND_FILE"; }

# Preserve valid UTF-8 and replace malformed bytes before writing JSON.
json_escape() {
    printf '%s' "${1:-}" | LC_ALL=C awk '
        function utf8_width(line, offset,    lead, width, code, j) {
            lead=octet[substr(line,offset,1)]
            if (lead >= 194 && lead <= 223) width=2
            else if (lead >= 224 && lead <= 239) width=3
            else if (lead >= 240 && lead <= 244) width=4
            else return 0
            if (offset+width-1 > length(line)) return 0

            code=octet[substr(line,offset+1,1)]
            # Reject overlong encodings, surrogate code points and values above U+10FFFF.
            if ((lead==224 && code<160) || (lead==237 && code>=160) ||
                (lead==240 && code<144) || (lead==244 && code>=144)) return 0
            for (j=1; j<width; j++) {
                code=octet[substr(line,offset+j,1)]
                if (code<128 || code>191) return 0
            }
            return width
        }
        BEGIN {
            for (i=1; i<32; i++) controls[sprintf("%c",i)]=sprintf("\\u%04x",i)
            for (i=128; i<256; i++) octet[sprintf("%c",i)]=i
        }
        { if (NR>1) printf "\\n"
          for (i=1; i<=length($0); i++) {
              c=substr($0,i,1)
              if (c=="\\") printf "\\\\"
              else if (c=="\"") printf "\\\""
              else if (c in controls) printf "%s",controls[c]
               else if (c in octet) {
                   width=utf8_width($0,i)
                   if (width==0) printf "\\ufffd"
                   else {
                       printf "%s",substr($0,i,width)
                       i+=width-1
                   }
               }
              else printf "%s",c
          }
        }'
}

jstr() {
    local escaped
    # A trailing marker lets awk preserve any final newline in the original value.
    escaped=$(json_escape "${1:-}.")
    printf '"%s"' "${escaped%.}"
}

# ---------------------------------------------------------------------------
# 参数解析
# ---------------------------------------------------------------------------
parse_args() {
    while [ $# -gt 0 ]; do
        case $1 in
            -h|--help)    usage; exit 0 ;;
            -V|--version) printf '%s %s\n' "$PROG" "$SCRIPT_VERSION"; exit 0 ;;
            --pid)        [ $# -ge 2 ] || die "--pid requires a process ID."
                          case $2 in ''|*[!0-9]*) die "--pid requires a positive integer." ;; esac
                          PID_ARGS[${#PID_ARGS[@]}]=$2; shift 2 ;;
            --json)       shift ;;
            --root)       [ $# -ge 2 ] || die "--root requires a directory."
                          ROOT_ARGS[${#ROOT_ARGS[@]}]=$2; shift 2 ;;
            --root-depth) [ $# -ge 2 ] || die "--root-depth requires a number."
                          case $2 in ''|*[!0-9]*) die "--root-depth requires a non-negative integer." ;; esac
                          ROOT_DEPTH=$2; shift 2 ;;
            --jcmd)       JCMD=1; shift ;;
            --processes-only) PROC_ONLY=1; shift ;;
            --no-processes)   NO_PROC=1; shift ;;
            --)           shift
                          [ "$#" -eq 0 ] || die "Unexpected argument after --. See --help."
                          break ;;
            -*)           die "Unknown Java option. See --help." ;;
            *)            die "Unexpected Java argument. See --help." ;;
        esac
    done

    if [ "$PROC_ONLY" -eq 1 ] && [ "$NO_PROC" -eq 1 ]; then
        die "Use either --processes-only or --no-processes."
    fi
    if [ "$PROC_ONLY" -eq 1 ] && [ ${#ROOT_ARGS[@]} -gt 0 ]; then
        die "Use --root without --processes-only."
    fi

}

cleanup() {
    [ -n "${WORK:-}" ] && [ -d "$WORK" ] && rm -rf "$WORK"
}

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
# Nginx2Root mode reuses the report format helpers and only reads local files.
NGINX_SITE_CONFIG=/apps/svr/nginx/conf/nginx.conf
NGINX_CONFIG_DIRECTORY_LIMIT=4096
NGINX_CONFIG_GLOB_LIMIT=128

nginx_config_evidence() {
    local config=$1 key comma=
    shift
    printf '['
    for key in "$@"; do
        [[ $config != *"\"$key\":true"* ]] || continue
        printf '%s"%s"' "$comma" "$key"
        comma=,
    done
    printf ']'
}

nginx_plus_result() {
    local version=$1 cve=${2:-}
    [[ $version =~ ^[0-9]+([.][0-9]+){0,3}(-p[0-9]+)?$ ]] || { printf pending; return; }
    version=${version%%-p*}
    case $version in
        37.0.8.1|37.3.0.1) printf no_risk; return ;;
        37.0.7.1|37.2.0.1)
            if [[ $cve == CVE-2026-123633 ]]; then printf no_risk; return; fi ;;
    esac
    case $version in
        34|34.*|35|35.*|36|36.*|37) printf risk; return ;;
        37.*)
            if { vge "$version" 37.0.0 && vle "$version" 37.0.7.1; } ||
               { vge "$version" 37.1.0 && vle "$version" 37.2.0.1; }; then
                printf risk; return
            fi ;;
    esac
    printf pending
}

nginx2root_cves() {
    local raw=$1 config=${2:-} flavor=${3:-nginx} plus=${4:-} version_source=${5:-}
    local cve minimum feature version_result result result_reason missing evidence version_range_match comma=
    printf '['
    while read -r cve minimum feature; do
        version_result=pending
        if [[ $flavor == plus ]]; then
            version_result=$(nginx_plus_result "$plus" "$cve")
        elif { [[ $raw == 1.30.* ]] && vge "$raw" 1.30.7; } ||
           { [[ $raw =~ ^1\.[0-9]+\.[0-9]+$ ]] && vge "$raw" 1.31.9; }; then
            version_result=no_risk
        elif [ -n "$raw" ]; then
            if vlt "$raw" "$minimum"; then version_result=no_risk
            elif vle "$raw" 1.31.8; then version_result=risk
            fi
        fi
        if [[ $flavor != nginx && $flavor != plus ]]; then
            [[ $version_result == risk && ( $flavor == openresty || $flavor == tengine ) ]] || version_result=pending
        fi
        case $feature in
            http2) missing=$(nginx_config_evidence "$config" http2_on) ;;
            http2_upstream) missing=$(nginx_config_evidence "$config" http2_on upstream) ;;
            http3_upstream) missing=$(nginx_config_evidence "$config" quic_listener) ;;
            resolver_proxy_mirror)
                if [[ $config == *'"ssi":true'* ]]; then
                    missing=$(nginx_config_evidence "$config" resolver dynamic_proxy_host)
                else
                    missing=$(nginx_config_evidence "$config" resolver dynamic_proxy_host mirror)
                fi ;;
            mail_proxy_auth_http) missing=$(nginx_config_evidence "$config" mail) ;;
        esac
        evidence=condition_not_observed
        [[ $missing != '[]' ]] || evidence=disk_hints_present
        if [[ -z $config ]]; then
            evidence=configuration_not_attributed
            missing='[]'
        elif [[ $config =~ \"skipped\":[1-9] && ( $missing != '[]' || $config == *'"files_examined":0,'* ) ]]; then
            evidence=configuration_incomplete
            missing='[]'
        elif [[ $config == *'"files_examined":0,'* ]]; then
            evidence=configuration_not_attributed
            missing='[]'
        fi
        case $version_result in
            risk) version_range_match=true ;;
            no_risk) version_range_match=false ;;
            *) version_range_match=null ;;
        esac
        result=pending
        if [[ $evidence == configuration_incomplete ]]; then
            result_reason=$evidence
        elif [[ $version_range_match == false && $version_source != disk ]]; then
            result=no_risk
            result_reason=version_outside_range
        elif [[ $evidence == configuration_not_attributed ]]; then
            result_reason=$evidence
        elif [[ $version_range_match == null ]]; then
            result_reason=version_match_unknown
        elif [[ $version_range_match == true && $evidence == disk_hints_present ]]; then
            result=risk
            result_reason=risk_gate_hit
        elif [[ $version_range_match == true ]]; then
            result_reason=condition_not_observed
        else
            result_reason=runtime_version_unverified
        fi
        printf '%s{"cve":"%s","result":"%s","result_reason":"%s","feature":"%s","config_evidence":"%s","version_range_match":%s}' \
            "$comma" "$cve" "$result" "$result_reason" "$feature" "$evidence" "$version_range_match"
        comma=,
    done <<'RULES'
CVE-2026-123007 1.9.5 http2
CVE-2026-123633 1.19.7 http2_upstream
CVE-2026-123634 0.6.18 resolver_proxy_mirror
CVE-2026-121810 1.25.0 http3_upstream
CVE-2026-113425 0.5.33 mail_proxy_auth_http
RULES
    printf ']'
}

nginx2root_binary_metadata() {
    local file=$1 marks versions plus flavor=nginx module comma= product= compiled_config
    local hints=''
    [[ -f "$file" && $(head -c 4 -- "$file" 2>/dev/null) == $'\x7fELF' ]] || return 0
    marks=$(head -c 16777216 -- "$file" 2>/dev/null |
        LC_ALL=C grep -aiEo 'nginx/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,5}\b|nginx-plus(-r[0-9]+([.][0-9]+){0,3}(-p[0-9]+)?)?|(Tengine|openresty)(/[0-9]+([.][0-9]+)+(-rc[0-9]+)?)?|--with-http_v[23]_module|--with-mail(=dynamic)?|ngx_http_v[23]_module|ngx_http_mirror_module|ngx_mail_proxy_module|--conf-path=/[a-zA-Z0-9/._-]+' |
        LC_ALL=C sort -u)
    compiled_config=$(sed -n 's|^--conf-path=||p' <<< "$marks")
    [[ $compiled_config != *$'\n'* ]] || compiled_config=ambiguous
    marks=$(sed '/^--conf-path=/d' <<< "$marks" | LC_ALL=C tr '[:upper:]' '[:lower:]' | LC_ALL=C sort -u)
    versions=$(sed -n 's|^nginx/||p' <<< "$marks")
    plus=$(sed -n 's|^nginx-plus-r||p' <<< "$marks")
    [[ $versions != *$'\n'* ]] || versions=
    [[ $plus != *$'\n'* ]] || plus=
    case $marks in
        *nginx-plus*) flavor=plus ;;
        *tengine*) flavor=tengine ;;
        *openresty*) flavor=openresty ;;
    esac
    # These bounded string matches are positive hints. Dynamic modules may be absent from the executable.
    for module in http_v2 http_v3 http_mirror mail_proxy; do
        case $module in
            http_v2|http_v3) [[ $marks == *"--with-${module}_module"* || $marks == *"ngx_${module}_module"* ]] || continue ;;
            http_mirror) [[ $marks == *ngx_http_mirror_module* ]] || continue ;;
            mail_proxy) [[ $marks == *ngx_mail_proxy_module* || $marks == *--with-mail* ]] || continue ;;
        esac
        hints+="$comma\"$module\""
        comma=,
    done
    if [[ $flavor == openresty || $flavor == tengine ]]; then
        product=$(sed -n "s|^$flavor/||p" <<< "$marks")
        [[ $product != *$'\n'* ]] || product=
    fi
    printf '%s|%s|%s|[%s]|%s|%s' "$versions" "$flavor" "$plus" "$hints" "$product" "$compiled_config"
}

nginx_process() {
    local proc=$1 name
    if ! IFS= read -r name 2>/dev/null < "$proc/comm"; then
        if [[ -d $proc ]]; then return 2; fi
        return 1
    fi
    case $name in nginx|nginx-debug|openresty|tengine) return 0 ;; *) return 1 ;; esac
}

nginx_process_role() {
    local proc=$1 title
    if ! IFS= read -r -d '' -n 48 title 2>/dev/null < "$proc/cmdline" || [[ -z $title ]]; then
        printf unknown
        return
    fi
    case $title in
        *': master process'|*': master process '*) printf master ;;
        *': worker process'|*': worker process '*) printf worker ;;
        *': cache manager process'*|*': cache loader process'*) printf auxiliary ;;
        *) printf standalone ;;
    esac
}

# Worker titles replace the original arguments. Use the parent's arguments
# only when both processes refer to the same image, filesystem and namespace.
nginx_worker_parent() {
    local proc=$1 id=$2 root=$3 namespace=$4 ppid parent
    [[ -n $id && -n $root && -n $namespace ]] || return 1
    ppid=$(awk '$1 == "PPid:" {print $2; exit}' "$proc/status" 2>/dev/null)
    [[ $ppid =~ ^[1-9][0-9]*$ ]] || return 1
    parent=${proc%/*}/$ppid
    nginx_process "$parent" && [[ $(nginx_process_role "$parent") == master ]] || return 1
    [[ $(file_id "$parent/exe") == "$id" && $(file_id "$parent/root") == "$root" &&
       $(readlink "$parent/ns/mnt" 2>/dev/null) == "$namespace" ]] || return 1
    printf '%s' "$parent"
}

nginx_master_binary_hint() {
    local proc=$1 title binary LC_ALL=C
    IFS= read -r -d '' -n 4097 title 2>/dev/null < "$proc/cmdline" || return 1
    [[ ${#title} -le 4096 && $title == *': master process '* ]] || return 1
    read -r binary _ <<< "${title#*: master process }"
    if [[ $binary == /* ]]; then
        [[ $binary =~ ^/[a-zA-Z0-9/._-]+$ && -f $binary && -r $binary ]] || return 1
    else
        binary=${binary#./}
        [[ $binary != */* ]] || return 1
    fi
    case ${binary##*/} in
        nginx|nginx-debug|openresty|tengine) printf '%s' "$binary" ;;
        *) return 1 ;;
    esac
}

nginx_unique_local_binary() {
    local command=$1 candidate candidate_id unique_id= chosen=
    shift
    for candidate in "$@"; do
        [[ -n $candidate && -f $candidate ]] || continue
        [[ $candidate == /* ]] || candidate=$PWD/$candidate
        candidate_id=$(file_id "$candidate") || return 1
        [[ -z $unique_id || $candidate_id == "$unique_id" ]] || return 1
        unique_id=$candidate_id
        if [[ -z $chosen && ${candidate##*/} == "$command" && -r $candidate && -x $candidate ]]; then
            chosen=$candidate
        fi
    done
    [[ -n $chosen ]] || return 1
    printf '%s' "$chosen"
}

# Parse only unambiguous absolute -c arguments from the visible process.
nginx_process_config_entry() {
    local proc=$1
    local original
    original=$(head -c 4097 -- "$proc/cmdline" 2>/dev/null | awk '
        BEGIN {RS="\0"}
        {size+=length($0)+1; args[NR]=$0}
        END {
            if (NR<=1 || (args[1] ~ /: master process( |$)/ && args[2]=="")) exit
            print "argv"
            if (size>4096) exit
            for(i=2;i<=NR;i++) {
                if(args[i]=="") break
                if(args[i]=="-g") {i++; continue}
                if (args[i]=="-c" || args[i] ~ /^-c\//) {
                    candidate=(args[i]=="-c" ? args[++i] : substr(args[i],3))
                    if (path!="" || candidate!~/^\/[[:alnum:]\/._-]+$/ ||
                        (args[i+1]!="" && args[i+1]!~/^-/)) exit
                    path=candidate
                }
            }
            if(path!="") print path
        }')
    if [[ $original == argv* ]]; then
        [[ $original != *$'\n'* ]] || printf '%s\n' "${original#*$'\n'}"
        return 0
    fi
    head -c 4097 -- "$proc/cmdline" 2>/dev/null | tr '\000' ' ' | awk '
        {text=text " " $0}
        END {
            if (length(text)>4097) exit
            count=split(text,words,/[[:space:]]+/)
            for(i=1;i<=count;i++) {
                if (words[i]=="-g") {
                    if (words[i+1]=="daemon" && words[i+2]=="off;") {i+=2; continue}
                    break
                }
                if (words[i]=="-c" || words[i] ~ /^-c\//) {
                    candidate=(words[i]=="-c" ? words[++i] : substr(words[i],3))
                    if (path!="" || candidate!~/^\/[[:alnum:]\/._-]+$/ ||
                        (words[i+1]!="" && words[i+1]!~/^-/)) exit
                    path=candidate
                }
            }
            if(path!="") print path
        }'
}

nginx_layout_config() {
    local binary=$1 prefix
    case $binary in
        /*/sbin/*|/*/bin/*) prefix=${binary%/*/*} ;;
        *) return 0 ;;
    esac
    if [[ $binary == /usr/sbin/nginx && ${2:-} == nginx && -f /etc/nginx/nginx.conf ]]; then
        printf '%s' /etc/nginx/nginx.conf
    elif [ -f "$prefix/conf/nginx.conf" ]; then
        printf '%s' "$prefix/conf/nginx.conf"
    fi
}

nginx_site_config_entry() {
    local proc=$1 binary=$2 flavor=$3 layout_config
    local config=$NGINX_SITE_CONFIG prefix=${NGINX_SITE_CONFIG%/conf/nginx.conf}
    [[ -f $config ]] || return 1

    layout_config=$(nginx_layout_config "$binary" "$flavor")
    if [[ -n $layout_config ]]; then
        [[ $config -ef $layout_config ]] || return 1
        # 文件软链接的两端可能位于不同目录，按安装路径解析相对 include。
        [[ ${config%/*} -ef ${layout_config%/*} ]] || config=$layout_config
    elif [[ ! $binary -ef "$prefix/sbin/nginx" && ! $binary -ef "$prefix/bin/nginx" ]]; then
        return 1
    fi

    nginx_process_uses_default_config "$proc" || return 1
    printf '%s' "$config"
}

# 存在无法解析的 -c 或 -p 时，保留配置归属未知。
nginx_process_uses_default_config() {
    head -c 4097 -- "$1/cmdline" 2>/dev/null | LC_ALL=C awk '
        BEGIN { RS="\0" }
        { size += length($0) + 1 }
        /(^|[[:space:]])-[^[:space:]]*[cp]/ { overridden=1 }
        END { exit !(size > 0 && size <= 4096 && !overridden) }
    '
}

nginx_config_directives() {
    LC_ALL=C awk '
        function token() {
            if (!in_word) return
            args[++argc] = word
            word = ""
            in_word = 0
        }
        function hint(key) {
            printf "@hint %d %s\n", line, key
        }
        function problem(reason, location) {
            printf "@problem %d %s\n", location, reason
        }
        # Lua has its own strings, comments, and table delimiters.
        # Share the cursor so NGINX parsing resumes after the closing brace.
        function lua_character(text, c,    opener, width, comment) {
            if (lua_long_end != "") {
                width = length(lua_long_end)
                if (c == "]" && substr(text, i, width) == lua_long_end) {
                    i += width - 1
                    lua_long_end = ""
                }
            } else if (lua_quote != "") {
                if (c == "\\") i++
                else if (c == lua_quote) lua_quote = ""
            } else if (c == "\"" || c == "\047") {
                lua_quote = c
            } else if (c == "[" || (c == "-" && substr(text, i, 2) == "--")) {
                comment = c == "-" ? 2 : 0
                if (match(substr(text, i + comment), /^\[=*\[/)) {
                    width = RLENGTH
                    opener = substr(text, i + comment, width)
                    lua_long_end = "]" substr(opener, 2, width - 2) "]"
                    i += comment + width - 1
                } else if (comment) {
                    return 1
                }
            } else if (c == "{") {
                lua_depth++
            } else if (c == "}") {
                lua_depth--
            }
            return 0
        }
        function directive(end,    name, value, host, i) {
            token()
            name = argc ? args[1] : ""
            value = argc > 1 ? args[2] : ""
            if (end == "{") {
                if (name ~ /^(init|init_worker|exit_worker|set|server_rewrite|rewrite|access|content|balancer|header_filter|body_filter|log|preread|ssl_client_hello|ssl_certificate|ssl_session_fetch|ssl_session_store)_by_lua_block$/) {
                    lua_depth = 1
                    lua_start = line
                } else {
                    depth++
                    if (name == "mail") hint("mail")
                    if (!argc && !bad_line) bad_line = NR
                }
            } else if (end == "}") {
                if ((--depth < 0 || argc) && !bad_line) bad_line = NR
            } else if (name == "include") {
                hint("include_observed")
                if (argc == 2 && value != "" && value !~ /[[:cntrl:]]/) print "@include " value
                else problem("unsupported_include", line)
            } else if (name == "listen") {
                for (i = 3; i <= argc; i++) {
                    if (args[i] == "http2") hint("http2_on")
                    if (args[i] == "quic") {
                        hint("http3_or_quic")
                        hint("quic_listener")
                    }
                }
            } else if (name == "http2" && value ~ /^(on|off)$/) hint("http2_" value)
            else if (name == "http3" && value == "on") hint("http3_or_quic")
            else if (name == "proxy_http_version" && value == "2") hint("proxy_http_version_2")
            else if (name == "resolver" && value != "off") hint("resolver")
            else if (name == "mirror" && value != "off") hint("mirror")
            else if (name == "mirror_request_body" && value == "off") hint("mirror_request_body_off")
            else if (name == "ssi" && value == "on") hint("ssi")
            else if (name == "proxy" && value == "on") hint("mail_proxy")
            else if (name == "auth_http") hint("auth_http")
            else if (name ~ /^(proxy|grpc|fastcgi|uwsgi|scgi|memcached)_pass$/) {
                hint("upstream")
                if (name == "grpc_pass") hint("grpc_upstream")
                if (name == "proxy_pass" && index(value, "$")) {
                    hint("dynamic_proxy_pass")
                    host = value
                    if (sub(/^https?:\/\//, "", host)) sub(/[:\/?].*$/, "", host)
                    if (index(host, "$")) hint("dynamic_proxy_host")
                }
            }
            argc = line = 0
        }
        {
            for (i = 1; i <= length($0); i++) {
                c = substr($0, i, 1)
                if (lua_depth) {
                    if (lua_character($0, c)) break
                    continue
                }
                if (escaped) {
                    word = word c
                    escaped = 0
                } else if (c == "\\") {
                    escaped = in_word = 1
                    if (!line) line = NR
                } else if (quote) {
                    if (c == quote) quote = ""
                    else word = word c
                } else if (variable) {
                    word = word c
                    if (c == "}") variable = 0
                } else if (c == "#" && !in_word) {
                    break
                } else if (c ~ /[[:space:]]/) {
                    token()
                } else if (c == "{" && word ~ /\$$/) {
                    word = word c
                    variable = 1
                } else if (c == ";" || c == "{" || c == "}") {
                    directive(c)
                } else {
                    if (!line) line = NR
                    in_word = 1
                    if (c == "\"" || c == "\047") quote = c
                    else word = word c
                }
            }
            if (quote) word = word "\n"
            else if (!escaped && !variable) token()
        }
        END {
            if (lua_depth)
                problem("unsupported_syntax", lua_start)
            else if (bad_line || depth || argc || in_word || quote || escaped || variable)
                problem("unsupported_syntax", bad_line ? bad_line : (line ? line : NR))
        }
    '
}

nginx_config_root_path() {
    local root=$1 rest=$2 directory=${3:-} resolved= part candidate target links=0
    [[ $rest == /* ]] || return 1
    while [[ -n $rest ]]; do
        part=${rest%%/*}
        if [[ $rest == */* ]]; then rest=${rest#*/}; else rest=; fi
        case $part in
            ''|.) continue ;;
            ..) resolved=${resolved%/*}; continue ;;
        esac
        candidate=$root$resolved/$part
        if [[ -L $candidate ]]; then
            ((links < 40)) || return 1
            links=$((links + 1))
            target=$(readlink -- "$candidate" 2>/dev/null) || return 1
            # 容器中的绝对软链接从容器根目录解析。
            [[ $target != /* ]] || resolved=
            rest=$target${rest:+/$rest}
        else
            if [[ ( -n $rest || $directory == directory ) && ! -d $candidate ]]; then
                if [[ -x $root$resolved/ && ! -e $candidate ]]; then return 2; fi
                return 1
            fi
            resolved+=/$part
        fi
    done
    printf '%s' "$root${resolved:-/}"
}

nginx_config_skip() {
    local reason=$1 path=$2 line=${3:-}
    printf '@skipped {"reason":"%s","file":%s' "$reason" "$(jstr "$(san_field "$path")")"
    [[ -z $line ]] || printf ',"line":%d' "$line"
    printf '}\n'
}

nginx_config_directory_entries() {
    # Read incrementally. An empty record marks EOF before the requested limit.
    if [[ $1 == perl ]]; then
        perl -e '
            my ($path, $remaining) = @ARGV;
            binmode(STDOUT, ":raw");
            opendir(my $dir, $path) or exit 1;
            while ($remaining > 0) {
                $! = 0;
                my $name = readdir($dir);
                if (!defined $name) {
                    exit 1 if $!;
                    print "\0";
                    last;
                }
                next if $name eq "." || $name eq "..";
                print $name, "\0";
                $remaining--;
            }
            closedir($dir);
        ' -- "$2" "$3"
    else
        python3 -c '
import os
import sys

with os.scandir(os.fsencode(sys.argv[1])) as entries:
    for _ in range(int(sys.argv[2])):
        entry = next(entries, None)
        if entry is None:
            sys.stdout.buffer.write(b"\0")
            break
        sys.stdout.buffer.write(entry.name + b"\0")
        ' "$2" "$3"
    fi
}

nginx_config_glob() {
    local target=$1 base=$2 depth=$3 dir=${1%/*} pattern=${1##*/} fs_dir status=0 name complete=false
    local -a matches=()
    [[ $glob_budget_reached == false ]] || return 0
    if ((directory_entries_examined >= directory_limit)); then
        glob_budget_reached=true
        nginx_config_skip directory_entry_limit "$target"
        return 0
    fi
    if ((glob_expansions >= glob_limit)); then
        glob_budget_reached=true
        nginx_config_skip glob_expansion_limit "$target"
        return 0
    fi
    glob_expansions=$((glob_expansions + 1))
    if [[ $dir == *[\*\?\[]* ]]; then
        nginx_config_skip unsupported_glob_directory "$target"
        return 0
    fi
    fs_dir=${dir:-/}
    [[ $fs_dir == /* ]] || fs_dir=$PWD/$fs_dir
    fs_dir=$(nginx_config_root_path "$config_root" "$fs_dir" directory) || status=$?
    # Nginx accepts a wildcard include with no matches, including an absent directory.
    [[ $status -ne 2 ]] || return 0
    if [[ $status -ne 0 || ! -r $fs_dir || ! -x $fs_dir ]]; then
        nginx_config_skip include_directory_unreadable "$target"
        return 0
    fi
    if [[ -z $directory_reader ]]; then
        nginx_config_skip include_directory_reader_unavailable "$target"
        return 0
    fi
    # One extra entry distinguishes a full directory from a truncated enumeration.
    while LC_ALL=C IFS= read -r -d '' name; do
        if [[ -z $name ]]; then complete=true; break; fi
        if ((directory_entries_examined >= directory_limit)); then
            glob_budget_reached=true
            nginx_config_skip directory_entry_limit "$target"
            break
        fi
        directory_entries_examined=$((directory_entries_examined + 1))
        if [[ $name == $pattern && ( $name != .* || $pattern == .* ) ]]; then matches+=("$name"); fi
    done < <(nginx_config_directory_entries "$directory_reader" "$fs_dir" "$((directory_limit - directory_entries_examined + 1))" 2>/dev/null)
    if [[ $complete == false && $glob_budget_reached == false ]]; then
        nginx_config_skip include_directory_read_failed "$target"
    fi
    if [[ -n ${matches[0]:-} ]]; then
        while LC_ALL=C IFS= read -r -d '' name; do
            nginx_config_stream "$dir/$name" "$base" "$depth" || break
        done < <(printf '%s\0' "${matches[@]}" | sort -z)
    fi
}

nginx_config_stream() {
    local path=$1 base=$2 depth=$3 id size content entry target fs_path problem_line reason
    local -a includes=()
    fs_path=$path
    if [[ -n $config_root ]] && ! fs_path=$(nginx_config_root_path "$config_root" "$path"); then
        nginx_config_skip path_unresolved "$path"
        return
    fi
    if [ ! -f "$fs_path" ]; then
        if [[ $depth -gt 0 || $explicit_roots -eq 1 ]]; then nginx_config_skip missing_or_not_regular "$path"; fi
        return
    fi
    id=$(file_id "$fs_path") || { nginx_config_skip stat_failed "$path"; return; }
    [[ $seen_files != *" $id "* ]] || return 0
    if [[ $count -ge 64 ]]; then nginx_config_skip file_limit "$path"; return 1; fi
    seen_files+="$id "
    count=$((count + 1))
    size=$(stat -Lc '%s' -- "$fs_path" 2>/dev/null) || { nginx_config_skip stat_failed "$path"; return; }
    if [[ $size -gt 65536 ]]; then nginx_config_skip file_too_large "$path"; return; fi
    if ! content=$(head -c 65536 -- "$fs_path" 2>/dev/null); then
        nginx_config_skip read_failed "$path"
        return
    fi
    printf '@file %s\n' "$(jstr "$(san_field "$path")")"
    while IFS= read -r entry; do
        case $entry in
            '@include '*) includes+=("${entry#@include }") ;;
            '@problem '*)
                read -r _ problem_line reason <<< "$entry"
                nginx_config_skip "$reason" "$path" "$problem_line" ;;
            *) printf '%s\n' "$entry" ;;
        esac
    done < <(nginx_config_directives <<< "$content")
    for target in ${includes[@]+"${includes[@]}"}; do
        if [[ $target != /* ]]; then target=$base/$target; fi
        if (( depth >= 8 )); then
            nginx_config_skip include_depth_limit "$target"
            continue
        fi
        if [[ $target == *[\*\?\[]* ]]; then
            nginx_config_glob "$target" "$base" "$((depth + 1))"
        else
            nginx_config_stream "$target" "$base" "$((depth + 1))" || break
        fi
    done
}

nginx2root_config() {
    local config config_root= count=0 explicit_roots=0 directory_reader=
    local directory_entries_examined=0 glob_expansions=0 glob_budget_reached=false
    local directory_limit=${config_directory_remaining:-$NGINX_CONFIG_DIRECTORY_LIMIT}
    local glob_limit=${config_glob_remaining:-$NGINX_CONFIG_GLOB_LIMIT}
    local -a configs=()
    if [[ ${1:-} == --root ]]; then
        config_root=$2
        shift 2
    fi
    if [ "$#" -gt 0 ]; then
        configs=("$@")
        explicit_roots=1
    else
        configs=("$NGINX_SITE_CONFIG" /etc/nginx/nginx.conf '/etc/nginx/conf.d/*.conf'
                 '/etc/nginx/sites-enabled/*' /usr/local/nginx/conf/nginx.conf)
    fi
    if have perl; then directory_reader=perl
    elif have python3; then directory_reader=python3
    fi
    (
        local seen_files=' '
        for config in "${configs[@]}"; do
            if [[ $explicit_roots -eq 0 && $config == *\** ]]; then
                nginx_config_glob "$config" "${config%/*}" 0
            else
                nginx_config_stream "$config" "$(dirname -- "$config")" 0 || break
            fi
        done
        printf '@glob_budget %d %d %s\n' "$directory_entries_examined" "$glob_expansions" "$glob_budget_reached"
    ) | awk '
        /^@file / { files++; file=substr($0,7); next }
        /^@glob_budget / { directory_entries=$2; glob_expansions=$3; glob_budget_reached=$4; next }
        /^@skipped / {
            if (++skipped <= 16) details=details (details=="" ? "" : ",") substr($0,10)
            next
        }
        /^@hint / {
            key=$3
            if (key in seen) next
            seen[key]=1
            if (key=="include_observed") next
            entries=entries (entries=="" ? "" : ",") sprintf("{\"hint\":\"%s\",\"file\":%s,\"line\":%d}", key,file,$2)
        }
        END {
            keys="http2_on http2_off http3_or_quic upstream resolver dynamic_proxy_pass mirror mirror_request_body_off ssi mail mail_proxy auth_http include_observed proxy_http_version_2 grpc_upstream quic_listener dynamic_proxy_host"
            printf "{\"scope\":\"disk_directive_hints\",\"files_examined\":%d,\"skipped\":%d,", files, skipped
            printf "\"directory_entries_examined\":%d,\"glob_expansions\":%d,\"glob_budget_reached\":%s,", directory_entries, glob_expansions, (glob_budget_reached=="true" ? "true" : "false")
            n=split(keys, flags, " ")
            for (i=1; i<=n; i++) printf "\"%s\":%s,", flags[i], (flags[i] in seen ? "true" : "false")
            printf "\"scope_resolution\":\"file_directive_only\",\"evidence\":[%s]", entries
            if (skipped) printf ",\"skipped_details\":[%s]", details
            printf "}"
        }'
}

nginx2root_sctp() {
    local file loaded=false automatic_block_hint=false in_use=null
    [ ! -d /sys/module/sctp ] || loaded=true
    if [ -r /proc/net/sctp/assocs ]; then
        in_use=$(awk 'NR > 1 && NF {found=1; exit} END {print found ? "true" : "false"}' /proc/net/sctp/assocs 2>/dev/null) || in_use=null
    fi
    for file in /etc/modprobe.d/*.conf /usr/lib/modprobe.d/*.conf /lib/modprobe.d/*.conf; do
        [ -f "$file" ] && [ -r "$file" ] || continue
        if grep -Eq '^[[:space:]]*install[[:space:]]+sctp[[:space:]]+(/usr)?/bin/false([[:space:]]|$)' "$file" 2>/dev/null; then
            automatic_block_hint=true
            break
        fi
    done
    printf '{"kernel_release":%s,"module_visible":%s,"associations_visible":%s,"modprobe_install_block_hint":%s,"patch_status":"unknown"}' \
        "$(jstr "$(cat /proc/sys/kernel/osrelease 2>/dev/null || :)")" "$loaded" "$in_use" "$automatic_block_hint"
}

apache_reference() {
    local raw=$1 scope=${2:-httpd}
    if [ "$scope" = module ]; then
        [[ $raw =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { printf unknown; return; }
        if vlt "$raw" 2.0.8; then printf outside_upstream_range
        elif vle "$raw" 2.0.42; then printf potential
        else printf outside_upstream_range
        fi
    else
        [[ $raw =~ ^2\.4\.[0-9]+$ ]] || { printf unknown; return; }
        if vlt "$raw" 2.4.55; then printf outside_upstream_range
        elif vle "$raw" 2.4.70; then printf potential
        else printf meets_upstream_reference
        fi
    fi
}

apache_config_hints() {
    local file size count=0
    local -a configs=()
    if [ "$#" -gt 0 ]; then
        configs=("$@")
    else
        configs=(/etc/apache2/apache2.conf /etc/apache2/{mods,conf,sites}-enabled/*.conf
                 /etc/apache2/mods-enabled/*.load /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf
                 /etc/httpd/conf.modules.d/*.conf /usr/local/apache2/conf/httpd.conf)
    fi
    (
        for file in "${configs[@]}"; do
            [ -f "$file" ] || continue
            count=$((count + 1))
            [ "$count" -le 64 ] || { printf '@skipped\n'; break; }
            size=$(stat -Lc '%s' -- "$file" 2>/dev/null) || size=
            if ! [[ $size =~ ^[0-9]+$ ]] || [ "$size" -gt 65536 ] || ! head -c 65536 -- "$file" 2>/dev/null; then
                printf '\n@skipped\n'; continue
            fi
            printf '\n@file\n'
        done
    ) | awk '
        /^@file$/ {files++; vhost=0; next}
        /^@skipped$/ {skipped++; vhost=0; next}
        { sub(/#.*/, ""); gsub(/"/, ""); $0=tolower($0) }
        /^[[:space:]]*<virtualhost[[:space:]]/ {vhost=1; next}
        /^[[:space:]]*<\/virtualhost[[:space:]]*>/ {vhost=0; next}
        $1 == "loadmodule" && $2 == "http2_module" {mod=1}
        $1 == "include" || $1 == "includeoptional" {includes=1}
        $1 == "h2direct" && $2 == "on" {direct=1}
        $1 == "h2upgrade" && $2 == "on" {upgrade=1}
        $1 == "protocols" {
            if (NF == 2 && $2 == "http/1.1") h1=1
            for (i=2; i<=NF; i++) {
                if ($i == "h2" || $i == "h2c") {
                    if (vhost) vhost_h2=1; else outer_h2=1
                    if ($i == "h2") h2=1; else h2c=1
                }
            }
        }
        function b(v) { return v ? "true" : "false" }
        END {
            printf "{\"scope\":\"disk_directive_hints\",\"files_examined\":%d,\"skipped\":%d,", files, skipped
            printf "\"h2\":%s,\"h2c\":%s,\"http1_only_directive\":%s,\"load_module\":%s,\"h2_direct_on\":%s,\"h2_upgrade_on\":%s,\"include_observed\":%s,\"h2_in_virtualhost\":%s,\"h2_outside_virtualhost\":%s}", b(h2),b(h2c),b(h1),b(mod),b(direct),b(upgrade),b(includes),b(vhost_h2),b(outer_h2)
        }'
}

apache_http2_mappings() {
    local LC_ALL=C file=$1 limit=$2 data bytes complete=true read_rc=0 records
    # Keep the trailing newline and account for partial reads even when head fails.
    data=$(head -c "$limit" -- "$file" 2>/dev/null; read_rc=$?; printf '.'; exit "$read_rc") || read_rc=$?
    data=${data%.}
    bytes=${#data}
    if ((read_rc != 0)); then
        printf 'false %d\n' "$bytes"
        return
    fi
    if ((bytes >= limit)); then
        complete=false
        # Only complete records can identify a mapped file.
        case $data in
            *$'\n') ;;
            *$'\n'*) data=${data%$'\n'*} ;;
            *) data= ;;
        esac
    fi
    records=$(LC_ALL=C awk '
        /\/mod_http2\.so( \(deleted\))?$/ && NF >= 6 {
            range=$1; dev=$4; inode=$5; path=$0
            for (i=0; i<5; i++) sub(/^[[:space:]]*[^[:space:]]+/, "", path)
            sub(/^[[:space:]]+/, "", path)
            if (path !~ /^\//) next
            key=dev "\037" inode "\037" path
            if (!seen[key]++) print range "\037" key
        }
    ' <<< "$data") || { records=; complete=false; }
    printf '%s %d\n' "$complete" "$bytes"
    if [[ -n $records ]]; then printf '%s\n' "$records"; fi
}

linux_inventory_unavailable() {
    local name=$1 cve=${2:-}
    printf '{"result":"pending","result_reason":"process_scan_unavailable","exit_code":3,"category":%s,"inventory_status":"unavailable","reason":"linux_proc_required","platform":%s' "$(jstr "$name")" "$(jstr "$OS")"
    if [ -n "$cve" ]; then printf ',"cve":%s' "$(jstr "$cve")"; fi
    printf ',"coverage":{"evidence_incomplete":true,"process_scan_unavailable":true}}\n' || return 2
    return 3
}

apache_inventory() {
    local proc name pid path id start row= seen=' ' rows=0 disk=0 comma= version reference mapped config
    local gate=0 modules=0 unknown=0 proc_limit=false unresolved=0 image_state match package_hint http2_evidence disk_http2=condition_not_observed module_version_source
    local maps_report maps_complete module_mappings runtime_modules module_pending incomplete_module_processes=0 process_result httpd_result
    local map_bytes_read=0 map_budget_reached=false map_remaining map_limit map_read_bytes
    local process_paths= process_entries=0 process_budget_reached=false process_scan_unavailable=false visibility_limited=false
    local image_key image_index image_count=0
    local -a image_keys=() image_versions=() image_packages=()
    local runtime_module_count=0 module_index
    local -a runtime_module_ids=() runtime_module_versions=() runtime_module_mapped=() module_mapping_indexes=()
    local -a configs=() explicit_paths=()
    while (($#)); do
        case $1 in
            --json) ;;
            --apache-path)
                (($# > 1)) && [ -n "$2" ] && [[ $2 != --* ]] || die "--apache-path requires a file path."
                explicit_paths+=("$2"); shift ;;
            --apache-config)
                (($# > 1)) && [ -n "$2" ] && [[ $2 != --* ]] || die "--apache-config requires a file path."
                configs+=("$2"); shift ;;
            --help|-h)
                usage
                return ;;
            *) die "Unknown Apache option. See --help." ;;
        esac
        shift
    done
    for path in ${explicit_paths[@]+"${explicit_paths[@]}"}; do
        [ -f "$path" ] || die "--apache-path requires an existing file."
    done
    for path in ${configs[@]+"${configs[@]}"}; do
        [ -f "$path" ] || die "--apache-config requires an existing file."
    done
    if [[ $OS != Linux ]]; then
        linux_inventory_unavailable Apache CVE-2026-119618
        return $?
    fi
    config=$(apache_config_hints ${configs[@]+"${configs[@]}"})
    if [[ $config == *'"load_module":true'* || $config == *'"h2":true'* || $config == *'"h2c":true'* ]]; then
        disk_http2=disk_hints_present
    fi
    if [[ -r /proc/self/stat ]]; then
        process_paths=$(linux_process_paths) || process_scan_unavailable=true
    else
        process_scan_unavailable=true
    fi

    apache_assess_loaded_modules() {
        local proc_dir=$1 mappings=$2 range dev inode module_path major minor expected probe
        local module_version version_source module_reference module_result reason sep=
        while LC_ALL=C IFS=$'\037' read -r range dev inode module_path; do
            [[ -n $module_path ]] || continue
            probe= module_version= version_source=unknown
            module_result=pending reason=module_identity_unverified module_reference=unknown
            major=${dev%%:*}
            minor=${dev##*:}
            if [[ $dev == *:* && $major =~ ^[[:xdigit:]]+$ && $minor =~ ^[[:xdigit:]]+$ &&
                  $inode =~ ^[1-9][0-9]*$ && $range =~ ^[[:xdigit:]]+-[[:xdigit:]]+$ ]]; then
                expected="$((16#$major)) $((16#$minor)) $inode"
                if [[ $(file_id "$proc_dir/map_files/$range") == "$expected" &&
                      -r $proc_dir/map_files/$range ]]; then
                    probe="$proc_dir/map_files/$range"
                    version_source=map_files
                elif [[ $module_path != *" (deleted)" &&
                        $(file_id "$proc_dir/root$module_path") == "$expected" ]]; then
                    probe="$proc_dir/root$module_path"
                    version_source=process_root
                fi
            fi
            if [[ -n $probe ]]; then
                for ((module_index=0; module_index<runtime_module_count; module_index++)); do
                    [[ ${runtime_module_ids[module_index]} != "$expected" ]] || break
                done
                if ((module_index < runtime_module_count)); then
                    module_version=${runtime_module_versions[module_index]}
                else
                    module_version=$(apache_version "$probe" module)
                fi
                if [[ $(file_id "$probe") == "$expected" ]]; then
                    if ((module_index == runtime_module_count)); then
                        runtime_module_ids[module_index]=$expected
                        runtime_module_versions[module_index]=$module_version
                        runtime_module_count=$((runtime_module_count + 1))
                    fi
                    module_mapping_indexes+=("$module_index")
                    module_reference=$(apache_reference "$module_version" module)
                    case $module_reference in
                        unknown) reason=module_version_unknown ;;
                        potential) reason=module_patch_unverified ;;
                        *) module_result=no_risk; reason=module_version_outside_range ;;
                    esac
                else
                    module_version= version_source=unknown
                fi
            fi
            if [[ $module_result == pending ]]; then module_pending=true; fi
            runtime_modules+="$sep{\"path\":$(jstr "$module_path"),\"version\":$(jstr "$module_version"),\"version_source\":\"$version_source\",\"version_reference\":\"$module_reference\",\"patch_verified\":false,\"result\":\"$module_result\",\"result_reason\":\"$reason\"}"
            sep=,
        done <<< "$mappings"
    }

    while IFS= read -r proc; do
        [ -n "$proc" ] || continue
        if ((process_entries >= PROCESS_SCAN_LIMIT)); then
            process_budget_reached=true
            proc_limit=true
            break
        fi
        process_entries=$((process_entries + 1))
        if ! IFS= read -r name 2>/dev/null < "$proc/comm"; then
            if [[ -d $proc ]]; then visibility_limited=true; fi
            continue
        fi
        case $name in apache2|httpd) ;; *) continue ;; esac
        pid=${proc##*/}
        start=$(java_process_start "$pid")
        path=$(readlink "$proc/exe" 2>/dev/null || :)
        id=$(file_id "$proc/exe" || :)
        image_key="$id:$path"
        for ((image_index=0; image_index<image_count; image_index++)); do
            [[ ${image_keys[image_index]} != "$image_key" ]] || break
        done
        version=
        if ((image_index < image_count)); then
            version=${image_versions[image_index]}
        elif [[ -n $id && -n $start ]]; then
            version=$(apache_version "$proc/exe" httpd)
        fi
        # Module mappings can differ between workers using the same binary.
        maps_report= maps_complete=false
        map_remaining=$((APACHE_MAP_SCAN_TOTAL_BYTES - map_bytes_read))
        if ((map_remaining > 0)); then
            map_limit=$APACHE_MAP_SCAN_MAX_BYTES
            if ((map_remaining < map_limit)); then map_limit=$map_remaining; fi
            maps_report=$(apache_http2_mappings "$proc/maps" "$map_limit") ||
                die "Cannot record the Apache process map byte count."
            read -r maps_complete map_read_bytes <<< "${maps_report%%$'\n'*}" ||
                die "Cannot parse the Apache process map byte count."
            map_bytes_read=$((map_bytes_read + map_read_bytes))
        fi
        if ((map_bytes_read >= APACHE_MAP_SCAN_TOTAL_BYTES)); then map_budget_reached=true; fi
        module_mappings= runtime_modules= module_pending=false
        module_mapping_indexes=()
        if [[ $maps_report == *$'\n'* ]]; then
            module_mappings=${maps_report#*$'\n'}
            mapped=true
            if [[ -n $id && -n $start ]]; then apache_assess_loaded_modules "$proc" "$module_mappings"; fi
        elif [[ $maps_complete == true ]]; then
            mapped=false
        else
            mapped=null
        fi
        image_state=$(web_disk_identity "$proc" "$path" "$id")
        if [[ -z $id || -z $start || $(file_id "$proc/exe") != "$id" ||
              $(java_process_start "$pid") != "$start" ]]; then
            version=
            mapped=null
            maps_complete=false
            runtime_modules= module_pending=false
            module_mapping_indexes=()
            # Keep a reported identity conflict visible instead of converting it to a read failure.
            case $image_state in mismatch|deleted) ;; *) image_state=unverified ;; esac
        elif ((image_index == image_count)); then
            image_keys[image_index]=$image_key
            image_versions[image_index]=$version
            image_packages[image_index]=
            image_count=$((image_count + 1))
        fi
        for module_index in ${module_mapping_indexes[@]+"${module_mapping_indexes[@]}"}; do
            runtime_module_mapped[module_index]=true
        done
        package_hint=null
        if [[ $image_state == matched && -n $id && $(file_id "$path") == "$id" ]]; then
            seen+="$id "
            if [[ -z ${image_packages[image_index]} ]]; then
                package_hint=$(web_package_hint "$path")
                image_packages[image_index]=${package_hint:-null}
            fi
            package_hint=${image_packages[image_index]}
        fi
        match=$(web_identity_boolean "$image_state")
        if [[ $image_state != matched || $maps_complete != true ]]; then
            unresolved=$((unresolved + 1))
        fi
        if [[ $module_pending == true ]]; then incomplete_module_processes=$((incomplete_module_processes + 1)); fi
        http2_evidence=$disk_http2
        [[ $mapped != true ]] || http2_evidence=module_mapped
        reference=$(apache_reference "$version")
        [[ $reference != potential ]] || gate=1
        [[ $reference != unknown ]] || unknown=1
        httpd_result=$(output_result "$reference")
        process_result=$httpd_result
        if [[ $process_result != risk && ( $module_pending == true || $maps_complete != true ) ]]; then
            process_result=pending
        fi
        row+="$comma{\"kind\":\"process\",\"pid\":$pid,\"path\":$(jstr "$(san_field "$path")"),\"version\":$(jstr "$version"),\"result\":\"$process_result\",\"httpd_result\":\"$httpd_result\",\"mod_http2_mapped\":$mapped,\"mod_http2_mappings_complete\":$maps_complete,\"mod_http2_modules\":[$runtime_modules],\"http2_evidence\":\"$http2_evidence\",\"disk_identity_matched\":$match,\"disk_identity_status\":\"$image_state\",\"package_evidence\":${package_hint:-null}}"
        comma=,
        rows=$((rows + 1))
    done <<< "$process_paths"
    for path in ${explicit_paths[@]+"${explicit_paths[@]}"} "$(type -P apache2 || :)" "$(type -P httpd || :)" /usr/sbin/apache2 /usr/sbin/httpd /usr/local/apache2/bin/httpd; do
        [ -n "$path" ] && [ -f "$path" ] || continue
        id=$(file_id "$path") || continue
        [[ $seen != *" $id "* ]] || continue
        seen+="$id "
        version=$(apache_version "$path" httpd)
        reference=$(apache_reference "$version")
        [[ $reference != potential ]] || gate=1
        [[ $reference != unknown ]] || unknown=1
        package_hint=$(web_package_hint "$path")
        row+="$comma{\"kind\":\"installation\",\"path\":$(jstr "$(san_field "$path")"),\"version\":$(jstr "$version"),\"result\":$(jstr "$(output_result "$reference")"),\"package_evidence\":${package_hint:-null},\"http2_evidence\":\"$disk_http2\"}"
        comma=,
        disk=$((disk + 1))
    done
    for path in /usr/lib/apache2/modules/mod_http2.so /usr/lib64/httpd/modules/mod_http2.so /usr/lib/httpd/modules/mod_http2.so /usr/local/apache2/modules/mod_http2.so; do
        [ -f "$path" ] || continue
        id=$(file_id "$path") || continue
        [[ $seen != *" $id "* ]] || continue
        for ((module_index=0; module_index<runtime_module_count; module_index++)); do
            [[ ${runtime_module_ids[module_index]} != "$id" ]] || break
        done
        # A verified live mapping already carries the assessment for this file.
        if ((module_index < runtime_module_count)) && [[ ${runtime_module_mapped[module_index]:-false} == true ]]; then
            continue
        fi
        seen+="$id "
        version=$(apache_version "$path" module)
        module_version_source=binary
        if [[ -z $version ]]; then
            version=$(apache_module_rpm_version "$path")
            module_version_source=rpm_package
        fi
        [[ -n $version ]] || module_version_source=unknown
        reference=$(apache_reference "$version" module)
        [[ $reference != potential ]] || gate=1
        [[ $reference != unknown ]] || unknown=1
        package_hint=$(web_package_hint "$path")
        row+="$comma{\"kind\":\"module_installation\",\"httpd_association\":\"unverified\",\"path\":$(jstr "$(san_field "$path")"),\"version\":$(jstr "$version"),\"version_source\":\"$module_version_source\",\"result\":$(jstr "$(output_result "$reference")"),\"package_evidence\":${package_hint:-null},\"http2_evidence\":\"$disk_http2\"}"
        comma=,
        modules=$((modules + 1))
    done
    local status=observed result=no_risk result_reason=risk_gate_not_hit exit_code
    local coverage_reason incomplete=false config_incomplete=false
    if process_visibility_limited; then visibility_limited=true; fi
    if [[ $config =~ \"skipped\":[1-9] ]]; then config_incomplete=true; fi
    if [[ $map_budget_reached == true ]]; then
        coverage_reason=scan_budget_exhausted
    else
        coverage_reason=$(web_coverage_reason "$proc_limit" "$process_budget_reached" "$process_scan_unavailable" "$visibility_limited" "$unresolved" "$config_incomplete")
    fi
    if [[ -z $coverage_reason ]] && ((incomplete_module_processes > 0)); then coverage_reason=module_evidence_incomplete; fi
    if [[ -z $coverage_reason && $unknown -eq 1 ]]; then coverage_reason=version_match_unknown; fi
    if [[ -n $coverage_reason ]]; then incomplete=true; fi
    if ((rows + disk + modules == 0)); then status=not_observed; fi
    if ((gate == 1)); then
        result=risk
        result_reason=risk_gate_hit
    elif [[ -n $coverage_reason ]]; then
        result=pending
        result_reason=$coverage_reason
    elif [[ $status == not_observed ]]; then
        result_reason=no_apache_findings
    fi
    exit_code=$(scan_exit_code "$result")
    printf '{"result":"%s","result_reason":"%s","exit_code":%s,"category":"Apache2Root"' "$result" "$result_reason" "$exit_code"
    printf ',"inventory_status":"%s","cve":"CVE-2026-119618","patch_verified":false,"configuration":%s,"proc_limit_reached":%s,' \
        "$status" "$config" "$proc_limit"
    printf '"coverage":{"evidence_incomplete":%s,"configuration_incomplete":%s,"proc_limit_reached":%s,"incomplete_process_evidence":%d,"incomplete_module_processes":%d,"process_visibility_limited":%s,"process_scan_limit":%s,"process_entries_examined":%s,"process_budget_reached":%s,"process_scan_unavailable":%s,' \
        "$incomplete" "$config_incomplete" "$proc_limit" "$unresolved" "$incomplete_module_processes" "$visibility_limited" "$PROCESS_SCAN_LIMIT" "$process_entries" "$process_budget_reached" "$process_scan_unavailable"
    printf '"map_read_limit_bytes":%s,"map_total_limit_bytes":%s,"map_bytes_read":%s,"map_budget_reached":%s},"findings":[%s]}\n' \
        "$APACHE_MAP_SCAN_MAX_BYTES" "$APACHE_MAP_SCAN_TOTAL_BYTES" "$map_bytes_read" "$map_budget_reached" "$row" || return 2
    return "$exit_code"
}

apache_module_rpm_version() {
    local path=$1 info name version
    have rpm && have timeout || return 0
    info=$(run_timed_command timeout -k 1s 2s rpm -qf --qf '%{NAME}\t%{VERSION}\n' -- "$path" 2>/dev/null) || return 0
    [[ $info != *$'\n'* ]] || return 0
    IFS=$'\t' read -r name version <<< "$info"
    [[ $name == mod_http2 && $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 0
    printf '%s' "$version"
}

apache_version() {
    local file=$1 scope=$2 marks pattern='Apache/'
    [ -f "$file" ] || return 0
    [[ $(head -c 4 -- "$file" 2>/dev/null) == $'\x7fELF' ]] || return 0
    if [ "$scope" = module ]; then pattern='mod_http2(/| \(v)'; fi
    marks=$(head -c 16777216 -- "$file" 2>/dev/null |
        LC_ALL=C grep -aEo "$pattern"'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,5}\b' | LC_ALL=C sort -u)
    local version_pattern='([0-9]+\.[0-9]+\.[0-9]+)$'
    if [[ $marks != *$'\n'* && $marks =~ $version_pattern ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
    fi
}

audit_all() {
    local java_report nginx_report apache_report report name status result=no_risk result_reason exit_code
    local java_rc=0 nginx_rc=0 apache_rc=0 execution_failed=0
    local fallback='{"result":"pending","result_reason":"report_unavailable","exit_code":2,"error":"report_unavailable"}'
    local result_pattern='^\{"result":"(risk|pending|no_risk)"[,}]'
    local -a java_args=() nginx_args=() apache_args=()
    while (($#)); do
        case $1 in
            --json) ;;
            --jcmd) java_args+=("$1") ;;
            --nginx-path|--nginx-config)
                (($# >= 2)) || die "$1 requires a file path."
                nginx_args+=("$1" "$2"); shift ;;
            --apache-path|--apache-config)
                (($# >= 2)) || die "$1 requires a file path."
                apache_args+=("$1" "$2"); shift ;;
            *) die "Unknown full scan option. See --help." ;;
        esac
        shift
    done
    java_report=$(java4shell_main ${java_args[@]+"${java_args[@]}"}) || java_rc=$?
    nginx_report=$(nginx2root_scan ${nginx_args[@]+"${nginx_args[@]}"}) || nginx_rc=$?
    apache_report=$(apache_inventory ${apache_args[@]+"${apache_args[@]}"}) || apache_rc=$?

    # Each specialist emits result first, before any per-asset result fields.
    for name in java_report nginx_report apache_report; do
        report=${!name}
        if [[ $report =~ $result_pattern && $report == *'}' ]]; then
            status=${BASH_REMATCH[1]}
        else
            printf -v "$name" '%s' "$fallback"
            status=pending
            execution_failed=1
        fi
        case $status in
            risk) result=risk ;;
            pending) [[ $result == risk ]] || result=pending ;;
        esac
    done
    exit_code=$(scan_exit_code "$result")
    case $result in
        risk) result_reason=risk_gate_hit ;;
        pending) result_reason=specialist_evidence_incomplete ;;
        no_risk) result_reason=risk_gate_not_hit ;;
    esac
    if ((execution_failed || java_rc == 2 || nginx_rc == 2 || apache_rc == 2 ||
         java_rc > 3 || nginx_rc > 3 || apache_rc > 3)); then
        exit_code=2
        result_reason=execution_failed
    fi
    printf '{"result":"%s","result_reason":"%s","exit_code":%s,"scope":"local_read_only_inventory","java4shell":%s,"nginx2root":%s,"apache":%s}\n' \
        "$result" "$result_reason" "$exit_code" "$java_report" "$nginx_report" "$apache_report" || return 2
    return "$exit_code"
}

web_disk_identity() {
    local proc=$1 path=$2 image_id=$3 disk_id
    if [[ $path == *" (deleted)" ]]; then printf deleted
    elif [[ -z $image_id || $path != /* ]]; then printf unverified
    elif ! disk_id=$(file_id "$proc/root$path"); then printf unverified
    elif [[ $disk_id == "$image_id" ]]; then printf matched
    else printf mismatch
    fi
}

web_identity_boolean() {
    case $1 in matched) printf true ;; mismatch|deleted) printf false ;; *) printf null ;; esac
}

web_coverage_reason() {
    local limit=$1 budget_reached=$2 scan_unavailable=$3 visibility_limited=$4 unresolved=$5 config_incomplete=$6
    if [[ $limit == true || $budget_reached == true ]]; then
        printf scan_budget_exhausted
    elif [[ $scan_unavailable == true ]]; then
        printf process_scan_unavailable
    elif [[ $visibility_limited == true ]]; then
        printf process_visibility_limited
    elif ((unresolved > 0)); then
        printf runtime_evidence_incomplete
    elif [[ $config_incomplete == true ]]; then
        printf configuration_incomplete
    fi
}

web_package_hint() {
    local path=$1 ownership owner manager result
    have timeout || return 0
    [[ $path == /* ]] || return 0
    if have dpkg-query; then
        ownership=$(run_timed_command timeout -k 1s 2s dpkg-query -S -- "$path" 2>/dev/null) || return 0
        owner=$(PACKAGE_QUERY_PATH="$path" awk '
            { separator=index($0,": ") }
            separator && substr($0,separator+2) == ENVIRON["PACKAGE_QUERY_PATH"] {
                print substr($0,1,separator-1)
            }
        ' <<< "$ownership") || return 0
        [[ $owner =~ ^[[:alnum:].+:-]+$ ]] || return 0
        manager=dpkg
        result=$(run_timed_command timeout -k 1s 2s dpkg-query -W -f='${binary:Package} ${Version} ${db:Status-Status}' -- "$owner" 2>/dev/null) || return 0
        [[ $result == *" installed" ]] || return 0
        result=${result% installed}
    elif have rpm; then
        manager=rpm
        result=$(run_timed_command timeout -k 1s 2s rpm -qf --qf '%{NAME} %{VERSION}-%{RELEASE}' -- "$path" 2>/dev/null) || return 0
    else
        return 0
    fi
    [[ -n $result && $result != *$'\n'* ]] || return 0
    printf '{"manager":%s,"installed_package":%s,"patch_status":"unverified"}' "$(jstr "$manager")" "$(jstr "$(san_field "$result")")"
}

nginx2root_scan() {
    local path proc pid id raw title_path hint_source path_source version_source same_host possible_host process_root disk_id package_id
    local site_prefix=${NGINX_SITE_CONFIG%/conf/nginx.conf}
    local seen=' ' master_count=0 comma= gate=0 unknown=0 version_unknown=false total=0 config_report sctp_report package_hint findings=
    local start image_state proc_limit=false unresolved=0 self_ns process_ns self_root metadata flavor plus module_hints product_version compiled_config config_entry row_config config_source incomplete=false
    local index package_count=0 condition_not_observed=0 potential_missing=0 unknown_missing=0 unattributed=0 incomplete_config=0 unmapped= unmapped_seen=" "
    local config_blocking=false config_incomplete=false
    local config_directory_remaining=$NGINX_CONFIG_DIRECTORY_LIMIT config_glob_remaining=$NGINX_CONFIG_GLOB_LIMIT
    local config_glob_budget_reached=false
    local process_paths= process_entries=0 process_budget_reached=false process_scan_unavailable=false visibility_limited=false
    local process_role config_proc config_start config_parent_pid image_index image_count=0
    local config_count=0
    local -a package_ids=() package_values=()
    local -a config_paths=() explicit_paths=() processes=() installation_paths=() image_ids=() image_metadata=()
    local -a config_scopes=() config_entries=() config_values=()
    while (($#)); do
        case $1 in
            --json) ;;
            --nginx-config)
                (($# > 1)) && [ -n "$2" ] && [[ $2 != --* ]] || die "--nginx-config requires a file path."
                config_paths+=("$2"); shift ;;
            --nginx-path)
                (($# > 1)) && [ -n "$2" ] && [[ $2 != --* ]] || die "--nginx-path requires a file path."
                explicit_paths+=("$2"); shift ;;
            --help|-h)
                usage
                return ;;
            *) die "Unknown NGINX option. See --help." ;;
        esac
        shift
    done
    for path in ${explicit_paths[@]+"${explicit_paths[@]}"}; do
        [ -f "$path" ] || die "--nginx-path requires an existing file."
        path=$(readlink -f -- "$path") || die "Cannot resolve the --nginx-path file path."
        installation_paths+=("$path")
    done
    for path in ${config_paths[@]+"${config_paths[@]}"}; do
        [ -f "$path" ] || die "--nginx-config requires an existing file."
    done
    if [[ $OS != Linux ]]; then
        linux_inventory_unavailable Nginx2Root
        return $?
    fi
    if [[ -r /proc/self/stat ]]; then
        process_paths=$(linux_process_paths) || process_scan_unavailable=true
    else
        process_scan_unavailable=true
    fi
    while IFS= read -r proc; do
        [ -n "$proc" ] || continue
        if ((process_entries >= PROCESS_SCAN_LIMIT)); then
            process_budget_reached=true
            proc_limit=true
            break
        fi
        process_entries=$((process_entries + 1))
        if nginx_process "$proc"; then
            process_role=$(nginx_process_role "$proc")
            processes+=("$proc")
            if [[ $process_role == master ]]; then master_count=$((master_count + 1)); fi
        elif [[ $? -eq 2 ]]; then
            visibility_limited=true
        fi
    done <<< "$process_paths"
    installation_paths+=("$(type -P nginx || :)" "$(type -P openresty || :)" "$(type -P tengine || :)"
                        "$site_prefix/sbin/nginx" "$site_prefix/bin/nginx"
                        /usr/sbin/nginx /usr/local/nginx/sbin/nginx /usr/local/openresty/nginx/sbin/nginx /usr/local/tengine/sbin/nginx)
    nginx_read_config() {
        row_config=$(nginx2root_config "$@") || row_config=
        # Each distinct configuration spends from the same scan-wide budget.
        if [[ $row_config =~ \"directory_entries_examined\":([0-9]+),\"glob_expansions\":([0-9]+),\"glob_budget_reached\":(true|false) ]]; then
            config_directory_remaining=$((config_directory_remaining - BASH_REMATCH[1]))
            config_glob_remaining=$((config_glob_remaining - BASH_REMATCH[2]))
            if [[ ${BASH_REMATCH[3]} == true ]]; then config_glob_budget_reached=true; fi
        fi
    }

    nginx_read_config ${config_paths[@]+"${config_paths[@]}"}
    config_report=$row_config
    sctp_report=$(nginx2root_sctp)

    nginx_config_view_matches() {
        local source=$1 started=$2 root_id=$3 mount_ns=$4
        [[ $(java_process_start "${source##*/}") == "$started" &&
           $(file_id "$source/root") == "$root_id" &&
           ( -z $mount_ns || $(readlink "$source/ns/mnt" 2>/dev/null) == "$mount_ns" ) ]]
    }

    nginx_read_entry_config() {
        local entry=$1 source=${2:-} started=${3:-} root_id=${4:-} mount_ns=${5:-}
        local scope=host config_index
        row_config=
        if [[ -n $source ]]; then
            # Container workers share the verified config owner's filesystem view.
            nginx_config_view_matches "$source" "$started" "$root_id" "$mount_ns" || return 0
            scope="$source:$started:$root_id:$mount_ns"
        fi
        for ((config_index=0; config_index<config_count; config_index++)); do
            if [[ ${config_scopes[config_index]} == "$scope" && ${config_entries[config_index]} == "$entry" ]]; then
                row_config=${config_values[config_index]}
                return 0
            fi
        done
        if [[ -n $source ]]; then
            nginx_read_config --root "$source/root" "$entry"
            nginx_config_view_matches "$source" "$started" "$root_id" "$mount_ns" || row_config=
        else
            nginx_read_config "$entry"
        fi
        [[ -n $row_config ]] || return 0
        config_scopes[config_count]=$scope
        config_entries[config_count]=$entry
        config_values[config_count]=$row_config
        config_count=$((config_count + 1))
    }

    nginx2root_row() {
        local kind=$1 pid=$2 path=$3 raw=$4 package_hint=${5:-null} image_state=$6 path_source=${7:-} version_source=${8:-}
        local cves missing_count missing_potential missing_unknown missing_config skipped_config row_result=no_risk
        if [ -z "$raw" ]; then
            # OpenResty 官方四段版本号的前三段是所捆绑的 Nginx 内核版本。
            case $flavor:$product_version in
                openresty:*)
                    [[ $product_version =~ ^[0-9]+(\.[0-9]+){3}$ ]] && raw=${product_version%.*} ;;
                tengine:3.2.0-rc5) raw=1.31.5 ;;
            esac
        fi
        if [[ -z $raw && -n $product_version && ( $flavor == openresty || $flavor == tengine ) ]]; then
            local tag="$flavor/$product_version"
            if [[ $unmapped_seen != *" $tag "* ]]; then
                unmapped_seen+="$tag "
                unmapped+="${unmapped:+,}$(jstr "$tag")"
            fi
        fi
        cves=$(nginx2root_cves "$raw" "${row_config:-}" "$flavor" "$plus" "$version_source")
        if [[ $row_config =~ \"skipped\":[1-9] || $cves == *'"result_reason":"configuration_not_attributed"'* ]]; then
            config_blocking=true
        fi
        read -r missing_count missing_potential missing_unknown missing_config skipped_config < <(
            awk -F '}' '{
                for (i=1; i<=NF; i++) {
                    if ($i ~ /"config_evidence":"configuration_not_attributed"/) unattributed++
                    if ($i ~ /"config_evidence":"configuration_incomplete"/) skipped++
                    if ($i !~ /"config_evidence":"condition_not_observed"/) continue
                    total++
                    if ($i ~ /"version_range_match":true/) potential++
                    else if ($i ~ /"version_range_match":null/) unknown++
                }
            } END {print total+0, potential+0, unknown+0, unattributed+0, skipped+0}' <<< "$cves"
        )
        condition_not_observed=$((condition_not_observed + missing_count))
        potential_missing=$((potential_missing + missing_potential))
        unknown_missing=$((unknown_missing + missing_unknown))
        unattributed=$((unattributed + missing_config))
        incomplete_config=$((incomplete_config + skipped_config))
        case $cves in *'"result":"pending"'*) row_result=pending; unknown=1 ;; esac
        case $cves in *'"result":"risk"'*) row_result=risk; gate=1 ;; esac
        case $cves in *'"version_range_match":null'*) version_unknown=true ;; esac
        total=$((total + 1))
        findings+=$(
            printf '%s{"kind":"%s","pid":%s,"path":%s,"version":%s,"disk_identity_status":"%s","flavor":"%s","product_version":%s' \
                "$comma" "$kind" "$(jstr "$pid")" "$(jstr "$(san_field "$path")")" "$(jstr "$raw")" "$image_state" "$flavor" "$(jstr "$product_version")"
            if [[ $kind == process ]]; then printf ',"process_role":"%s"' "$process_role"; fi
            if [[ -n $path_source ]]; then printf ',"path_source":%s' "$(jstr "$path_source")"; fi
            if [[ -n $version_source ]]; then printf ',"version_source":%s' "$(jstr "$version_source")"; fi
            if [[ $flavor == plus ]]; then printf ',"plus_release":%s' "$(jstr "$plus")"; fi
            printf ',"cves":%s,"package_evidence":%s,"binary_module_hints":%s,"result":"%s"' \
                "$cves" "$package_hint" "${module_hints:-null}" "$row_result"
            if [[ -n $row_config ]]; then
                printf ',"configuration_entry":%s,"configuration_entry_source":%s' "$(jstr "$config_entry")" "$(jstr "$config_source")"
                if [[ $kind == process && -n $config_parent_pid ]]; then
                    printf ',"configuration_parent_pid":%s' "$config_parent_pid"
                fi
                if [[ $config_source == container_* || $row_config != "$config_report" ]]; then
                    printf ',"configuration":%s' "$row_config"
                fi
            fi
            printf '}'
        )
        comma=,
    }

    self_ns=$(readlink /proc/self/ns/mnt 2>/dev/null || :)
    self_root=$(file_id /proc/self/root || :)
    for proc in ${processes[@]+"${processes[@]}"}; do
        if ! nginx_process "$proc"; then
            unresolved=$((unresolved + 1))
            unknown=1
            continue
        fi
        pid=${proc##*/}
        start=$(java_process_start "$pid")
        process_role=$(nginx_process_role "$proc")
        path=$(readlink "$proc/exe" 2>/dev/null || :)
        id=$(file_id "$proc/exe" || :)
        metadata=
        for ((image_index=0; image_index<image_count; image_index++)); do
            [[ ${image_ids[image_index]} != "$id" ]] || break
        done
        if ((image_index < image_count)); then
            metadata=${image_metadata[image_index]}
        elif [[ -n $id && -n $start ]]; then
            metadata=$(nginx2root_binary_metadata "$proc/exe")
        fi
        IFS='|' read -r raw flavor plus module_hints product_version compiled_config <<< "$metadata"
        image_state=$(web_disk_identity "$proc" "$path" "$id")
        process_ns=$(readlink "$proc/ns/mnt" 2>/dev/null || :)
        process_root=$(file_id "$proc/root" || :)
        if [[ -z $id || -z $start || $(file_id "$proc/exe") != "$id" ||
              $(java_process_start "$pid") != "$start" ]]; then
            raw= flavor= plus= module_hints= product_version= compiled_config=
            image_state=unverified
        else
            seen+="$id "
            if ((image_index == image_count)); then
                image_ids[image_index]=$id
                image_metadata[image_index]=$metadata
                image_count=$((image_count + 1))
            fi
        fi
        [[ $image_state == matched ]] || unresolved=$((unresolved + 1))
        possible_host=true
        if [[ ( -n $self_ns && -n $process_ns && $process_ns != "$self_ns" ) ||
              ( -n $self_root && -n $process_root && $process_root != "$self_root" ) ]]; then
            possible_host=false
        fi
        path_source= version_source= package_id= hint_source=
        if [[ $process_role == master && $possible_host == true && -z $path && -z $id && -n $start ]] &&
                title_path=$(nginx_master_binary_hint "$proc"); then
            if [[ $title_path == /* ]]; then
                hint_source=process_title
            elif [[ $master_count -eq 1 && -r $proc/cgroup && -z $(container_hint "$proc") ]] &&
                    { [[ -n ${config_paths[0]:-} ]] || nginx_process_uses_default_config "$proc" ||
                      [[ -n $(nginx_process_config_entry "$proc") ]]; } &&
                    title_path=$(nginx_unique_local_binary "$title_path" "${installation_paths[@]}"); then
                hint_source=unique_local_installation
            fi
        fi
        if [[ -n $hint_source ]] && disk_id=$(file_id "$title_path") &&
                [[ $(java_process_start "$pid") == "$start" ]]; then
            metadata=$(nginx2root_binary_metadata "$title_path")
            if [[ $(file_id "$title_path") == "$disk_id" && $(java_process_start "$pid") == "$start" ]]; then
                path=$title_path
                path_source=$hint_source
                if [[ -n $metadata ]]; then
                    IFS='|' read -r raw flavor plus module_hints product_version compiled_config <<< "$metadata"
                    version_source=disk
                    package_id=$disk_id
                fi
                seen+="$disk_id "
            fi
        fi

        package_hint=null
        config_entry= row_config= config_source= config_parent_pid=
        same_host=false
        if [[ $image_state == matched && -n $self_ns && $process_ns == "$self_ns" &&
               -n $self_root && $process_root == "$self_root" && $(file_id "$path") == "$id" ]]; then
            same_host=true
            package_id=$id
        fi
        config_proc=$proc
        case $process_role in
            worker|auxiliary)
                config_proc=$(nginx_worker_parent "$proc" "$id" "$process_root" "$process_ns") || config_proc= ;;
            unknown) config_proc= ;;
        esac
        config_start=$start
        if [[ -n $config_proc && $config_proc != "$proc" ]]; then
            config_start=$(java_process_start "${config_proc##*/}")
        fi
        if [[ -n ${config_paths[0]:-} ]]; then
            row_config=$config_report
            config_source=explicit
            config_entry=${config_paths[0]}
        elif [[ -n $config_proc && -n $config_start && -n $start && $possible_host == false && -n $process_root ]]; then
            config_entry=$(nginx_process_config_entry "$config_proc")
            if [[ -n $config_entry ]]; then
                config_source=container_process_argument
            elif nginx_process_uses_default_config "$config_proc"; then
                config_source=container_default
                config_entry=$compiled_config
                if [[ -z $config_entry ]]; then
                    case $path in
                        /usr/sbin/nginx|/usr/bin/nginx) config_entry=/etc/nginx/nginx.conf ;;
                        /*/sbin/*|/*/bin/*) config_entry=${path%/*/*}/conf/nginx.conf ;;
                    esac
                fi
            fi
            if [[ $config_entry == /* && $(java_process_start "$pid") == "$start" ]]; then
                nginx_read_entry_config "$config_entry" "$config_proc" "$config_start" "$process_root" "$process_ns"
                if [[ $(java_process_start "$pid") != "$start" || $(file_id "$proc/root") != "$process_root" ||
                      ( -n $process_ns && $(readlink "$proc/ns/mnt" 2>/dev/null) != "$process_ns" ) ||
                      ( -n $id && $(file_id "$proc/exe") != "$id" ) ]]; then
                    row_config=
                fi
            fi
        elif [[ -n $config_proc && -n $config_start && -n $start && $possible_host == true &&
                ( $same_host == true || $image_state == unverified ) ]]; then
            config_entry=$(nginx_process_config_entry "$config_proc")
            if [[ -n $config_entry ]]; then
                config_source=process_argument
            elif [[ $same_host == true || -n $path_source ]] &&
                    config_entry=$(nginx_site_config_entry "$config_proc" "$path" "$flavor"); then
                config_source=installation_layout
            elif [[ $same_host == true || $path_source == unique_local_installation ]] &&
                    nginx_process_uses_default_config "$config_proc"; then
                if [[ $compiled_config == /* ]]; then
                    config_entry=$compiled_config
                elif [[ -z $compiled_config ]]; then
                    config_entry=$(nginx_layout_config "$path" "$flavor")
                fi
                config_source=installation_layout
            fi
            if [[ -n $config_entry && $(java_process_start "$pid") == "$start" ]]; then
                [[ $same_host == true ]] || config_source+=_unverified
                nginx_read_entry_config "$config_entry"
            fi
        fi
        if [[ -n $row_config && $config_source != explicit && $config_proc != "$proc" ]]; then
            if [[ $(java_process_start "${config_proc##*/}") == "$config_start" &&
                  $(java_process_start "$pid") == "$start" && $(file_id "$proc/exe") == "$id" &&
                  $(nginx_worker_parent "$proc" "$id" "$process_root" "$process_ns") == "$config_proc" ]]; then
                config_parent_pid=${config_proc##*/}
            else
                row_config=
            fi
        fi
        if [[ -n $package_id ]]; then
            for ((index=0; index<package_count; index++)); do
                [ "${package_ids[index]}" != "$package_id" ] || break
            done
            if [ "$index" -eq "$package_count" ]; then
                package_ids[index]=$package_id
                package_values[index]=$(web_package_hint "$path")
                package_count=$((package_count + 1))
            fi
            package_hint=${package_values[index]:-null}
        fi
        nginx2root_row process "$pid" "$path" "$raw" "$package_hint" "$image_state" "$path_source" "$version_source"
    done
    for path in "${installation_paths[@]}"; do
        [ -n "$path" ] && [ -f "$path" ] || continue
        id=$(file_id "$path") || continue
        [[ $seen != *" $id "* ]] || continue
        metadata=$(nginx2root_binary_metadata "$path")
        IFS='|' read -r raw flavor plus module_hints product_version compiled_config <<< "$metadata"
        seen+="$id "
        package_hint=$(web_package_hint "$path")
        config_entry= row_config= config_source=
        if [ -n "${config_paths[0]:-}" ]; then
            row_config=$config_report
            config_source=explicit
            config_entry=${config_paths[0]}
        elif config_entry=$(nginx_layout_config "$path" "$flavor") && [ -n "$config_entry" ]; then
            config_source=installation_layout
            if [[ $path == /usr/sbin/nginx && $config_entry == /etc/nginx/nginx.conf ]]; then config_source=system_layout; fi
            nginx_read_entry_config "$config_entry"
        fi
        nginx2root_row installation "" "$path" "$raw" "${package_hint:-null}" not_applicable
    done
    if ((total == 0)) && [[ $config_report =~ \"(files_examined|skipped)\":[1-9] ]]; then
        # Keep a finding for a discovered configuration, even if it was unreadable.
        flavor= plus= product_version= module_hints=
        row_config=$config_report
        config_entry=${config_paths[0]:-}
        config_source=host_scan
        [[ -z $config_entry ]] || config_source=explicit
        nginx2root_row configuration "" "$config_entry" "" null not_applicable
    fi
    if ((incomplete_config > 0)) || [[ $config_report =~ \"skipped\":[1-9] || $config_glob_budget_reached == true ]]; then
        config_blocking=true
    fi
    if ((unattributed > 0)) || [[ $config_blocking == true ]]; then
        config_incomplete=true
    fi
    local result=no_risk result_reason=risk_gate_not_hit exit_code coverage_reason
    if process_visibility_limited; then visibility_limited=true; fi
    if [[ $config_glob_budget_reached == true ]]; then
        coverage_reason=scan_budget_exhausted
    else
        coverage_reason=$(web_coverage_reason "$proc_limit" "$process_budget_reached" "$process_scan_unavailable" "$visibility_limited" "$unresolved" "$config_blocking")
    fi
    if [[ -z $coverage_reason && $unknown -eq 1 ]]; then
        coverage_reason=finding_evidence_incomplete
        if [[ $version_unknown == true ]]; then coverage_reason=version_match_unknown; fi
    fi
    if [[ -n $coverage_reason || $config_incomplete == true ]]; then incomplete=true; fi
    if ((gate == 1)); then
        result=risk
        result_reason=risk_gate_hit
    elif [[ -n $coverage_reason ]]; then
        result=pending
        result_reason=$coverage_reason
    elif ((total == 0)); then
        result_reason=no_nginx_findings
    elif ((unattributed > 0)); then
        result_reason=version_outside_range
    fi
    exit_code=$(scan_exit_code "$result")
    printf '{"result":"%s","result_reason":"%s","exit_code":%s,"category":"Nginx2Root"' "$result" "$result_reason" "$exit_code"
    printf ',"assessment_scope":"version_and_disk_configuration","patch_verified":false,"sctp":%s,"configuration_scope":"host","configuration":%s,"findings":[%s],' \
        "$sctp_report" "$config_report" "$findings"
    printf '"coverage":{"proc_limit_reached":%s,"incomplete_process_evidence":%d,"evidence_incomplete":%s,"configuration_incomplete":%s,"process_visibility_limited":%s,"process_scan_limit":%s,"process_entries_examined":%s,"process_budget_reached":%s,"process_scan_unavailable":%s,' \
        "$proc_limit" "$unresolved" "$incomplete" "$config_incomplete" "$visibility_limited" "$PROCESS_SCAN_LIMIT" "$process_entries" "$process_budget_reached" "$process_scan_unavailable"
    printf '"config_directory_entry_limit":%s,"config_directory_entries_examined":%s,"config_glob_expansion_limit":%s,"config_glob_expansions":%s,"config_glob_budget_reached":%s},' \
        "$NGINX_CONFIG_DIRECTORY_LIMIT" "$((NGINX_CONFIG_DIRECTORY_LIMIT - config_directory_remaining))" \
        "$NGINX_CONFIG_GLOB_LIMIT" "$((NGINX_CONFIG_GLOB_LIMIT - config_glob_remaining))" "$config_glob_budget_reached"
    printf '"summary":{"condition_not_observed":%d,"potential_condition_not_observed":%d,"unknown_condition_not_observed":%d,"configuration_not_attributed":%d,"configuration_incomplete":%d,"unmapped_product_versions":[%s]}}\n' \
        "$condition_not_observed" "$potential_missing" "$unknown_missing" "$unattributed" "$incomplete_config" "$unmapped" || return 2
    return "$exit_code"
}

java4shell_main() {
    parse_args "$@"

    WORK=$(mktemp -d "${TMPDIR:-/tmp}/java4shell.XXXXXX") || die "Cannot create the Java scan temporary directory."
    FIND_FILE="$WORK/findings.tsv"
    WARN_FILE="$WORK/warnings.txt"
    ACTIVE_FILE="$WORK/active-ids"
    ROOT_COVERAGE_FILE="$WORK/root-coverage"
    trap 'cleanup' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    local scratch_file
    for scratch_file in "$ROOT_COVERAGE_FILE" "$FIND_FILE" "$WARN_FILE" "$ACTIVE_FILE"; do
        : > "$scratch_file" || die "Cannot initialize the temporary report."
    done
    printf '0\n' > "$WORK/map-bytes" || die "Cannot initialize the process map byte count."

    if [ "$PROC_ONLY" -eq 1 ]; then MODE_NAME="processes-only"; else MODE_NAME="local"; fi

    if [ ${#ROOT_ARGS[@]} -gt 0 ] && [ "$PROC_ONLY" -eq 0 ]; then
        local r
        for r in ${ROOT_ARGS[@]+"${ROOT_ARGS[@]}"}; do
            [ -d "$r" ] || die "--root requires an existing directory."
        done
    fi

    cpu_probe

    if [ "$EUID" -ne 0 ] 2>/dev/null; then
        warn "The scan runs without root privileges. Limited /proc access can prevent discovery of processes that other users own."
    fi

    case $OS in
        Linux) : ;;
        Darwin) : ;;
        *) warn "The platform ($OS) has no /proc. The scan uses launcher hints for process checks." ;;
    esac

    # --- 运行进程 ---
    if [ "$NO_PROC" -eq 0 ]; then
        if [[ $OS == Linux && -r /proc/self/stat ]]; then
            scan_processes
        elif [ "$OS" = "Darwin" ]; then
            scan_processes_other
        else
            JAVA_PROC_SCAN_UNAVAILABLE=true
            warn "The scan cannot discover processes on this platform."
        fi
    fi

    # --- 安装目录 ---
    if [ "$PROC_ONLY" -eq 0 ]; then
        scan_installations
    fi

    local coverage_counts
    coverage_counts=$(awk '
        { counts[$0]++ }
        END { printf "%d %d\n", counts["boundary"], counts["error"] }
    ' "$ROOT_COVERAGE_FILE") || die "Cannot read the directory scan coverage record."
    read -r ROOT_DEPTH_BOUNDARIES ROOT_SCAN_ERRORS <<< "$coverage_counts" ||
        die "Cannot parse the directory scan coverage record."
    IFS= read -r JAVA_MAP_BYTES_READ < "$WORK/map-bytes" || die "Cannot read the process map byte count."
    if [[ -f $WORK/map-total-limit ]] || grep -qx map_limit "$ROOT_COVERAGE_FILE"; then
        JAVA_MAP_BUDGET_REACHED=true
    fi
    if grep -qx root_limit "$ROOT_COVERAGE_FILE"; then JAVA_ROOT_BUDGET_REACHED=true; fi
    if [ "$ROOT_DEPTH_BOUNDARIES" -gt 0 ]; then
        warn "$ROOT_DEPTH_BOUNDARIES directories reached --root-depth $ROOT_DEPTH. The scan skipped deeper directories."
    fi
    if ((LIMITED_PROCS > 0)); then
        warn "Cannot read the maps of $LIMITED_PROCS processes. This can hide embedded JVMs."
    fi

    if ((NO_PROC == 0 && ${#PID_ARGS[@]} == 0)) &&
       process_visibility_limited; then
        JAVA_PROC_VISIBILITY_LIMITED=true
    fi

    if [ "$(total_count)" -eq 0 ]; then
        warn "The scan found no Java assets to assess in its scope."
    fi

    report_json
}

# 帮助使用与巡检报告相同的 JSON 格式。
usage() {
    printf '{"result":"pending","event":"help","program":%s,"version":%s,"usage":["--all","--java4shell [OPTIONS]","--nginx2root [--nginx-path PATH] [--nginx-config FILE]","--apache2root [--apache-path PATH] [--apache-config FILE]"],"output":"English JSON only","results":["risk","no_risk","pending"],' "$(jstr "$PROG")" "$(jstr "$SCRIPT_VERSION")"
    printf '"java_options":["--root DIR","--root-depth N","--pid PID","--processes-only","--no-processes","--jcmd","--json"],'
    printf '"scan_timeout_seconds":%s,' "$SCAN_TIMEOUT_SECONDS"
    printf '"exit_codes":{"0":"No risk gate matched in the checked scope.","1":"A risk gate matched, even if coverage is incomplete.","2":"Invalid arguments or execution failure.","3":"No risk gate matched and the evidence is insufficient."},'
    printf '"process_visibility_hint":"If host processes are not visible, rerun from an environment that can see them."}\n'
}

# 将内部检测状态映射为 JSON 结果。
output_result() {
    case ${1:-unknown} in
        affected|potential|1) printf risk ;;
        mitigated|not_affected|outside_scope|outside_upstream_range|meets_upstream_reference|0) printf no_risk ;;
        *) printf pending ;;
    esac
}

# Java 巡检报告
report_json() {
    local id kind status reason build bevid cpu version jhome vendor product vm arch flags feff container notes identity disk_version disk_vendor disk_product disk_build
    local affected potential mitigated safe unknown total result finding_result exit_code first=1
    local result_reason=risk_gate_not_hit coverage_reason= incomplete=false
    affected=$(status_count affected); potential=$(status_count potential)
    mitigated=$(status_count mitigated); safe=$(status_count not_affected)
    unknown=$(status_count unknown); total=$(total_count)
    if java_budget_reached; then
        coverage_reason=scan_budget_exhausted
    elif [[ $JAVA_PROC_SCAN_UNAVAILABLE == true ]]; then
        coverage_reason=process_scan_unavailable
    elif [[ $JAVA_PROC_VISIBILITY_LIMITED == true ]]; then
        coverage_reason=process_visibility_limited
    elif ((LIMITED_PROCS > 0)); then
        coverage_reason=unreadable_process_maps
    elif ((ROOT_DEPTH_BOUNDARIES > 0 || ROOT_SCAN_ERRORS > 0)); then
        coverage_reason=scan_coverage_incomplete
    elif ((unknown > 0)); then
        coverage_reason=finding_evidence_incomplete
    fi
    if [[ -n $coverage_reason ]]; then incomplete=true; fi
    result=no_risk
    if ((affected + potential > 0)); then
        result=risk
        result_reason=risk_gate_hit
    elif [[ -n $coverage_reason ]]; then
        result=pending
        result_reason=$coverage_reason
    elif ((total == 0)); then
        result_reason=no_java_findings
    elif [[ $OS == Linux && ( $ARCH_NORM == x86_64 || $ARCH_NORM == amd64 ) &&
            $CPU_SOURCE == /proc/cpuinfo && $CPU_STATE == absent ]]; then
        result_reason=cpu_condition_not_met
    fi
    exit_code=$(scan_exit_code "$result")
    printf '{"result":"%s","result_reason":"%s","exit_code":%s,"category":"Java4Shell","cve":%s,"rules_as_of":%s,"mode":%s,' \
        "$result" "$result_reason" "$exit_code" "$(jstr "$CVE")" "$(jstr "$RULES_AS_OF")" "$(jstr "$MODE_NAME")"
    printf '"summary":{"total":%s,"risk":%s,"no_risk":%s,"pending":%s},' "$total" "$((affected + potential))" "$((mitigated + safe))" "$unknown"
    printf '"cpu":{"arch":%s,"state":%s,"required_features":%s,"counts":%s},' \
        "$(jstr "$ARCH_RAW")" "$(jstr "$CPU_STATE")" "$(jstr "$REQ_FEATURES")" "$(jstr "$CPU_COUNTS")"
    printf '"coverage":{"evidence_incomplete":%s,"root_max_depth":%s,"root_depth_boundaries":%s,"root_scan_errors":%s,"unreadable_process_maps":%s,"process_scan_unavailable":%s,"process_visibility_limited":%s,' \
        "$incomplete" "$((10#$ROOT_DEPTH))" "$ROOT_DEPTH_BOUNDARIES" "$ROOT_SCAN_ERRORS" "$LIMITED_PROCS" "$JAVA_PROC_SCAN_UNAVAILABLE" "$JAVA_PROC_VISIBILITY_LIMITED"
    printf '"process_scan_limit":%s,"process_entries_examined":%s,"process_budget_reached":%s,"map_read_limit_bytes":%s,"map_total_limit_bytes":%s,"map_bytes_read":%s,"map_budget_reached":%s,' \
        "$PROCESS_SCAN_LIMIT" "$JAVA_PROC_ENTRIES" "$JAVA_PROC_BUDGET_REACHED" "$MAP_SCAN_MAX_BYTES" "$MAP_SCAN_TOTAL_BYTES" "$JAVA_MAP_BYTES_READ" "$JAVA_MAP_BUDGET_REACHED"
    printf '"directory_entry_limit":%s,"directory_timeout_seconds":%s,"root_budget_reached":%s}' \
        "$DIRECTORY_SCAN_LIMIT" "$DIRECTORY_SCAN_SECONDS" "$JAVA_ROOT_BUDGET_REACHED"
    if ((LIMITED_PROCS > 0)); then
        printf ',"warnings":[{"code":"unreadable_process_maps","count":%s}]' "$LIMITED_PROCS"
    fi
    printf ',"findings":['
    while IFS=$'\037' read -r id kind status reason build bevid cpu version jhome vendor product vm arch flags feff container notes identity disk_version disk_vendor disk_product disk_build; do
        [ -n "$id" ] || continue
        [ "$first" -eq 1 ] || printf ','; first=0
        finding_result=$(output_result "$status")
        # 为机器接口提供固定的判定说明。
        case $status in
            affected) reason='Risk identified by the configured build and runtime rules.' ;;
            potential) reason='Potential risk identified; vendor or runtime verification is required.' ;;
            mitigated) reason='Mitigation identified by the configured rules.' ;;
            not_affected) reason='Outside the affected conditions of the configured rules.' ;;
            *) reason='Insufficient evidence to determine risk.' ;;
        esac
        printf '{"id":%s,"kind":%s,"result":"%s","reason":%s,"build_assessment":%s,"cpu_assessment":%s,' \
            "$(jstr "$id")" "$(jstr "$kind")" "$finding_result" "$(jstr "$reason")" "$(jstr "$build")" "$(jstr "$cpu")"
        printf '"version":%s,"java_home":%s,"vendor":%s,"product":%s,"vm":%s,"arch":%s,"flags":%s,"flags_effective":%s' \
            "$(jstr "$version")" "$(jstr "$jhome")" "$(jstr "$vendor")" "$(jstr "$product")" "$(jstr "$vm")" "$(jstr "$arch")" "$(jstr "$flags")" "${feff:-false}"
        [ -z "$identity" ] || printf ',"identity_confidence":%s' "$(jstr "$identity")"
        [ -z "$disk_build" ] || printf ',"disk_evidence":{"version":%s,"vendor":%s,"product":%s,"build_assessment":%s}' \
            "$(jstr "$disk_version")" "$(jstr "$disk_vendor")" "$(jstr "$disk_product")" "$(jstr "$disk_build")"
        printf '}'
    done < "$FIND_FILE"
    printf ']}\n' || return 2
    return "$exit_code"
}

main() {
    if [ "$#" -eq 0 ]; then audit_all; return; fi
    case $1 in
        --all) shift; audit_all "$@" ;;
        --nginx2root) shift; nginx2root_scan "$@" ;;
        --apache2root) shift; apache_inventory "$@" ;;
        --java4shell) shift; java4shell_main "$@" ;;
        *) java4shell_main "$@" ;;
    esac
}

stop_supervised_scan() {
    local scan_pid=$1 signal=$2 scan_started=$3 exit_code=143
    # The launcher checks for a signal received before the background PID was assigned.
    [[ -n $scan_pid ]] || return 0
    trap '' INT TERM
    if [[ $signal == INT ]]; then exit_code=130; fi
    {
        if kill -s "$signal" -- "-$scan_pid" &&
                ((SECONDS - scan_started < SCAN_TIMEOUT_SECONDS - 1)); then
            sleep 1 || :
        fi
        kill -s KILL -- "-$scan_pid" || :
        wait "$scan_pid" || :
    } 2>/dev/null
    printf '{"result":"pending","result_reason":"scan_interrupted","exit_code":%s,"error":"scan_interrupted","signal":"%s"}\n' "$exit_code" "$signal"
    exit "$exit_code"
}

run_supervised_scan() {
    local timer script_path=${BASH_SOURCE[0]} scan_rc=0 scan_pid= interrupt_signal= scan_started
    local -a worker_flags=(--noprofile --norc)
    if ! timer=$(type -P timeout || type -P gtimeout); then
        printf '{"result":"pending","result_reason":"timeout_utility_unavailable","exit_code":2,"error":"timeout_utility_unavailable","message":"Running a scan requires timeout or gtimeout."}\n'
        return 2
    fi
    [[ $script_path == /* ]] || script_path=$PWD/$script_path
    if [[ $- == *e* ]]; then worker_flags+=(-e); fi
    if shopt -qo pipefail; then worker_flags+=(-o pipefail); fi
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/x2shell-scan.XXXXXX") || die "Cannot create the scan temporary directory."
    trap 'cleanup' EXIT
    scan_started=$SECONDS
    trap 'interrupt_signal=TERM; stop_supervised_scan "$scan_pid" "$interrupt_signal" "$scan_started"' TERM
    trap 'interrupt_signal=INT; stop_supervised_scan "$scan_pid" "$interrupt_signal" "$scan_started"' INT
    # Give the watchdog its own process group from launch. A background wait lets the launcher trap signals.
    set -m
    # Spool the worker output so a forced stop can replace it with a complete error report.
    TMPDIR="$WORK" "$timer" -s KILL "${SCAN_TIMEOUT_SECONDS}s" \
        "$BASH" "${worker_flags[@]}" -c '
            source "$1" || exit 2
            shift
            SCAN_DEADLINE_ACTIVE=1
            set +m
            main "$@"
        ' "$PROG" "$script_path" "$@" > "$WORK/report.json" 2> "$WORK/stderr.log" &
    scan_pid=$!
    set +m
    if [[ -n $interrupt_signal ]]; then
        stop_supervised_scan "$scan_pid" "$interrupt_signal" "$scan_started"
    fi
    wait "$scan_pid" 2>/dev/null || scan_rc=$?
    scan_pid=
    trap - INT TERM
    case $scan_rc in
        124|137)
            printf '{"result":"pending","result_reason":"scan_timeout","exit_code":2,"error":"scan_timeout","timeout_seconds":%s}\n' "$SCAN_TIMEOUT_SECONDS"
            return 2 ;;
        0|1|2|3) ;;
        *) die "The scan process failed." ;;
    esac
    if [[ -s $WORK/stderr.log ]]; then cat -- "$WORK/stderr.log" >&2; fi
    [[ -s $WORK/report.json ]] || die "The scan report is unavailable."
    cat -- "$WORK/report.json" || return 2
    return "$scan_rc"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    case ${1:-} in
        -h|--help|-V|--version) main "$@" ;;
        *) run_supervised_scan "$@" ;;
    esac
fi
