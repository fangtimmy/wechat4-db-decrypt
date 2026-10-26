#!/bin/bash
# 一键导出（macOS）：构建 SIP 调试副本 → Gadget 抓密钥 → 映射 → 解密 → 批量导出
# Windows 请使用 run.ps1 / run.bat。
# 用法:
#   ./run.sh              # 全流程
#   ./run.sh --no-hunt    # 跳过抓密钥（密钥没变时，只重新解密+导出）
#   ./run.sh --no-restart # 连接已运行的 Gadget 微信副本
set -euo pipefail

case "$(uname -s)" in
    Darwin) ;;
    *)
        echo "[!] run.sh 仅适用于 macOS；Windows 请使用 run.ps1 或 run.bat" >&2
        exit 1
        ;;
esac

cd "$(dirname "$0")"

NO_HUNT=0
NO_RESTART=0
REFRESH_SNAPSHOT=0
OUTPUT_DIR="$(pwd)/exported_all"

usage() {
    cat <<'EOF'
用法: ./run.sh [选项]

选项:
  --no-hunt           复用已有密钥，跳过 Gadget 抓取
  --no-restart        连接已经运行的 Gadget 调试副本
  --refresh-snapshot  刷新调试容器内的 APFS 数据快照
  --output DIR        将聊天记录导出到 DIR
  -h, --help          显示帮助
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --no-hunt)
            NO_HUNT=1
            ;;
        --no-restart)
            NO_RESTART=1
            ;;
        --refresh-snapshot)
            REFRESH_SNAPSHOT=1
            ;;
        --output)
            if [ "$#" -lt 2 ]; then
                echo "[!] --output 缺少目录参数" >&2
                exit 2
            fi
            OUTPUT_DIR="$2"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "[!] 未知参数: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

if [ "$NO_HUNT" -eq 1 ] && [ "$NO_RESTART" -eq 1 ]; then
    echo "[!] --no-hunt 与 --no-restart 不能同时使用" >&2
    exit 2
fi
if [ "$REFRESH_SNAPSHOT" -eq 1 ] && \
        { [ "$NO_HUNT" -eq 1 ] || [ "$NO_RESTART" -eq 1 ]; }; then
    echo "[!] --refresh-snapshot 需要完整重启抓取，不能与 --no-hunt/--no-restart 同时使用" >&2
    exit 2
fi

# 自动识别 SIP。无论开启或关闭均使用内嵌 Gadget；开启时不需要 task_for_pid，
# 关闭时也避免退回 root 外部附加链路，保持单一、可验证的执行路径。
SIP_OUTPUT=$(csrutil status 2>/dev/null || true)
case "$SIP_OUTPUT" in
    *"System Integrity Protection status: enabled"*)
        SIP_STATUS=enabled
        echo "[+] 检测到 SIP 已开启：自动使用内嵌 Frida Gadget 模式"
        ;;
    *"System Integrity Protection status: disabled"*)
        SIP_STATUS=disabled
        echo "[*] 检测到 SIP 已关闭：继续使用内嵌 Frida Gadget 模式（无需 root）"
        ;;
    *)
        SIP_STATUS=unknown
        echo "[!] 无法确定 SIP 状态，按兼容性最高的内嵌 Gadget 模式继续" >&2
        ;;
esac
export SIP_STATUS

# 1. 虚拟环境与依赖（uv 托管）
if ! command -v uv >/dev/null 2>&1; then
    echo "[!] 未找到 uv，请先安装: curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
    exit 1
fi
uv sync --frozen --quiet
PY="$PWD/.venv/bin/python"

# 2. 官方 /Applications/WeChat.app 仅作为只读源，调试副本放在 .runtime。
if [ "$NO_HUNT" -eq 0 ]; then
    "$PY" -m wxexport.sip.prepare
fi

# 3. TCC/App Data 权限预检及数据目录检测
"$PY" -m wxexport.check_permissions
"$PY" -c "from wxexport.config import load_config; load_config()"

# 4. Gadget 抓取
if [ "$NO_HUNT" -eq 0 ]; then
    if [ "$NO_RESTART" -eq 1 ]; then
        "$PY" -m wxexport.keys.hunt --timeout 180
    else
        HUNT_ARGS=(--restart)
        if [ "$REFRESH_SNAPSHOT" -eq 1 ]; then
            HUNT_ARGS+=(--refresh-snapshot)
        fi
        "$PY" -m wxexport.keys.hunt "${HUNT_ARGS[@]}"
    fi
fi

# 5. 密钥映射 → 解密 → 批量导出
"$PY" -m wxexport.keys.map
"$PY" -m wxexport.decrypt
"$PY" -m wxexport.export.all --output "$OUTPUT_DIR"

OUTPUT_ABS=$("$PY" -c 'import os,sys; print(os.path.abspath(os.path.expanduser(sys.argv[1])))' "$OUTPUT_DIR")

echo
echo "============================================================"
echo " 完成。聊天记录在: $OUTPUT_ABS/"
echo " 总索引:          $OUTPUT_ABS/index.csv"
echo "============================================================"
