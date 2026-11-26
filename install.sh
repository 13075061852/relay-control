#!/usr/bin/env bash
# Relay Control 中转面板 + Xray 一键安装
# 系统: Debian/Ubuntu、RHEL/CentOS/Rocky/Alma/Fedora、openSUSE（需 systemd）
# 架构: x86_64、aarch64/arm64、armv7、armv6、i686、loongarch64、riscv64、s390x 等
# 用法: sudo bash install.sh --host <公网IP> [--label 名称] [--xray-version v26.3.27] [--dry-run]
set -Eeu
set -o pipefail
shopt -s lastpipe 2>/dev/null || true

HOST_IP=""
LABEL="中转控制台"
XRAY_VERSION="${XRAY_VERSION:-v26.3.27}"
PANEL_PORT=8443
CONFIG_PORT=8443
DRY_RUN=0
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST_IP="${2:-}"; shift 2 ;;
    --label) LABEL="${2:-}"; shift 2 ;;
    --xray-version) XRAY_VERSION="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) sed -n '2,5p' "$0"; exit 0 ;;
    *) echo "未知参数: $1"; exit 1 ;;
  esac
done

log() { printf '\033[1;34m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "请使用 root 运行"
if [ "$DRY_RUN" = 0 ] && [ ! -f "$SRC_DIR/files/app.py" ]; then die "缺少 files/ 目录，请在仓库根目录执行"; fi

log "1/9 检查系统"
if [ -r /etc/os-release ]; then . /etc/os-release; fi
OS_NAME="${PRETTY_NAME:-$(uname -s)}"
OS_ID="${ID:-unknown}"; OS_VER="${VERSION_ID:-}"
log "系统: $OS_NAME"

command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] || die "本脚本依赖 systemd，当前系统不是 systemd 管理（Alpine/OpenRC、WSL1 等不支持）。可换 Debian/Ubuntu/CentOS/Rocky 等发行版。"

case "$(uname -m)" in
  x86_64|amd64) XRAY_ARCH="64" ;;
  i386|i486|i586|i686) XRAY_ARCH="32" ;;
  aarch64|arm64) XRAY_ARCH="arm64-v8a" ;;
  armv7*|armv8l) XRAY_ARCH="arm32-v7a" ;;
  armv6*) XRAY_ARCH="arm32-v6" ;;
  armv5*) XRAY_ARCH="arm32-v5" ;;
  loongarch64|loong64) XRAY_ARCH="loong64" ;;
  riscv64) XRAY_ARCH="riscv64" ;;
  s390x) XRAY_ARCH="s390x" ;;
  ppc64le) XRAY_ARCH="ppc64le" ;;
  ppc64) XRAY_ARCH="ppc64" ;;
  mips64le) XRAY_ARCH="mips64le" ;;
  mips64) XRAY_ARCH="mips64" ;;
  mipsel) XRAY_ARCH="mips32le" ;;
  mips) XRAY_ARCH="mips32" ;;
  *) die "不支持的 CPU 架构: $(uname -m)" ;;
esac
log "架构: $(uname -m) -> Xray-linux-$XRAY_ARCH.zip"

if command -v apt-get >/dev/null 2>&1; then PKG=apt
elif command -v dnf >/dev/null 2>&1; then PKG=dnf
elif command -v yum >/dev/null 2>&1; then PKG=yum
elif command -v zypper >/dev/null 2>&1; then PKG=zypper
elif command -v apk >/dev/null 2>&1; then PKG=apk
else PKG=""; fi
[ -n "$PKG" ] || die "找不到 apt / dnf / yum / zypper / apk，无法安装依赖"
log "包管理器: $PKG"

if [ "$DRY_RUN" = 1 ]; then
  log "dry-run: 仅检查环境，不做任何修改"
  printf '  系统       %s\n' "$OS_NAME"
  printf '  架构       %s (%s)\n' "$(uname -m)" "$XRAY_ARCH"
  printf '  包管理器   %s\n' "$PKG"
  printf '  systemd    %s\n' "$(systemctl --version | head -1)"
  printf '  Xray       %s / Xray-linux-%s.zip\n' "$XRAY_VERSION" "$XRAY_ARCH"
  printf '  apt/pip    %s\n' "$( [ "$PKG" = apt ] && echo apt || echo "$PKG + pip 兜底" )"
  exit 0
fi

# Debian 11 已停止维护，security 源下架；改为归档源，否则依赖装不上
if [ "$PKG" = apt ] && [ "$OS_VER" = "11" ]; then
  CHANGED=0
  for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do
    [ -f "$f" ] || continue
    if grep -qs 'security.debian.org/debian-security' "$f"; then
      cp -a "$f" "$f.bak.$(date +%s)"
      sed -i 's|https\?://security.debian.org/debian-security|http://archive.debian.org/debian-security|' "$f"
      sed -i 's|https\?://ftp.debian.org/debian|http://archive.debian.org/debian|' "$f"
      sed -i '/bullseye-updates/d' "$f" || true
      CHANGED=1
    fi
  done
  if [ "$CHANGED" = 1 ]; then
    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-valid-until
    log "检测到 Debian 11，已切换归档源"
  fi
fi

log "2/9 安装依赖 (curl / ca-certificates / python3 / openssl)"
export DEBIAN_FRONTEND=noninteractive
case "$PKG" in
  apt)
    apt-get update -qq || warn "apt update 返回非零，继续尝试安装"
    apt-get install -y -qq curl ca-certificates python3 openssl iproute2 >/dev/null ;;
  dnf|yum)
    "$PKG" install -y -q curl ca-certificates python3 openssl iproute >/dev/null 2>&1 \
      || "$PKG" install -y curl ca-certificates python3 openssl iproute >/dev/null ;;
  zypper)
    zypper --non-interactive --quiet install curl ca-certificates python3 openssl iproute2 >/dev/null ;;
  apk)
    apk add --no-cache curl ca-certificates python3 openssl iproute2 >/dev/null ;;
esac
command -v curl >/dev/null || die "curl 安装失败"
command -v openssl >/dev/null || die "openssl 安装失败"
command -v python3 >/dev/null || die "python3 安装失败"

# 二维码依赖：优先用发行版包，失败了再用 pip，兼容 qrcode 7.1 与 7.3+
ensure_qrcode() {
  python3 -c 'import qrcode, qrcode.image.svg' >/dev/null 2>&1 && return 0
  case "$PKG" in
    apt) apt-get install -y -qq python3-qrcode >/dev/null 2>&1 || true ;;
    dnf|yum) "$PKG" install -y python3-qrcode >/dev/null 2>&1 || true ;;
    zypper) zypper --non-interactive --quiet install python3-qrcode >/dev/null 2>&1 || true ;;
    apk) apk add --no-cache py3-qrcode >/dev/null 2>&1 || true ;;
  esac
  python3 -c 'import qrcode, qrcode.image.svg' >/dev/null 2>&1 && return 0
  python3 -m pip install --quiet --disable-pip-version-check qrcode >/dev/null 2>&1 \
    || python3 -m pip install --quiet --break-system-packages --disable-pip-version-check qrcode >/dev/null 2>&1 \
    || { case "$PKG" in
           apt) apt-get install -y -qq python3-pip >/dev/null 2>&1 && python3 -m pip install --quiet --break-system-packages qrcode >/dev/null 2>&1 ;;
           dnf|yum) "$PKG" install -y python3-pip >/dev/null 2>&1 && python3 -m pip install --quiet qrcode >/dev/null 2>&1 ;;
           *) false ;;
         esac; }
  python3 -c 'import qrcode, qrcode.image.svg' >/dev/null 2>&1 \
    || die "无法安装 python3 qrcode 模块，请手动安装后重跑（apt install python3-qrcode / pip3 install qrcode）"
}
ensure_qrcode

if [ -z "$HOST_IP" ]; then
  HOST_IP="$(curl -4 -fsS --max-time 8 https://api.ipify.org 2>/dev/null || curl -4 -fsS --max-time 8 https://ifconfig.me 2>/dev/null || true)"
  [ -n "$HOST_IP" ] || die "无法自动识别公网 IP，请用 --host 指定"
  log "自动识别公网 IP: $HOST_IP"
fi

log "3/9 创建用户与目录"
NOLOGIN="$(for p in /usr/sbin/nologin /sbin/nologin /bin/false; do [ -x "$p" ] && echo "$p" && break; done)"
[ -n "$NOLOGIN" ] || NOLOGIN=/bin/false
if ! getent group xray-att-relay >/dev/null; then
  if command -v groupadd >/dev/null; then groupadd -r xray-att-relay; else addgroup -S xray-att-relay; fi
fi
if ! id -u xray-att-relay >/dev/null 2>&1; then
  if command -v useradd >/dev/null; then
    useradd -r -g xray-att-relay -d /nonexistent -s "$NOLOGIN" xray-att-relay
  else
    adduser -S -H -h /nonexistent -s "$NOLOGIN" -G xray-att-relay xray-att-relay
  fi
fi
install -d -m 0700 /etc/node-admin /var/backups/node-admin /var/log/node-admin
install -d -m 0700 /etc/fastclient-subscription /etc/att-subscription
install -d -m 0755 /usr/local/lib/relay-dns-fallback /opt/node-admin
install -d -m 0750 -o root -g xray-att-relay /etc/xray-att-relay
chmod 2750 /etc/xray-att-relay

log "4/9 安装 Xray $XRAY_VERSION"
XRAY_ASSET="Xray-linux-$XRAY_ARCH.zip"
if [ -x /usr/local/bin/xray ]; then
  log "已存在 $(/usr/local/bin/xray version 2>/dev/null | head -1 || true)，跳过下载"
else
  TMP="$(mktemp -d)"
  BASE="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}"
  curl -fL --retry 3 --connect-timeout 15 -o "$TMP/xray.zip" "$BASE/$XRAY_ASSET" \
    || { rm -rf "$TMP"; die "Xray 下载失败: $BASE/$XRAY_ASSET（检查网络能否访问 github.com）"; }
  if curl -fsSL --max-time 20 -o "$TMP/xray.zip.dgst" "$BASE/$XRAY_ASSET.dgst" 2>/dev/null; then
    EXPECT="$(sed -n 's/^SHA2-256=[[:space:]]*//p' "$TMP/xray.zip.dgst" | head -1 | tr -d '[:space:]')"
    if [ -n "$EXPECT" ] && command -v sha256sum >/dev/null; then
      ACTUAL="$(sha256sum "$TMP/xray.zip" | awk '{print $1}')"
      [ "$EXPECT" = "$ACTUAL" ] || { rm -rf "$TMP"; die "Xray 校验和不匹配，已中止安装"; }
      log "Xray 包 SHA256 校验通过"
    fi
  else
    warn "未取到官方校验文件，跳过哈希校验"
  fi
  python3 - "$TMP/xray.zip" "$TMP" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as zf:
    for name in ('xray', 'geoip.dat', 'geosite.dat'):
        try:
            zf.extract(name, sys.argv[2])
        except KeyError:
            pass
PY
  [ -f "$TMP/xray" ] || { rm -rf "$TMP"; die "安装包内没有 xray 可执行文件（架构可能不匹配）"; }
  install -m 0755 "$TMP/xray" /usr/local/bin/xray
  install -d -m 0755 /usr/local/share/xray
  for data in geoip.dat geosite.dat; do
    if [ -f "$TMP/$data" ]; then
      install -m 0644 "$TMP/$data" "/usr/local/share/xray/$data"
    fi
  done
  rm -rf "$TMP"
fi
/usr/local/bin/xray version 2>/dev/null | head -1 || true

log "5/9 安装面板文件"
for name in app.py console.js console.css delete-dialog.js login.js operations.py fallback_policy.py; do
  install -m 0640 "$SRC_DIR/files/$name" "/opt/node-admin/$name"
done
install -m 0644 "$SRC_DIR/scripts/upstream_fallback.py" /usr/local/lib/relay-dns-fallback/upstream_fallback.py
chown -R root:root /opt/node-admin

log "6/9 生成证书与登录凭据"
if [ ! -f /etc/node-admin/cert.pem ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 900 \
    -keyout /etc/node-admin/key.pem -out /etc/node-admin/cert.pem \
    -subj "/CN=$HOST_IP" -addext "subjectAltName=IP:$HOST_IP" 2>/dev/null || \
  openssl req -x509 -newkey rsa:2048 -nodes -days 900 \
    -keyout /etc/node-admin/key.pem -out /etc/node-admin/cert.pem \
    -subj "/CN=$HOST_IP" 2>/dev/null
  chmod 0600 /etc/node-admin/key.pem; chmod 0644 /etc/node-admin/cert.pem
  log "已生成自签证书 CN=$HOST_IP"
else
  log "证书已存在，保留"
fi
if [ ! -f /etc/node-admin/admin.json ]; then
  ADMIN_PASSWORD="$(python3 "$SRC_DIR/scripts/make-admin.py")"
  log "登录密码: $ADMIN_PASSWORD （请立即保存，后续可在面板内修改）"
else
  ADMIN_PASSWORD=""
  log "admin.json 已存在，保留原密码"
fi

log "7/9 生成 Xray 配置"
if [ ! -f /etc/xray-att-relay/config.json ]; then
  KEYS="$(/usr/local/bin/xray x25519)"
  PRIV="$(printf '%s\n' "$KEYS" | sed -n 's/^[Pp]rivate[Kk]ey: *//p' | head -1)"
  [ -n "$PRIV" ] || die "无法从 xray x25519 解析私钥"
  SHORT_ID="$(python3 -c 'import secrets; print(secrets.token_hex(8))')"
  python3 "$SRC_DIR/scripts/make-config.py" --private-key "$PRIV" --short-id "$SHORT_ID" --port "$PANEL_PORT"
  chown root:xray-att-relay /etc/xray-att-relay/config.json
  log "REALITY 已生成（Short ID: $SHORT_ID）"
else
  log "config.json 已存在，保留原配置"
fi
/usr/local/bin/xray run -test -config /etc/xray-att-relay/config.json >/dev/null 2>&1 || die "Xray 配置校验失败"

log "8/9 安装 systemd 服务"
install -m 0644 "$SRC_DIR/systemd/xray-att-relay.service" /etc/systemd/system/xray-att-relay.service
install -m 0644 "$SRC_DIR/systemd/upstream-dns-fallback.service" /etc/systemd/system/upstream-dns-fallback.service
install -d -m 0755 /etc/systemd/system/xray-att-relay.service.d
install -m 0644 "$SRC_DIR/systemd/xray-att-relay.service.d/dns-fallback.conf" /etc/systemd/system/xray-att-relay.service.d/dns-fallback.conf
sed -e "s|__PUBLIC_HOST__|$HOST_IP|" -e "s|__RELAY_LABEL__|$LABEL|" \
  "$SRC_DIR/systemd/node-admin.service.in" > /etc/systemd/system/node-admin.service
chmod 0644 /etc/systemd/system/node-admin.service

cat > /etc/sysctl.d/99-relay.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
EOF
sysctl -p /etc/sysctl.d/99-relay.conf >/dev/null 2>&1 || true

# 放行端口（仅在已启用本机防火墙时，云安全组仍需自行放行）
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then
  ufw allow 8443/tcp >/dev/null 2>&1 || true
  ufw allow 8444/tcp >/dev/null 2>&1 || true
  log "已在本机 ufw 放行 8443/8444"
fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port=8443/tcp >/dev/null 2>&1 || true
  firewall-cmd --permanent --add-port=8444/tcp >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
  log "已在本机 firewalld 放行 8443/8444"
fi
command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null || true)" = "Enforcing" ] && \
  warn "SELinux 处于 Enforcing，若面板或 Xray 报权限错误，请执行 setenforce 0 或添加放行规则"

systemctl daemon-reload
systemctl enable xray-att-relay upstream-dns-fallback node-admin >/dev/null 2>&1
systemctl restart upstream-dns-fallback
systemctl restart xray-att-relay
sleep 2
systemctl restart node-admin
sleep 3

log "9/9 自检"
FAIL=0
for unit in upstream-dns-fallback xray-att-relay node-admin; do
  state="$(systemctl is-active "$unit" 2>/dev/null || true)"
  printf '  %-24s %s\n' "$unit" "$state"
  [ "$state" = active ] || FAIL=1
done
curl -sk -o /dev/null -w "  面板健康检查 %{http_code}\n" "https://127.0.0.1:8444/healthz" || FAIL=1
if command -v ss >/dev/null 2>&1; then
  ss -lntp 2>/dev/null | grep -q ':8443' && echo "  入口 8443 监听正常" || { echo "  入口 8443 未监听"; FAIL=1; }
else
  warn "缺少 ss 命令，跳过端口检查"
fi

echo
echo "=============================================="
echo " 面板地址: https://$HOST_IP:8444"
echo " 登录账号: admin"
[ -n "${ADMIN_PASSWORD:-}" ] && echo " 登录密码: $ADMIN_PASSWORD"
echo " 入口端口: 8443 (VLESS + REALITY)"
echo " 后续步骤: 面板内添加上游节点 -> 创建转发"
echo "=============================================="
[ "$FAIL" = 0 ] || die "自检未全部通过，请查看 journalctl -u node-admin -n 50"
