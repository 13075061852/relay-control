#!/usr/bin/env bash
# Relay Control 中转面板 + Xray 一键安装（Debian 11/12、Ubuntu 20.04+）
# 用法: sudo bash install.sh --host <公网IP> [--label 名称] [--xray-version v26.3.27]
set -Eeu
set -o pipefail
shopt -s lastpipe 2>/dev/null || true

HOST_IP=""
LABEL="中转控制台"
XRAY_VERSION="${XRAY_VERSION:-v26.3.27}"
PANEL_PORT=8443
CONFIG_PORT=8443
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST_IP="${2:-}"; shift 2 ;;
    --label) LABEL="${2:-}"; shift 2 ;;
    --xray-version) XRAY_VERSION="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,3p' "$0"; exit 0 ;;
    *) echo "未知参数: $1"; exit 1 ;;
  esac
done

log() { printf '\033[1;34m[install]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "请使用 root 运行"
[ -f "$SRC_DIR/files/app.py" ] || die "缺少 files/ 目录，请在仓库根目录执行"

log "1/9 检查系统"
. /etc/os-release 2>/dev/null || die "无法识别系统版本"
log "系统: $PRETTY_NAME"

# Debian 11 已停止维护，官方 security 源已下架；改为归档源，否则装不上 curl/qrcode
if [ "${VERSION_ID:-}" = "11" ] && grep -qs 'security.debian.org/debian-security bullseye-security' /etc/apt/sources.list; then
  log "检测到 Debian 11，切换归档源"
  cp -a /etc/apt/sources.list "/etc/apt/sources.list.bak.$(date +%s)"
  sed -i 's|http://security.debian.org/debian-security|http://archive.debian.org/debian-security|' /etc/apt/sources.list
  sed -i 's|http://ftp.debian.org/debian|http://archive.debian.org/debian|' /etc/apt/sources.list
  echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-valid-until
fi

log "2/9 安装依赖 (curl / ca-certificates / python3-qrcode)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq || log "apt update 返回非零，继续尝试安装"
apt-get install -y -qq curl ca-certificates python3-qrcode >/dev/null
python3 - <<'PY' || die "python3 qrcode 模块不可用"
import qrcode, qrcode.image.svg
PY
command -v curl >/dev/null || die "curl 安装失败"

if [ -z "$HOST_IP" ]; then
  HOST_IP="$(curl -4 -fsS --max-time 8 https://api.ipify.org || true)"
  [ -n "$HOST_IP" ] || die "无法自动识别公网 IP，请用 --host 指定"
  log "自动识别公网 IP: $HOST_IP"
fi

log "3/9 创建用户与目录"
getent group xray-att-relay >/dev/null || groupadd -r xray-att-relay
id -u xray-att-relay >/dev/null 2>&1 || useradd -r -g xray-att-relay -d /nonexistent -s /usr/sbin/nologin xray-att-relay
install -d -m 0700 /etc/node-admin /var/backups/node-admin /var/log/node-admin
install -d -m 0700 /etc/fastclient-subscription /etc/att-subscription
install -d -m 0755 /usr/local/lib/relay-dns-fallback /opt/node-admin
install -d -m 0750 -o root -g xray-att-relay /etc/xray-att-relay
chmod 2750 /etc/xray-att-relay

log "4/9 安装 Xray $XRAY_VERSION"
if [ -x /usr/local/bin/xray ]; then
  log "已存在 $(/usr/local/bin/xray version 2>/dev/null | head -1 || true)，跳过下载"
else
  TMP="$(mktemp -d)"
  URL="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip"
  curl -fL --retry 3 --connect-timeout 15 -o "$TMP/xray.zip" "$URL" || die "Xray 下载失败: $URL"
  python3 - "$TMP/xray.zip" "$TMP" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as zf:
    for name in ('xray', 'geoip.dat', 'geosite.dat'):
        try:
            zf.extract(name, sys.argv[2])
        except KeyError:
            pass
PY
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
    -subj "/CN=$HOST_IP" -addext "subjectAltName=IP:$HOST_IP" 2>/dev/null
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
[ -x /usr/local/bin/xray ] || die "Xray 未安装"

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
ss -lntp 2>/dev/null | grep -q ':8443' && echo "  入口 8443 监听正常" || { echo "  入口 8443 未监听"; FAIL=1; }

echo
echo "=============================================="
echo " 面板地址: https://$HOST_IP:8444"
echo " 登录账号: admin"
[ -n "${ADMIN_PASSWORD:-}" ] && echo " 登录密码: $ADMIN_PASSWORD"
echo " 入口端口: 8443 (VLESS + REALITY)"
echo " 后续步骤: 面板内添加上游节点 -> 创建转发"
echo "=============================================="
[ "$FAIL" = 0 ] || die "自检未全部通过，请查看 journalctl -u node-admin -n 50"
