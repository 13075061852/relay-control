# Relay Control 中转面板

单文件 Python 面板 + Xray（VLESS/REALITY）中转节点的一键安装脚本。在全新的 Debian/Ubuntu 服务器上执行一条命令即可完成部署，安装后通过浏览器管理上游节点、客户转发、流量额度与订阅。

## 环境要求

| 项目 | 要求 |
| --- | --- |
| 系统 | Debian 11/12、Ubuntu 20.04 及以上 |
| 架构 | x86_64 |
| 权限 | root |
| 端口 | 8444 面板（HTTPS）、8443 入口（VLESS）、10085 计费（仅本机） |
| 内存 | 建议 1GB 以上 |

## 安装

```bash
apt-get update && apt-get install -y git
git clone https://github.com/13075061852/relay-control.git
cd relay-control
bash install.sh --host 你的公网IP --label 服务器名称
```

脚本会依次完成：系统检查 → 依赖安装 → 用户与目录 → Xray 下载 → 面板文件 → 自签证书与登录密码 → REALITY 配置 → systemd 服务 → 自检。全部成功后会打印面板地址、管理员密码和自检结果。

安装完成后访问 `https://你的公网IP:8444`，用 `admin` 登录，然后：

1. 在「节点管理」添加上游节点（SOCKS5 / HTTP / VLESS）
2. 用「一键创建节点」按客户批量生成转发
3. 把生成的链接或二维码发给客户

## 参数

| 参数 | 说明 | 默认值 |
| --- | --- | --- |
| `--host` | 公网 IP，写入证书与面板配置 | 自动探测 |
| `--label` | 面板显示名称 | 中转控制台 |
| `--xray-version` | Xray 版本标签 | v26.3.27 |
| 环境变量 `XRAY_VERSION` | 同 `--xray-version` | — |

## 目录结构

```
install.sh                    一键安装脚本
files/                        面板程序（app.py、console.js、console.css 等）
scripts/make-admin.py         生成登录凭据
scripts/make-config.py        生成 Xray 配置
scripts/upstream_fallback.py  DNS 回退传输
systemd/                      三个服务单元
docs/install-guide.md         安装手册（Markdown）
```

## 注意事项

1. **重复执行安全**：脚本会保留已有的证书、`admin.json`、`config.json`，只更新程序文件与 systemd 单元，可用于升级。
2. **防火墙**：需要放行 8443 与 8444；云厂商安全组同样要放行，否则外网打不开。
3. **自签证书**：首次访问浏览器会提示不受信任，选择继续访问即可。
4. **Debian 11 归档源**：脚本会自动把已下架的 `security.debian.org` 换成 `archive.debian.org`，否则 `curl`、`python3-qrcode` 装不上。
5. **二维码依赖**：面板兼容 qrcode 7.1 与 7.3+，两个版本的 API 都已处理，无需手动升级。
6. **数据位置**：`/etc/node-admin`（凭据、状态、会话）、`/etc/xray-att-relay/config.json`（Xray 配置）、`/var/backups/node-admin`（自动备份）。迁移时用面板内的「导出迁移包」。
7. **升级**：重新拉取仓库并执行同一条安装命令即可，程序文件会更新，配置不动。

## 常用排查

```bash
systemctl status node-admin xray-att-relay upstream-dns-fallback
journalctl -u node-admin -n 50 --no-pager
curl -sk https://127.0.0.1:8444/healthz      # 期望输出 ok
/usr/local/bin/xray run -test -config /etc/xray-att-relay/config.json
```
