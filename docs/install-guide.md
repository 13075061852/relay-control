# Relay Control 安装手册

中转面板 + Xray（VLESS / REALITY）一键部署 · v1.0 · 适用 Debian 11/12、Ubuntu 20.04+ · x86_64

## 1. 环境要求

| 项目 | 要求 |
| --- | --- |
| 操作系统 | Debian 11/12/13、Ubuntu 20.04+、RHEL/CentOS 8+、Rocky/Alma/Fedora、openSUSE（**必须 systemd**） |
| 架构 | x86_64、aarch64/arm64、armv7、armv6、i686、loongarch64、riscv64、s390x、ppc64le、mips 系列 |
| 权限 | root |
| 端口 | 8444 面板 HTTPS、8443 入口 VLESS、10085 计费（仅本机） |
| 资源 | 建议 1 核 1GB 内存以上，磁盘 5GB 可用 |
| 网络 | 能直连 github.com（下载 Xray）与软件源 |

不支持：无 systemd 的系统（Alpine/OpenRC、WSL1、容器内无 init）。

## 2. 安装来源

```
https://github.com/13075061852/relay-control
```

服务器上只需要 git 与网络，其余依赖由脚本自动安装。

## 3. 安装步骤

步骤 1：登录服务器并安装 git

```bash
apt-get update && apt-get install -y git
```

步骤 2：拉取安装包

```bash
git clone https://github.com/13075061852/relay-control.git
cd relay-control
```

步骤 3：先做环境预检（只读，不改任何东西）

```bash
bash install.sh --dry-run
```

输出会告诉你：系统版本、CPU 架构、对应的 Xray 包名、包管理器、systemd 版本。有一条不符合就直接换机器，不要硬上。

步骤 4：执行一键安装（替换为你的公网 IP 和名称）

```bash
bash install.sh --host 203.0.113.10 --label 香港节点
```

脚本依次完成 9 个阶段，每个阶段结束打印该阶段用时：

1. 系统检查：识别发行版、CPU 架构与包管理器；Debian 11 自动切换到归档源
2. 依赖安装：curl、ca-certificates、python3、openssl；二维码依赖优先用发行版包，失败自动 pip 兜底
3. 用户与目录：xray-att-relay 系统用户、/etc/node-admin、/opt/node-admin
4. Xray 下载：按架构选对应包，校验官方 SHA256 后安装到 /usr/local/bin/xray
5. 面板文件：复制到 /opt/node-admin
6. 证书与凭据：自签证书（含 IP SAN）与随机管理员密码
7. Xray 配置：生成 REALITY 密钥、Short ID、计费 API
8. systemd：xray-att-relay、upstream-dns-fallback、node-admin 三个服务
9. 自检：服务状态、面板健康检查、8443 监听

安装结束会给出两段输出：给人看的摘要，和给程序/Agent 用的机器可读块：

```
----- 机器可读摘要 -----
PANEL_URL=https://203.0.113.10:8444
ADMIN_USER=admin
ADMIN_PASSWORD=xxxxxxxxxxxxxxxxxx
ENTRY_PORT=8443
RELAY_LABEL=香港节点
CREDENTIALS_FILE=/root/node-admin-credentials.txt
INSTALL_SECONDS=23
STATUS=ok
```

同一份凭据会写入 `/root/node-admin-credentials.txt`（600 权限），密码丢了不用重装即可查看。

```
面板地址: https://203.0.113.10:8444
登录账号: admin
登录密码: 随机 18 位（仅首次安装显示）
入口端口: 8443 (VLESS + REALITY)
```

## 4. 参数说明

| 参数 | 作用 | 默认值 |
| --- | --- | --- |
| `--host` | 公网 IP，写入证书 SAN 与面板配置 | 自动探测 |
| `--label` | 面板左上角显示名称，建议「地区 + 序号」 | 中转控制台 |
| `--xray-version` | 指定 Xray Release 标签 | v26.3.27 |
| `--dry-run` | 只检测环境并打印计划，不做任何修改（排查兼容性用） | 关闭 |

## 5. 安装后配置

访问 `https://公网IP:8444`，浏览器提示证书不受信任时选择继续访问，用 admin 登录：

1. 节点管理 → 添加上游节点（SOCKS5 / HTTP / VLESS REALITY），填写地址、端口、账号密码与客户有效期
2. 用「一键检测」确认延迟、测速与出口 IP 正常
3. 一键创建节点：选择客户与协议（默认 VLESS + HTTPS），批量生成转发与订阅
4. 在转发列表点客户名可查看该客户全部转发，二维码与链接可直接发给客户

迁移旧服务器：旧面板「导出迁移包」→ 新面板「导入迁移包」，节点、客户、额度、用量、到期时间全部带入。

## 6. 安装速度

脚本做了四项优化，全新机器通常 20–40 秒完成（实测快速网络环境 6 秒）：

- **并行预下载**：Xray 安装包与依赖安装在后台同时进行，不再串行等两次网络
- **跳过重复索引**：apt 索引在 30 分钟内则跳过 update；装包失败会自动补一次 update 再重试
- **轮询代替固定等待**：服务就绪与面板健康检查用轮询，正常 1–2 秒即通过，不再固定 sleep 5 秒
- **精简安装**：`--no-install-recommends`，不装无关推荐包

## 7. 注意事项

- 云厂商安全组必须放行 8443 和 8444；脚本会顺手在已启用的 ufw / firewalld 上放行，但安全组只能在云控制台改。
- 发行版、架构自动识别，无需手改脚本；ARM 机器会自动下载 arm64 包，不会出现“架构不匹配”。
- RHEL 系如果 SELinux 为 Enforcing，脚本会提示；面板或 Xray 报权限错误时执行 setenforce 0 或加放行规则。
- 面板使用自签证书，浏览器提示「不安全」属正常现象，不影响功能。
- 重复执行安装脚本是安全的：证书、admin.json、config.json 不会被覆盖，可当作升级命令。
- Debian 11 已停止维护，脚本会自动把 security.debian.org 改为 archive.debian.org，否则依赖装不上。
- 二维码功能兼容 qrcode 7.1 与 7.3+ 两种 API，无需手动升级 python 库。
- 数据集中在 /etc/node-admin（凭据、状态、会话）与 /etc/xray-att-relay/config.json；迁移优先用面板导出迁移包。
- 密码记录在 /root/node-admin-credentials.txt；彻底丢失时删除 /etc/node-admin/admin.json 后重跑脚本会重新生成。

## 8. 故障排查

```bash
systemctl status node-admin xray-att-relay upstream-dns-fallback
journalctl -u node-admin -n 50 --no-pager
curl -sk https://127.0.0.1:8444/healthz
/usr/local/bin/xray run -test -config /etc/xray-att-relay/config.json
```

| 现象 | 原因与处理 |
| --- | --- |
| 面板打不开 | 安全组未放行 8444，或 node-admin 未启动，查看 journalctl |
| 证书提示不安全 | 自签证书的正常现象，选择继续访问 |
| 二维码无法显示 | 旧版 qrcode 兼容问题，确认使用最新 app.py，并在日志中搜索 to_string |
| 入口无法连接 | 8443 未放行，或 xray-att-relay 启动失败，先做配置语法校验 |
| 依赖安装 404 | Debian 11 归档源问题，确认脚本已改写 sources.list |
| 提示不是 systemd | Alpine/OpenRC、WSL1 或纯容器环境，换 Debian/Ubuntu/RHEL 系 |
| Xray 下载失败 | 机器无法访问 github.com，先修网络或换源，脚本不会用第三方镜像 |
| 校验和不匹配 | 下载被中间人篡改或代理返回错误页，重跑或换网络 |
| 架构不支持 | uname -m 不在支持列表，换 x86_64/arm64 机器 |
| 端口被占用 | 8443/8444 已被其他程序占用，装前会直接报错退出 |
| 能连但打不开网页 | 上游节点异常，在节点管理用「一键检测」确认出口 IP |

## 9. 交付验收清单

- [ ] 三个服务均为 active 且 enabled（开机自启）
- [ ] `curl -sk https://127.0.0.1:8444/healthz` 返回 ok
- [ ] 浏览器能打开面板并登录成功
- [ ] 8443 可从外网连接
- [ ] 添加上游节点后「一键检测」能得到延迟、速度与出口 IP
- [ ] 创建一条转发，二维码与链接均正常显示

## 10. 交给 AI 执行时的硬要求

把本手册和仓库地址一起交给 AI，并明确以下四条，可避免绝大多数装歪的情况：

- 先跑 `bash install.sh --dry-run`，把系统、架构、包管理器、systemd 四项结果贴出来再继续
- 预检不满足时停下来说明原因，不许自行换方案、不许改装别的代理软件
- `--host` 必须显式传真实公网 IP，不要依赖自动探测（NAT 云主机可能探测到内网地址）
- 安装完成后逐条执行第 9 节验收清单，并按「机器可读摘要」原样回报 `PANEL_URL`、`ADMIN_USER`、`ADMIN_PASSWORD`、`ENTRY_PORT`、`STATUS`
- 失败时贴原始报错并停止，同一命令最多重试 2 次；脚本失败时会自动附上两个服务的 journal 尾部
