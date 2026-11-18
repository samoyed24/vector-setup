# Vector 代理日志一键接入

一个入口，支持独立 Xray、3x-ui、3x-ui Shadow、S-UI 内嵌 sing-box，以及实际启用的 Nginx `cfws` WebSocket 日志。包含探测、安装、已有配置接管、备份、校验、回滚和 SSH 接收端白名单接入。

已修复并接管：`aws-hk`、`dedirock-us-la`、`oci-sg-west`。未修改 `gc-jp`、`aws-tw` 的配置。

## 快速使用

从管理电脑直接运行。已有 Vector 时可以先用 `plan` 查看变更：

```sh
curl -fsSL https://raw.githubusercontent.com/samoyed24/vector-setup/main/bootstrap.sh | bash -s -- plan --ssh aws-hk
```

把服务器通过 SSH 接入现有 Loki 时，将 `NEW_SERVER` 替换为目标机别名：

```sh
curl -fsSL https://raw.githubusercontent.com/samoyed24/vector-setup/main/bootstrap.sh | bash -s -- deploy --ssh NEW_SERVER --receiver oci-sg-west
```

直接在服务器上安装时，传入本机已有的 Loki 写入凭据文件：

```sh
curl -fsSL https://raw.githubusercontent.com/samoyed24/vector-setup/main/bootstrap.sh | sudo bash -s -- install --host my-node --credentials-file /root/loki-push.env
```

入口需要 Bash、curl 和 tar，脚本运行还需要下文列出的 Python 版本。命令默认下载 `main`，可在 `bash` 前设置 `VECTOR_SETUP_REF` 为固定提交或版本标签。也可用 `git clone https://github.com/samoyed24/vector-setup.git` 下载后执行下面的命令。已克隆时用 `git pull --ff-only` 更新。

```sh
# 只看识别结果和预期变更
./vector-setup.sh inspect --ssh aws-hk
./vector-setup.sh plan --ssh aws-hk

# 新服务器：自动选择包架构、安装 Vector、生成配置、接入现有 Loki
# 把 NEW_SERVER 换成真实 SSH 别名
./vector-setup.sh deploy --ssh NEW_SERVER \
  --receiver oci-sg-west

# 首次接管其他已安装 Vector 的机器：明确加上此选项
./vector-setup.sh deploy --ssh gc-jp \
  --receiver oci-sg-west --adopt-existing

# 这次已接管的三台以后直接重复运行，无变化不重启
./vector-setup.sh deploy --ssh aws-hk --receiver oci-sg-west

# 解析测试、Loki 健康检查，以及接收端近期事件查询
./vector-setup.sh verify --ssh aws-hk --receiver oci-sg-west

# 恢复上一次由本工具应用的配置与服务状态
./vector-setup.sh rollback --ssh aws-hk
```

脚本不是自动给所有现有机器批量改配置。每次只操作指定目标；`inspect`、`plan`、`check`、`verify` 不替换生效配置。SSH 模式会上传包到临时目录，操作结束清理。

默认复用目标机已有凭据。指定 `--receiver` 后，工具通过现有 SSH 认证安全读取接收端的专用 Loki 写入凭据，传到目标机的临时受限文件中，不打印凭据，不在参数中传密码。接收端 SSH 私钥留在管理电脑。

`deploy --receiver` 会从采集机发出一次带随机标记的 HTTPS 健康检查请求，再从接收端 Nginx 的 Loki 访问日志中识别它看到的源地址。探测不发送 Loki 凭据，接收端只放行该单个地址。如果使用了自定义日志格式、代理网络或多个出口，必要时用 `--egress-ip` 显式指定地址。

## 服务器本机安装

Debian / Ubuntu 使用 systemd。Alpine 使用 OpenRC 与 [Vector 官方 musl 构建](https://vector.dev/docs/setup/installation/manual/from-archives/)，从独立文件采集日志。若 Alpine 的代理只写标准输出，先在代理配置中指定日志文件。脚本可以从运行配置识别日志路径，也可用 `--log-file /绝对路径/access.log` 指定路径。Alpine 每日清理任务由运行中的 `crond` 执行。

目标机需要 Python 3.11+ 与 CA 证书。Alpine 精简系统本机执行时可先以 root 运行 `apk add python3 bash curl ca-certificates`。SSH 部署只在目标机调用 Python，Bash 入口在管理电脑上运行。

把整个包复制到服务器，准备仅 root 可读的凭据文件：

```text
LOKI_PUSH_USER="你的写入用户名"
LOKI_PUSH_PASSWORD="你的写入密码"
```

```sh
chmod 600 /root/loki-push.env
sudo ./vector-setup.sh install --host my-node \
  --credentials-file /root/loki-push.env
```

本机安装可沿用接收端已有授权，也可从管理电脑使用 `deploy --receiver` 自动完成放行。

## 自动识别及覆盖

- 从实际代理进程的配置参数、工作目录和配置分片发现日志与入站，不只猜固定路径。
- 识别 `x-ui.service`、`x-ui-shadow.service`、`xray.service`、`sing-box.service`、`s-ui.service`。
- S-UI 从只读 SQLite 连接读取入站配置；不会读取用户表或改面板数据。
- Nginx 简单 TCP 转发、SNI map 自动映射公网端口，例如 443 → 18443、8443 → 18444。
- Xray 支持 `>>` / `->`、可选 email、IPv4/IPv6；成功的 REALITY 入站不误判为握手失败。
- S-UI/sing-box 保留 from、to、outbound 的分拆事件及 connection_id，不伪造完整会话。缺少入站的 outbound 端口为 `unknown`。
- 文件是访问日志主来源时，journal 中重复的 accepted/rejected 不再重复采集；journal 限定到对应服务。
- 面板内部 api 入站被排除。无法解析的 accepted 格式保留 raw，标记 `parse_error` / `unparsed`，而非静默输出空字段的“成功”事件。
- 保留 Loki 标签 `job/host/proxy_port/event/result/kind`；JSON 正文新增 `listen_port`、`connection_id`、`parse_status`。

可以覆盖复杂端口关系：

```sh
./vector-setup.sh plan --ssh my-node --port-map vmess-cf=8443
./vector-setup.sh deploy --ssh my-node --receiver oci-sg-west \
  --port-map vmess-cf=8443 --adopt-existing
```

首次本机运行必须明确 `--host`；SSH 模式默认使用别名，避免不同云主机系统 hostname 不稳定。已托管本机可从管理清单读取标签。

## 备份、状态与保留

- 应用前备份至 `/var/backups/vector-setup/<UTC时间>/`，包括配置、凭据、unit、权限和服务状态。
- 原子替换；失败恢复本次备份；不会重启 Xray、S-UI 或 3x-ui。
- 保留 `/var/lib/vector`，不清空文件断点、journal cursor、磁盘缓冲；保留原有 source ID。
- 已有配置只接管本工具认识的组件。未知自定义 source/transform/sink、特殊配置路径、重复入站 tag 或歧义路由会拒绝应用，需要手工合并。
- `/etc/vector/vector-setup.json` 记录版本、配置散列、入站映射和上一次备份。
- `vector-proxy-retention.timer` 每日清理 `/var/log/proxy-events-YYYY-MM-DD.jsonl*` 中超过七天未修改的副本；不清理代理原始日志，不重复配置其 logrotate。
- 如果有 `/opt/log-pipeline/vector.toml`，必须先与生效配置一致；随后同步维护，并纳入备份。避免旧部署源覆盖生效配置。
- `rollback` 恢复配置和服务状态，不卸载新装的 Vector 包，不回滚日志偏移。手动回滚采集器不自动撤销接收端已存在的 IP 授权。

## 接收端约定

当前支持已有的 OCI 接收端布局：

```text
/etc/nginx/conf.d/loki-portcloud-online.conf
/opt/log-pipeline/nginx-loki.conf
http://127.0.0.1:3100
```

只向 `/ready` 和 `/loki/api/v1/push` 添加单个明确 IP，保留 Basic Auth；不开放查询 API 或 Grafana。接收端操作加锁、备份、`nginx -t` 后 reload。若部署源和生效文件不同则停止，避免覆盖未知改动。

若采集端应用失败，控制器只撤销本次新增、带工具标记的 allow 行；不会删除原先就有的授权。

## 支持范围和测试

- 管理电脑：Bash、Python 3.9+、SSH 配置与认证已就绪。
- 目标机：Debian / Ubuntu（systemd）或 Alpine（OpenRC），amd64 / arm64，Python 3.11+，root 或无交互 sudo。Alpine 上运行中的第三方 Vector 服务需先手工迁移。
- Vector：保留现有 0.50.0；其他版本不自动升级或降级。新装下载官方 0.50.0 的 amd64/arm64 包并校验固定 SHA-256。Alpine 使用 musl 压缩包。安装失败不会忽略错误继续启用。
- 新装需要能访问官方包下载地址；`dpkg` 如报告系统依赖缺失，需先修复依赖再重试。
- 不自动开启/修改 Nginx stream access log，不把普通 HTTP combined 日志当 WebSocket 日志；这两类需要额外适配。
- 相同 tag 的多个代理实例暂不合并，避免端口映射错误；需先明确区分 tag 或手工合并。
- 收到数据和字段正确分开核对。`verify --receiver` 查询近十分钟事件，不等于一定产生了本次部署后的新业务请求；无流量时显示 `waiting_for_events`。

本次验证：三台实际接管、解析测试及 Loki 健康检查；真实香港/美国 VLESS 请求及接收字段比对；重复部署不重启；Nginx cfws 通过独立合成日志测试。新版已在 Debian 13、Ubuntu 24.04 现有主机通过解析和 Loki 健康检查，也在 Alpine 3.23 arm64 容器通过全新安装、OpenRC 启动、重复运行和回滚。

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

## 文件

- `vector-setup.sh`：统一入口。
- `cli.py`：本机/SSH 协调，安全传递凭据，接收端授权。
- `agent.py`：检测、配置生成、验证、安装、接管和回滚。
- `templates/`：共享 VRL 解析规则。
- `tests/`：下载完整性、配置备份恢复、特殊字符、端口映射等单元测试。

包不含服务器密码、Loki 凭据或节点配置。GitHub 仓库是后续更新的来源。
