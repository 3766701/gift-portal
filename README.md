# DROP//ZONE 礼包兑换演示

前端使用原生 HTML/CSS/JavaScript。全球提货复用 `E:\QQfile\pubg_cookie\pubg_cookie_getter_http.py`，并通过 MySQL 校验、原子核销激活码。

```powershell
cd E:\QQfile\steam_login\gift-portal
python -m pip install -r requirements.txt
python -m playwright install chromium
python server.py
```

浏览器打开 `http://127.0.0.1:8000/gift/`。Steam 演示激活码：`TAECG5XVAQ8XQNQY414`、`DEMO2026DROP001`。数据只保存在当前 Python 进程内。

`/gift` 是唯一可访问的应用路径；未带此前缀的页面和 API 会返回 `404`。接口使用 `/gift/api/...`。

Steam 提货登录只对 Steam 域名使用本机 Mihomo/Clash HTTP 代理 `http://127.0.0.1:7890`，KRAFTON、SOOP 和其他域名直连；Steam 登录入口不执行 KID/Akamai Cookie 初始化，也不启动 Playwright telemetry。全球 KID 登录保持原有独立流程。不读取代理环境变量，也不使用 QG 代理。请先启动本机 Mihomo 并监听该端口。

服务器上的 Mihomo 可通过 `external-controller: 127.0.0.1:9090` 提供节点控制 API；`secret: ''` 表示空密钥，项目会直接访问该 API。启动时项目会读取 `/root/.config/mihomo/config.yaml`（也支持 `$XDG_CONFIG_HOME/mihomo/config.yaml`），获取代理组节点并测速，随后通过 `PUT /proxies/<代理组>` 切换节点。遇到网络错误、403、429 或 Steam 限流时会切换节点并重试，最多 3 次。项目和 Mihomo 必须运行在同一台服务器上，因为 `127.0.0.1` 只指向本机。

全球提货和 Steam 提货会在服务端验证账号密码。账号、密码、Steam令牌和授权令牌不会保存到订单数据或返回给浏览器。Steam 账户需要关联已有 KRAFTON/KID 账号；需要二次验证时页面会要求输入 Steam手机令牌或备用码。

全球账号登录实现已包含在 `global_login/` 目录，部署时无需额外复制 `pubg_cookie_getter_http.py`。默认使用 Playwright 生成 KRAFTON 登录所需的浏览器遥测，因此需要执行 `python -m playwright install chromium`。

后端请求审计日志写入 `gift_portal.log`：激活码、邮箱和账号仅记录脱敏值；密码、授权令牌和完整激活码不会写入日志。

后台“系统日志”仅保存业务失败和未处理错误（`ERROR` 级别），包括 SOOP 库存映射、账号绑定和全球账号登录失败；普通请求、参数校验和可恢复重试不会写入该列表。

全球激活码数据库默认连接 `47.116.48.188:3306/gift_portal`。可用 `GIFT_PORTAL_DB_HOST`、`GIFT_PORTAL_DB_PORT`、`GIFT_PORTAL_DB_USER`、`GIFT_PORTAL_DB_PASSWORD` 和 `GIFT_PORTAL_DB_NAME` 覆盖连接配置。

提货方式由数据库表 `portal_feature_config` 控制，不依赖环境变量。`default` 配置用于生产服务器，默认关闭 Steam 提货和令牌扫码；可为开发机主机名新增一条配置以启用这两项。后端会同步拒绝已关闭的 Steam 提货接口。Steam 提货通过 Steam OAuth 登录关联的 KRAFTON/KID 账号，完成 SOOP 绑定后领取对应库存。

数据库表结构与核销 DDL 见 [docs/database.md](docs/database.md)。

后台位于 `/gift/admin`。先执行数据库 DDL，再创建首个后台账号：

```powershell
python server.py --create-admin admin
```

命令会安全提示输入密码。登录后台后可批量导入 SOOP 库存、记录录入人、生成与库存一对一绑定的激活码，并分页搜索库存状态和领取记录。

库存导入每行一条，使用竖线或 Tab 分隔：

```text
录入人|SOOP账号|商品名称|itemCodeIdx|SOOP Cookie
```
