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

全球提货会在服务端验证账号密码；账号、密码和授权令牌不会保存到订单数据或返回给浏览器。

全球账号登录实现已包含在 `global_login/` 目录，部署时无需额外复制 `pubg_cookie_getter_http.py`。默认使用 Playwright 生成 KRAFTON 登录所需的浏览器遥测，因此需要执行 `python -m playwright install chromium`。

全球激活码数据库默认连接 `47.116.48.188:3306/gift_portal`。可用 `GIFT_PORTAL_DB_HOST`、`GIFT_PORTAL_DB_PORT`、`GIFT_PORTAL_DB_USER`、`GIFT_PORTAL_DB_PASSWORD` 和 `GIFT_PORTAL_DB_NAME` 覆盖连接配置。

默认环境为 `development`，全球提货、Steam 提货和令牌扫码提货均启用。生产环境启动前设置 `GIFT_PORTAL_ENV=production`，页面会禁用 Steam 提货与令牌扫码提货，后端也会拒绝 Steam 提货接口。

数据库表结构与核销 DDL 见 [docs/database.md](docs/database.md)。
