# Database DDL

The global redemption service uses the `gift_portal` MySQL database. Activation codes are stored in `activation_codes` and are claimed with a conditional update where `used_at IS NULL`.

```sql
CREATE DATABASE IF NOT EXISTS gift_portal
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_0900_ai_ci;

USE gift_portal;

CREATE TABLE IF NOT EXISTS activation_codes (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(64) NOT NULL,
    used_at DATETIME NULL,
    claim_status VARCHAR(16) NOT NULL DEFAULT 'available',
    claim_token CHAR(32) NULL,
    claim_started_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_activation_codes_code (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

| Column | Description |
| --- | --- |
| `id` | Auto-increment primary key. |
| `code` | Activation code. Must be unique. |
| `used_at` | UTC claim time. `NULL` means the code is available. |
| `claim_status` | `available`, `processing`, or `claimed`. |
| `claim_token` | Random token which identifies the request that owns a `processing` reservation. |
| `claim_started_at` | UTC reservation time for operational recovery. |
| `created_at` | Row creation time. |

Global redemption consumes a code with this atomic statement after the account login succeeds:

```sql
UPDATE activation_codes
SET used_at = UTC_TIMESTAMP()
WHERE code = ? AND used_at IS NULL;
```

在调用 SOOP 前，服务先将 `available` 激活码原子更新为 `processing` 并保存随机
`claim_token`。只有持有该 token 的请求可以写入领取记录并更新为 `claimed`。SOOP
领取失败会释放为 `available`；SOOP 成功后数据库确认失败则保持 `processing`，避免
再次请求导致重复领取，须通过运营恢复流程核对后处理。

## Claim records

每次成功兑换写入一条记录，保存领取时间、领取账号、激活码和实际领取的商品名。
领取前仅选择 Drops 库存中 `type` 为 `krafton`、已连接游戏账号且未领取的项目。
商品名称从 `get_drops_list.php` 响应的 `itemName` 获取；其中字面量 Unicode 转义会解码，同次领取多个商品时以英文逗号拼接保存。

```sql
CREATE TABLE IF NOT EXISTS activation_claims (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    activation_code_id BIGINT UNSIGNED NOT NULL,
    activation_code VARCHAR(64) NOT NULL,
    claim_account VARCHAR(255) NOT NULL,
    claim_password TEXT NOT NULL,
    product_name VARCHAR(255) NOT NULL,
    claimed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_activation_claims_code (activation_code_id),
    KEY ix_activation_claims_claimed_at (claimed_at),
    CONSTRAINT fk_activation_claims_code
        FOREIGN KEY (activation_code_id) REFERENCES activation_codes(id)
        ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

| 字段 | 中文含义 |
| --- | --- |
| `id` | 领取记录主键 |
| `activation_code_id` | 激活码表 ID |
| `activation_code` | 激活码文本 |
| `claim_account` | 前台提交的账号名 |
| `claim_password` | 前台提交的账号密码 |
| `product_name` | Drops 库存接口返回的实际领取商品名（`itemName`） |
| `claimed_at` | 领取时间 |

管理端的“领取记录”商品列显示关联 `soop_inventory.product_name`，即录入库存时配置的商品名称。

## Feature configuration

Feature availability is controlled in the same database. The service first looks up the current machine hostname, then falls back to the `default` row. Keep `default` disabled for production and create a development-machine override to enable the two local-only methods.

```sql
CREATE TABLE IF NOT EXISTS portal_feature_config (
    scope VARCHAR(128) NOT NULL PRIMARY KEY,
    steam_enabled TINYINT(1) NOT NULL DEFAULT 0,
    qr_enabled TINYINT(1) NOT NULL DEFAULT 0,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Production fallback: only the global redemption method is enabled.
INSERT INTO portal_feature_config (scope, steam_enabled, qr_enabled)
VALUES ('default', 0, 0)
ON DUPLICATE KEY UPDATE scope = VALUES(scope);

-- Development-machine override. Replace with the actual local hostname.
INSERT INTO portal_feature_config (scope, steam_enabled, qr_enabled)
VALUES ('YOUR-DEVELOPMENT-HOSTNAME', 1, 1)
ON DUPLICATE KEY UPDATE
    steam_enabled = VALUES(steam_enabled),
    qr_enabled = VALUES(qr_enabled);
```

## SOOP inventory accounts

SOOP 礼包领取使用账号级 Cookie。一个账号可以绑定多个礼包商品，多个
`itemCodeIdx` 以英文逗号分隔保存，例如 `111198867,110890557`。

```sql
CREATE TABLE IF NOT EXISTS soop_inventory (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    created_by VARCHAR(128) NOT NULL,
    soop_account_name VARCHAR(128) NOT NULL,
    soop_cookie TEXT NOT NULL,
    product_name VARCHAR(255) NOT NULL,
    item_code_idxs VARCHAR(2048) NOT NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_soop_inventory_account_product (soop_account_name, product_name),
    KEY ix_soop_inventory_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

后台账号使用单独的账号表，密码仅保存 PBKDF2-SHA256 哈希：

```sql
CREATE TABLE IF NOT EXISTS admin_users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_admin_users_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

激活码与库存商品通过中间表关联，激活码表本身不保存商品名称。每个激活码只能
关联一个库存商品；同一库存商品可关联多个激活码：

```sql
CREATE TABLE IF NOT EXISTS activation_code_inventory (
    activation_code_id BIGINT UNSIGNED NOT NULL,
    soop_inventory_id BIGINT UNSIGNED NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (activation_code_id),
    UNIQUE KEY uq_aci_soop_inventory (soop_inventory_id),
    CONSTRAINT fk_aci_activation_code
        FOREIGN KEY (activation_code_id) REFERENCES activation_codes(id)
        ON DELETE CASCADE,
    CONSTRAINT fk_aci_soop_inventory
        FOREIGN KEY (soop_inventory_id) REFERENCES soop_inventory(id)
        ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

示例数据：

```sql
INSERT INTO soop_inventory
    (soop_account_name, soop_cookie, product_name, item_code_idxs)
VALUES
    ('SOOP_ACCOUNT_A', 'COOKIE_HEADER_OR_NAME_VALUE_PAIRS', 'PUBG 补给箱', '111198867,110890557');
```

已有数据库迁移时执行：

```sql
ALTER TABLE activation_codes DROP INDEX uq_activation_codes_order_id;
ALTER TABLE activation_codes DROP COLUMN order_id;
ALTER TABLE activation_codes ADD COLUMN claim_status VARCHAR(16) NOT NULL DEFAULT 'available' AFTER used_at;
ALTER TABLE activation_codes ADD COLUMN claim_token CHAR(32) NULL AFTER claim_status;
ALTER TABLE activation_codes ADD COLUMN claim_started_at DATETIME NULL AFTER claim_token;
UPDATE activation_codes SET claim_status = 'claimed' WHERE used_at IS NOT NULL;
ALTER TABLE activation_claims ADD COLUMN claim_password TEXT NOT NULL AFTER claim_account;
ALTER TABLE activation_claims ADD COLUMN claimed_item_code_idxs VARCHAR(2048) NOT NULL AFTER product_name;
ALTER TABLE activation_claims DROP INDEX uq_activation_claims_code_id;
ALTER TABLE activation_claims ADD UNIQUE KEY uq_activation_claims_code (activation_code_id);
ALTER TABLE activation_code_inventory DROP PRIMARY KEY;
ALTER TABLE activation_code_inventory ADD PRIMARY KEY (activation_code_id);
ALTER TABLE activation_code_inventory ADD UNIQUE KEY uq_aci_soop_inventory (soop_inventory_id);
ALTER TABLE soop_inventory ADD COLUMN created_by VARCHAR(128) NOT NULL AFTER id;
```

按 `itemCodeIdx` 查找待领取账号时，应用层应先拆分逗号值并绑定参数，不能
直接拼接 SQL：

```sql
SELECT id, soop_account_name, soop_cookie, product_name, item_code_idxs
FROM soop_inventory
WHERE enabled = 1
  AND FIND_IN_SET(%s, REPLACE(item_code_idxs, ' ', '')) > 0
LIMIT 1;
```

`soop_cookie` 属于敏感凭据，接口响应和审计日志都不应返回或记录该字段。

领取流程会并发请求每个 `itemCodeIdx`，每个索引独立最多重试 3 次，并等待全部索引完成。
只要至少一个索引成功，就核销激活码，并将全部成功索引以英文逗号保存至同一条
`activation_claims.claimed_item_code_idxs` 记录；全部索引均失败时，激活码不核销。
