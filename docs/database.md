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
    reward VARCHAR(255) NOT NULL,
    used_at DATETIME NULL,
    order_id VARCHAR(64) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_activation_codes_code (code),
    UNIQUE KEY uq_activation_codes_order_id (order_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

| Column | Description |
| --- | --- |
| `id` | Auto-increment primary key. |
| `code` | Activation code. Must be unique. |
| `reward` | Reward displayed on the order. |
| `used_at` | UTC claim time. `NULL` means the code is available. |
| `order_id` | Unique order ID written when the code is claimed. |
| `created_at` | Row creation time. |

Global redemption consumes a code with this atomic statement after the account login succeeds:

```sql
UPDATE activation_codes
SET used_at = UTC_TIMESTAMP(), order_id = ?
WHERE code = ? AND used_at IS NULL;
```

The code is considered successfully claimed only when the affected row count is `1`.

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
