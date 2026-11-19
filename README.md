# 多租户数据集服务（Multi-Tenant Dataset Service）

支持 **行级租户隔离、列级敏感字段权限、临时授权与撤销** 的数据集服务。
权限变更通过单调递增的**授权版本**级联影响查询、导出、查询缓存与物化结果；
所有访问判定（含越权）均落审计，可凭 `request_id` 追溯命中规则与当时版本。

## 能力总览

| 需求 | 实现 |
| --- | --- |
| 行级租户隔离 | 行策略 `row_scope = tenant/all/custom`，按行 `tenant_id` 与谓词过滤；`deny` 覆盖 `allow` |
| 列级敏感字段权限 | 列定义 `sensitive` + 默认脱敏（redact/hash）；列策略/临时授权控制明文，`deny` 优先 |
| 临时授权 | 带 `ttl_seconds` 与 `expires_at`，到期自动清扫；可手动撤销 |
| 授权撤销 | 撤销立即推进权限版本并级联失效 |
| 影响查询 | 每次查询按当前版本重算有效权限，返回命中规则 |
| 影响导出 | 版本变更后导出按数据集策略 `invalidate`（失效，下载 410）或 `retain_audit`（保留审计、禁止下载） |
| 影响缓存 | 缓存 key 内含 `auth_version`；版本推进物理删除旧条目；缓存 TTL 被授权到期时间截断 |
| 影响物化 | 版本推进把物化结果标记 `stale`，下次读取按请求人当前权限重算 |
| 越权可追溯 | 每次 allow/deny 写 `audit_logs`，含 request_id、命中规则、权限版本、原因 |
| 页面展示 | `/console/` 展示授权版本、命中规则、导出状态、缓存/物化状态、审计记录 |
| 并发验证 | 读写锁 + 版本守卫；测试覆盖服务层多线程与真实 uvicorn HTTP 层并发 |

## 架构

```
app/
├── main.py                # FastAPI 应用、异常处理
├── locks.py               # 进程内读写锁（读并发 / 写独占）
├── models.py              # ORM：租户/用户/数据集/策略/临时授权/版本/审计/导出/缓存/物化
├── schemas.py             # Pydantic 请求模型
├── deps.py                # X-User-Id 请求头鉴权
├── services/
│   ├── permissions.py     # 权限引擎：有效权限、行判定、列投影、命中规则
│   ├── auth_service.py    # 策略/临时授权/撤销/过期清扫 → 版本推进 → 级联失效
│   ├── data_service.py    # 查询/缓存/导出/物化（全部经权限引擎 + 审计）
│   └── audit.py           # 审计落库
├── routers/
│   ├── admin.py           # 管理端：租户/用户/数据集/策略/临时授权
│   ├── data.py            # 数据端：查询/导出/下载/物化
│   └── console.py         # 控制台 API + 页面
└── static/console.html    # 控制台页面（原生 JS，无构建）
```

### 权限版本与级联失效

每个数据集维护单调递增的 `auth_version`。任何权限变更（策略增删、临时授权、撤销、过期）
在**写锁**内执行 `_bump_version`：

1. `auth_version += 1`，写一条 `auth_versions` 流水（含变更类型与级联处置统计）；
2. 删除该数据集全部 `query_cache` 条目；
3. `materialized_results` 标记 `stale`；
4. `ready` 状态的导出按 `export_policy` 变为 `invalidated` 或 `retained_audit`。

读路径整体处于**读锁临界区**，进入后 `expire_all()` 重读当前版本；
临界区内不可能有写者插入，因此缓存写入的版本恒等于当前版本，杜绝旧版本缓存残留。
缓存 key = `sha256(user_id, dataset_id, auth_version, filters)`，版本变更后旧 key 天然不可命中。

### 权限合并规则（`services/permissions.py`）

- 行级：先判所有 `deny`（all/tenant/custom 谓词），再按 `all > tenant > custom` 取 allow 范围；
- 列级：`deny` 列强制脱敏；非敏感列默认可见；敏感列需显式 allow（策略或未过期临时授权）才可见，否则按列默认方式脱敏；
- 临时授权过期或撤销后不产生任何权限，且其 TTL 会截断缓存有效期。

## 快速开始

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

.venv/bin/python seed.py                 # 初始化演示库（两租户、admin/alice/bob、orders 数据集）
.venv/bin/uvicorn app.main:app --port 8000
# 控制台： http://127.0.0.1:8000/console/   （请求头 X-User-Id: 1 为管理员）
# OpenAPI：http://127.0.0.1:8000/docs
```

演示身份（seed 固定 ID）：`1=admin`，`2=alice(租户 acme)`，`3=bob(租户 beta)`，所有请求带头 `X-User-Id: <id>`。

### 典型流程

```bash
# alice 只能看本租户行，mobile/salary 脱敏
curl -s -X POST localhost:8000/api/datasets/1/query -H 'X-User-Id: 2' -d '{}'

# 管理员临时授予 alice mobile 明文 10 分钟
curl -s -X POST localhost:8000/admin/datasets/1/temp-grants -H 'X-User-Id: 1' \
  -H 'Content-Type: application/json' \
  -d '{"user_id":2,"scope":"column","columns":["mobile"],"ttl_seconds":600,"reason":"客服工单"}'

# 撤销（版本立即推进，缓存/导出/物化级联失效）
curl -s -X POST localhost:8000/admin/datasets/1/temp-grants/1/revoke -H 'X-User-Id: 1' -d '{}'

# 查越权审计
curl -s 'localhost:8000/console/audit?decision=deny' -H 'X-User-Id: 1'
```

## 测试

```bash
.venv/bin/python -m pytest tests/ -q
```

22 个用例，覆盖：

- `test_row_column_security.py`：行隔离、列脱敏、deny 覆盖、越权 403 与审计、过滤；
- `test_grants.py`：临时列授权/撤销/过期、行授权、deny 压过临时授权、入参校验、管理员鉴权；
- `test_cache_invalidation.py`：缓存命中、版本变更清缓存、TTL 受授权到期截断、版本不串；
- `test_exports_materialized.py`：导出失效/保留审计、下载鉴权、物化 stale 重算、敏感列聚合拒绝；
- `test_concurrency.py`：服务层多线程并发授权/撤销/查询（版本单调无丢失、无旧版本缓存残留、
  结果与版本自洽）与真实 uvicorn + httpx HTTP 层并发（无 5xx、无半变更状态）。

## 设计边界（演示实现）

- 鉴权用 `X-User-Id` 请求头模拟，生产应替换为 JWT/会话；
- 单进程读写锁 + SQLite；多实例部署需把锁与版本推进下沉到数据库事务/分布式锁；
- custom 谓词支持 `== != > >= < <= in not in`，不含任意表达式求值；
- 导出为 JSONL 落本地目录，失效后文件保留用于审计但禁止下载。
