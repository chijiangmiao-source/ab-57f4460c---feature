# 浮标失联应急采样 · 受限委托链核验岸站

海洋观测浮标失联时，岸站携带**离线签发的受限委托链**下发应急采样命令。本服务对
值班员粘贴的「根公钥 + 按顺序排列的委托 / 末端命令」按**同一套规范 JSON 字节**
（JCS，RFC 8785）逐跳验签，确认每跳委托由前一主体签发，且时间窗、浮标集合、
采样上限只允许收紧；对有效链展示逐跳证据与最终准许结论，对违规链给出可定位的拒绝原因。

## 快速开始

### Docker Compose（推荐）

```bash
# 启动静态页面与健康端点（宿主机端口可配置，默认 8080）
docker compose up -d gateway
GATEWAY_PORT=9090 docker compose up -d gateway   # 自定义宿主机端口

curl http://127.0.0.1:8080/health          # {"status":"ok",...}
open  http://127.0.0.1:8080/               # 值班员页面

# 一次性验收服务（名为 verify）：复核证据/拒绝、跑测试、页面检查、健康冒烟，
# 执行完毕即退出，退出码即验收结果
docker compose run --rm verify; echo "exit=$?"
```

### 本机（Node ≥ 20，零第三方依赖）

```bash
npm start                 # 启动网关（PORT 环境变量可改端口，默认 8080）
npm test                  # 相关代码测试
npm run check:page        # 页面构建检查
./bin/verify              # 一次性验收服务（退出码报告结果）
```

## 链对象格式（每份均为规范 JSON，键按 JCS 顺序）

```json
{"aud":["buoy-01"],"exp":1790003600,"iss":{"crv":"P-256","kty":"EC","x":"…","y":"…"},"maxSamples":50,"nbf":1789996400,"sig":"…","sub":{"crv":"P-256","kty":"EC","x":"…","y":"…"},"typ":"delegation"}
```

| 字段 | 含义 |
| --- | --- |
| `iss` / `sub` | 签发者 / 主体的 P-256 JWK（`crv,kty,x,y`，base64url 无填充） |
| `nbf` / `exp` | 有效期（unix 秒，int32 区间整数，nbf < exp） |
| `aud` | 允许浮标集合（非空字符串数组，元素唯一） |
| `maxSamples` | 采样上限（int32 区间整数，≥0） |
| `sig` | 对「去掉 `sig` 后的规范 JSON 字节」的 ECDSA P-256/SHA-256 签名（P1363 `r‖s`，base64url 无填充） |
| `typ` | `delegation`（委托）或 `command`（末端命令，仅允许在链末） |
| `buoy` / `samples` | 仅末端命令：目标浮标 / 请求采样量（≥1） |

## 链规则

1. 链首 `iss` 必须等于所粘贴的根公钥；其后每跳 `iss` 必须等于上一跳 `sub`；
2. 每跳仅允许收紧：`nbf` 不提前、`exp` 不延后、`aud` 为上一跳子集、`maxSamples` 不大于上一跳；
3. 评估时刻须落在每跳时间窗内；
4. 末端 `buoy` 须获**全部**上游 `aud` 允许，`samples` 不超过**任一** `maxSamples`；
5. 任一失败即拒绝，并定位**首个限制字段或签名失败跳**。

## 错误定位（`hop` = 跳号，`-1` = 根公钥；附行/列）

| code | 含义 |
| --- | --- |
| `DUPLICATE_KEY` | 重复键 |
| `KEY_ORDER` | 对象键序不规范（未按 JCS 排序） |
| `NUMBER_NON_FINITE` | 非有限数（如 `1e999`） |
| `NUMBER_UNSAFE_INTEGER` | 不安全整数（超出 ±(2^53−1)，精度丢失） |
| `NUMBER_OUT_OF_RANGE` | 越界整数（超出字段允许区间） |
| `NUMBER_NOT_INTEGER` | 整数字段出现小数/指数 |
| `ISSUER_NOT_ROOT` | 链首签发者 ≠ 根公钥 |
| `ISSUER_MISMATCH` | 委托并非前一主体签发 |
| `NOT_TIGHTENED` | 时间窗/浮标集合/采样上限被放宽（`field` 指出首个违规字段） |
| `TIME_NOT_YET_VALID` / `TIME_EXPIRED` | 未生效 / 已过期 |
| `BAD_SIGNATURE` | 签名与规范载荷摘要不符（内容或签名被改写） |
| `BUOY_NOT_ALLOWED` | 末端浮标未获某上游允许（定位首个限制跳） |
| `SAMPLES_EXCEEDED` | 采样量超过某跳上限（定位首个限制跳） |
| `SCHEMA` / `JSON_SYNTAX` / `JSON_TRAILING` | 模式或语法错误 |

## API

- `GET /health` → `{"status":"ok",...}`
- `GET /` → 值班员静态页面
- `POST /api/verify`，请求体 `{"rootKey":"<规范JSON>","objects":["<规范JSON>",…],"now":1790000000?}`
  - 成功：`200 {"ok":true,"evidence":{hops:[{signature,payloadDigest,tightened,…}],finalConstraints,verdict}}`
  - 拒绝：`422 {"ok":false,"error":{code,hop,field,message,line,col}}`

页面行为：**错误草稿不覆盖上一份有效证据**——本次核验被拒绝时，上一份有效
证据仍保留展示（标注「上一份有效证据」），仅当新的核验通过时才更新。

## 一次性验收服务 `verify`

`docker compose run --rm verify`（或本机 `./bin/verify`）依次执行：

1. 复核合法链逐跳证据（签名、规范载荷摘要独立复算、收紧约束、准许结论）；
2. 复核越权链拒绝（浮标越权、采样超限、集合/时间窗放宽、链首非根、非前一主体签发）；
3. 复核篡改签名 / 改写载荷的拒绝（`BAD_SIGNATURE`）；
4. 复核结构性与数值错误定位（重复键、键序、不安全/越界整数、非有限数等）；
5. 运行相关代码测试（`node --test`）与页面构建检查；
6. 启动临时网关做健康地址 API/HTTP 冒烟（`GATEWAY_URL` 存在时再冒烟对端）。

执行完毕即退出：退出码 `0` 全部通过，`1` 存在失败项，`2` 执行异常。

## 目录

```
src/canonical.js   严格规范 JSON（JCS）解析/序列化、整数边界判定
src/chain.js       委托链逐跳核验（验签、签发关系、收紧、时效、末端检查）
src/sign.js        离线签发辅助（测试与验收复现完整链路）
src/server.js      零依赖 HTTP 服务（静态页面 /health /api/verify）
public/            值班员页面（证据留存、错误草稿独立展示）
tests/             单元测试（node:test）
scripts/check-page.js  页面构建检查
verify/acceptance.js   一次性验收服务入口
bin/verify             本机可执行验收入口
compose.yaml           gateway（可配置宿主机端口）+ verify（一次性验收）
```
