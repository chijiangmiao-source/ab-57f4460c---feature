# 浮标失联应急采样 · 受限委托链核验 / 容量审计岸站

海洋观测浮标失联时，岸站携带**离线签发的受限委托链**下发应急采样命令。本服务提供两种核验：

1. **逐跳核验（单链）**：对值班员粘贴的「根公钥 + 按顺序排列的委托 / 末端命令」按
   **同一套规范 JSON 字节**（JCS，RFC 8785）逐跳验签，确认每跳委托由前一主体签发，
   且时间窗、浮标集合、采样上限只允许收紧；对有效链展示逐跳证据与最终准许结论，
   对违规链给出可定位的拒绝原因。
2. **容量审计（委托图）**：粘贴「根公钥 + **无序**容量委托集合 + 目标主体 + 浮标 +
   评估时刻」，服务按父摘要接成有向委托图，逐边验签、确认签发关系与约束只收紧，
   精确计算根到目标主体的**最大可转移采样额度**（最大流），并给出按规范摘要稳定
   排列的流量边、顶点剩余容量与**最小割**证据——失联期间该主体最多能获得多少
   额度，一眼可知，无需逐条猜测哪一条链足够。

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

## 容量委托格式（容量审计）

容量委托沿用 P-256 签名与规范 JSON，在上述委托字段之外新增两个成员：

```json
{"aud":["buoy-01"],"exp":1790003600,"iss":{…},"maxSamples":50,"nbf":1789996400,"parent":"<64位hex>","sig":"…","sub":{…},"transfer":30,"typ":"delegation"}
```

| 新增字段 | 含义 |
| --- | --- |
| `parent` | 父载荷摘要（64 位十六进制 SHA-256，即父委托「去掉 `sig` 后规范字节」的摘要）；根出边委托填根公钥指纹 |
| `transfer` | 本边可转移容量（int32 区间内的非负整数，且必须 ≤ 本委托 `maxSamples`） |

容量模型：每条委托恰有一个 `parent`，故委托顶点入度恒为 1，按 `parent` 接出的是
以根为起点的有根树（同一主体可在多份委托的 `sub` 处汇聚为审计汇点）。网络边容量
取该边声明的 `transfer`，目标主体各授予顶点到超汇的容量取其 `maxSamples`；
schema 已保证 `transfer ≤ 自身 maxSamples`，中转顶点上限不会先于其入边收口。
根→目标主体的**最大流**即该主体在指定浮标/时刻最多可获得的可用采样额度。

### 容量审计拒绝码（`node` = 根/目标/输入序号/问题委托摘要）

| code | 含义 |
| --- | --- |
| `PARENT_NOT_FOUND` | 父摘要在集合中不存在且不等于根公钥指纹 |
| `CYCLE_DETECTED` | 按 parent 拼接后存在环（图必须是 DAG；真实签名因摘要固定点约束无法构成环） |
| `SUCCESSOR_ISSUER_MISMATCH` | 后继委托的签发者不是父委托的主体（根出边则须为根本身） |
| `SCOPE_WIDENED` | 相对父委托放宽时间窗 / 浮标集合 / 采样上限（`field` 指出首个违规字段） |
| `BAD_SIGNATURE` | 签名与规范载荷摘要不符（内容或签名被篡改） |
| `TARGET_UNREACHABLE` | 给定浮标与评估时刻下根到目标主体不可达（含全部路径失效） |
| `DUPLICATE_DELEGATION` | 集合中存在规范载荷摘要相同的重复委托 |
| `TARGET_IS_ROOT` / `SCHEMA` / `JSON_*` | 目标即根 / 模式或语法错误 |

评估时刻落在时间窗外或委托 `aud` 不含目标浮标时，该委托（及其出边）**过滤为
本次不可用**（顶点表标注 `inactive` 与原因），不作为整图拒绝；若所有到目标路径
均被过滤则定位为 `TARGET_UNREACHABLE`。


## API

- `GET /health` → `{"status":"ok",...}`
- `GET /` → 值班员静态页面
- `POST /api/verify`（单链逐跳核验），请求体 `{"rootKey":"<规范JSON>","objects":["<规范JSON>",…],"now":1790000000?}`
  - 成功：`200 {"ok":true,"evidence":{hops:[{signature,payloadDigest,tightened,…}],finalConstraints,verdict}}`
  - 拒绝：`422 {"ok":false,"error":{code,hop,field,message,line,col}}`
- `POST /api/audit`（容量审计），请求体
  `{"rootKey":"<规范JSON>","targetKey":"<规范JSON>","buoy":"buoy-01","delegations":["<容量委托规范JSON>",…],"now":1790000000?}`
  （`delegations` 为**无序**集合，每行一份即可，服务按 `parent` 自行接图）
  - 成功：`200 {"ok":true,"audit":{now,buoy,rootKeyThumbprint,targetThumbprint,delegationCount,vertices:[…],flowEdges:[…],minCut:{edges,capacity,sourceSideVertices},verdict:{reachable,maxTransferable,reason}}}`
    - `flowEdges`：按 `payloadDigest`、`parentDigest` 稳定排列，每条含 `transfer / flow / residual`；
    - `vertices`：按 `payloadDigest` 稳定排列，含全部顶点（标注 `status`、`inactiveReason`、`reachable`、`isTarget`、`inflow`、`remaining`）；
    - `minCut`：与最大流等值的最小割证据，割边可回溯到具体委托摘要。
  - 拒绝：`422 {"ok":false,"error":{code,node,field,message,line,col}}`，`node` 为根 / 目标 / 输入序号 / 问题委托摘要。

页面行为：**容量结论与单链证据分区显示**，二者各自留存——本次核验/审计失败时，
上一份成功证据仍保留展示（标注「上一份有效证据」），新的失败请求不会替换最近一次
成功的容量证据；仅当新的同类请求成功时才更新对应分区。

## 一次性验收服务 `verify`

`docker compose run --rm verify`（或本机 `./bin/verify`）依次执行：

1. 复核合法链逐跳证据（签名、规范载荷摘要独立复算、收紧约束、准许结论）；
2. 复核越权链拒绝（浮标越权、采样超限、集合/时间窗放宽、链首非根、非前一主体签发）；
3. 复核篡改签名 / 改写载荷的拒绝（`BAD_SIGNATURE`）；
4. 复核结构性与数值错误定位（重复键、键序、不安全/越界整数、非有限数等）；
5. 复核容量审计（无序接图、最大流值、流量守恒、摘要稳定排列、最小割证据，以及父摘要缺失 / 后继签发者不匹配 / 范围放宽 / 篡改签名 / 目标不可达的定位拒绝）；
6. 运行相关代码测试（`node --test`）与页面构建检查；
7. 启动临时网关做健康地址 API/HTTP 冒烟，含 `/api/audit` 成功与拒绝用例（`GATEWAY_URL` 存在时再冒烟对端）。

执行完毕即退出：退出码 `0` 全部通过，`1` 存在失败项，`2` 执行异常。

## 目录

```
src/canonical.js   严格规范 JSON（JCS）解析/序列化、整数边界判定
src/chain.js       单链逐跳核验（验签、签发关系、收紧、时效、末端检查）
src/audit.js       容量委托图审计（接图、逐边验签、收紧、最大流/最小割）
src/sign.js        离线签发辅助（含容量委托 issueCapacityDelegation，供测试与验收复现）
src/server.js      零依赖 HTTP 服务（静态页面 /health /api/verify /api/audit）
public/            值班员页面（单链与容量分区、各自证据留存、错误草稿独立展示）
tests/             单元测试（node:test，含 audit.test.js）
scripts/check-page.js  页面构建检查
verify/acceptance.js   一次性验收服务入口
bin/verify             本机可执行验收入口
compose.yaml           gateway（可配置宿主机端口）+ verify（一次性验收）
```
