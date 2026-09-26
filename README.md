# 浮标失联应急采样 · 受限委托链核验 / 容量委托图审计岸站

海洋观测浮标失联时，岸站携带**离线签发的受限委托链**下发应急采样命令。本服务对
值班员粘贴的「根公钥 + 按顺序排列的委托 / 末端命令」按**同一套规范 JSON 字节**
（JCS，RFC 8785）逐跳验签，确认每跳委托由前一主体签发，且时间窗、浮标集合、
采样上限只允许收紧；对有效链展示逐跳证据与最终准许结论，对违规链给出可定位的拒绝原因。

此外，值班员可在**同一页面**粘贴一份**无序的容量委托集合**、目标主体、浮标与
评估时刻，发起**容量审计**：系统按各条声明的父载荷摘要把委托接成有向委托图，
逐边验签、确认签发关系与约束只收紧，并在指定浮标 / 时刻上**精确计算根到目标
主体的最大可转移容量**，给出按规范摘要稳定排列的流量边、剩余容量与能阻断更多
采样的最小割证据——无需再逐链猜测哪一条足够。

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

## 容量委托（`cap-delegation`）与容量审计

容量委托沿用单链的 P-256 签名与规范 JSON 字节，在既有字段上新增两个成员
（键按 JCS 顺序排列）：

```json
{"aud":["buoy-01"],"exp":1790003600,"iss":{"crv":"P-256","kty":"EC","x":"…","y":"…"},"maxSamples":50,"nbf":1789996400,"parent":"<父载荷 SHA-256 hex，根边为 \"\">","sig":"…","sub":{"crv":"P-256","kty":"EC","x":"…","y":"…"},"transfer":40,"typ":"cap-delegation"}
```

| 新增字段 | 含义 |
| --- | --- |
| `parent` | 父载荷摘要：父委托「去掉 `sig` 后规范字节」的 SHA-256（小写 hex）；根委托用空串 `""` 显式锚定所粘贴根公钥 |
| `transfer` | 本边**可转移容量**（int32 区间内非负整数，且不得大于本边 `maxSamples`） |

### 图规则（集合无序，按 `parent` 摘要接线）

1. 每条用本边 `iss` 公钥独立验签（规范字节 = 去掉 `sig` 后的 JCS 字节）；
2. 根边（`parent=""`）的 `iss` 必须等于根公钥；非根边的 `iss` 必须等于
   **父边的 `sub`**（后继签发者不匹配即拒绝）；
3. 相对父边只允许收紧：`nbf` 不提前、`exp` 不延后、`aud` 为父边子集、
   `maxSamples` 不大于父边；`transfer ≤ maxSamples`；
4. `parent` 指向的摘要必须在集合内（悬空 / 缺失即拒绝），图不得成环；
5. 同一规范委托（同摘要）不得重复粘贴。

### 容量计算

在指定**浮标**与**评估时刻**上，仅时间窗覆盖 `now` 且 `aud` 含该浮标的边为
「生效边」。以边的 `transfer` 为容量，在「根公钥 → 目标主体」的有向图上用
Edmonds–Karp 求**最大流**，其值即失联期间目标主体在该浮标上**最多可获得的
可用采样额度**；同时给出残量网络最小割（最大流最小割定理保证割容量等于最大流），
割中委托边就是「割掉即可阻断更多采样」的最小证据集。所有边列表（流量、剩余
容量、割集、可达集）均按**规范载荷摘要稳定排列**，与粘贴顺序无关。

### 容量审计错误码（`index` = 粘贴集合中的序号，`-1` = 根公钥 / 目标 / 请求）

| code | 含义 |
| --- | --- |
| `PARENT_MISSING` / `PARENT_NOT_FOUND` | 缺少 `parent` 成员 / 父摘要在集合中找不到对应委托 |
| `GRAPH_CYCLE` | 父摘要链接形成有向环 |
| `ISSUER_NOT_ROOT` / `ISSUER_MISMATCH` | 根边签发者非根公钥 / 后继边并非父边主体签发 |
| `NOT_TIGHTENED` | 相对父边放宽了时间窗 / 浮标集合 / 采样上限（`field` 定位） |
| `BAD_SIGNATURE` | 签名与规范载荷摘要不符（内容或签名被改写） |
| `TARGET_UNREACHABLE` | 目标主体不在图中，或在该浮标 / 时刻无根到目标的生效路径 |
| `SCHEMA` / `JSON_SYNTAX` / `KEY_ORDER` / … | 模式、语法、键序、整数边界等错误（与单链同一套） |

## API

- `GET /health` → `{"status":"ok",...}`
- `GET /` → 值班员静态页面
- `POST /api/verify`，请求体 `{"rootKey":"<规范JSON>","objects":["<规范JSON>",…],"now":1790000000?}`
  - 成功：`200 {"ok":true,"evidence":{hops:[{signature,payloadDigest,tightened,…}],finalConstraints,verdict}}`
  - 拒绝：`422 {"ok":false,"error":{code,hop,field,message,line,col}}`
- `POST /api/capacity`，请求体
  `{"rootKey":"<规范JSON>","delegations":["<cap-delegation 规范JSON>",…],"target":"<目标主体 JWK 规范JSON>","buoy":"buoy-01","now":1790000000?}`
  （`delegations` 无序；根边 `parent` 为 `""`）
  - 成功：`200 {"ok":true,"evidence":{kind:"capacity",maxTransferable,flowEdges:[{payloadDigest,capacity,flow,remaining,…}],minCut:{capacity,edges:[…],reachableThumbprints},edges:[全部边（含未生效原因）…],verdict}}`
  - 拒绝：`422 {"ok":false,"error":{code,index,hop,field,message,line,col}}`

页面行为：**错误草稿不覆盖上一份有效证据**——本次核验（或容量审计）被拒绝时，
上一份有效证据仍保留展示（标注「上一份有效证据」），仅当新的同区核验通过时才
更新。容量结论与单链证据**分区显示、各自独立留存**，互不替换。

## 一次性验收服务 `verify`

`docker compose run --rm verify`（或本机 `./bin/verify`）依次执行：

1. 复核合法链逐跳证据（签名、规范载荷摘要独立复算、收紧约束、准许结论）；
2. 复核越权链拒绝（浮标越权、采样超限、集合/时间窗放宽、链首非根、非前一主体签发）；
3. 复核篡改签名 / 改写载荷的拒绝（`BAD_SIGNATURE`）；
4. 复核结构性与数值错误定位（重复键、键序、不安全/越界整数、非有限数等）；
5. 复核容量委托图审计（乱序接线、逐边验签、只收紧、最大流 / 最小割精确相等、
   确定性、父摘要缺失 / 成环（白盒）/ 签发者不匹配 / 放宽 / 篡改 / 目标不可达的定位拒绝）；
6. 运行相关代码测试（`node --test`）与页面构建检查；
7. 启动临时网关做健康地址 API/HTTP 冒烟（含 `/api/capacity`；`GATEWAY_URL` 存在时再冒烟对端）。

执行完毕即退出：退出码 `0` 全部通过，`1` 存在失败项，`2` 执行异常。

## 目录

```
src/canonical.js   严格规范 JSON（JCS）解析/序列化、整数边界判定
src/chain.js       委托链逐跳核验（验签、签发关系、收紧、时效、末端检查）
src/capacity.js    容量委托图审计（按父摘要接线、逐边验签、最大流 / 最小割）
src/sign.js        离线签发辅助（委托 / 命令 / 容量委托，测试与验收复现完整链路）
src/server.js      零依赖 HTTP 服务（静态页面 /health /api/verify /api/capacity）
public/            值班员页面（单链与容量分区、证据分别留存、错误草稿独立展示）
tests/             单元测试（node:test）
scripts/check-page.js  页面构建检查
verify/acceptance.js   一次性验收服务入口
bin/verify             本机可执行验收入口
compose.yaml           gateway（可配置宿主机端口）+ verify（一次性验收）
```
