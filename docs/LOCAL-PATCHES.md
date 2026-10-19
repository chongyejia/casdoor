# 本地补丁清单

## 微信小程序 OAuth 响应兼容（mingpian-fix-20261019）

- 原因：升级线微信成功分支直接序列化内部 `Token`，返回 `idToken`；名片、PIMAP 等旧客户端读取 `id_token`，可能缓存无效凭据并反复登录。
- 位置：`object/token_wechat_compat.go` 集中完成映射；官方代码仅 `object/token_oauth.go` 微信成功出口一行调用。JWT 生成、存储、cert、application 及错误分支不变。
- 合同：构造 `TokenWrapper`，保留 `access_token/id_token/refresh_token/token_type/expires_in/scope`，追加同值 `accessToken/idToken/refreshToken/tokenType/expiresIn`；`scope` 共用。默认成功响应只含这些字段，不嵌入内部 `Token`。
- 开关：`wechatMiniProgramTokenCompat`，使用既有 conf 读取方式，环境变量优先于 app.conf。未配置、空值、`true` 或其他值均启用；只有精确 `false` 关闭。首次只换镜像无需配置变更。关闭后恢复原上游 `Token` 响应（含内部字段），仅用于客户端全部完成迁移后的退出演练，不视为安全加固。
- 测试：`TestWechatTokenCompatMappingAndSwitch`、`TestWechatTokenCompatFullFlow`、`TestWechatTokenCompatErrorsUnchanged`。FullFlow 使用 SQLite 内存数据库、合成身份/RSA 密钥和拒绝非预期请求的微信 HTTP mock，调用实际 `GetOAuthToken`，检查字段白名单、存储值、JWT 签名/iss/aud/exp/sub/type；删除或覆盖调用点必失败。错误 code、空 session、缺 provider、禁用/删除用户、存储失败保持错误合同。
- 必跑检查：`go test -mod=readonly -count=1 ./object -run '^TestWechatTokenCompat'`。已纳入 `ci/test-identity-offline.sh`，现有 fork-source-build CI 会执行。当前提交没有官方源同步脚本；`.github/workflows/sync.yml` 是翻译同步，不是源同步。任何手工 upstream merge/rebase 后、构建镜像前必须运行上述检查，禁止将“没有匹配测试”视为通过；同时核实三个测试名仍存在。
- 防覆盖验收：保留测试，把官方出口临时还原为 `return token, nil`，FullFlow 必须失败；恢复调用后通过。若同步把整个本地测试文件删除，需靠清单与 CI 下面的测试存在性检查拒绝构建。

## 退出计划及客户端

本次本地盘点未发现直接依赖微信接口 camelCase 的已检查客户端；仍按兼容要求同时返回两套字段，覆盖未知客户端。宠业家 APP 使用 MP API 自身 `data.idToken` 包装，其 password grant 读取 `id_token`；开放平台使用普通授权码读取 `access_token`；OMS Web 使用授权码 SDK，OMS Lark 使用独立 tag，均不改动。

1. 名片下一版统一 `id_token ?? idToken`、refresh token 同样规范化，增加写缓存和发请求前的 JWT 结构校验；发布另行审批。
2. PIMAP、供货小程序、库存小程序、porder 等直接调用微信换票的客户端后续全部兼容两套字段；核对实际生产版本与未知外部调用者。仅源码修改不算发布完成。
3. 所有消费端发版且经过约定覆盖窗口后，先在 TEST 设开关 `false` 验证成功登录/刷新/历史缓存恢复；再审批生产关闭（本任务禁止改生产配置）。
4. 观察旧客户端存量归零、无 malformed 回归后，删除适配器及调用点，更新清单、CI 和测试。若上游已修复为标准 TokenWrapper，也需全链路合同测试后再移除本地逻辑，不静默删除测试。
