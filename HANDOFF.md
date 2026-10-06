# 账号与权限 Casdoor｜固定入口与交接

整理日期：2026-10-06。目录迁移后按用户授权做本地提交、历史保全和目录退役；未发布或改生产。

## 日常入口

固定目录：`/Users/luban/codebase/casdoor`。本地会话：**账号体系｜Casdoor**，确切 ID 与恢复/界面验收在 [项目导航](/Users/luban/codebase/PROJECTS.md)；用户未实际打开前不称会话验收完成。

旧定制溯源、官方升级与兼容，逐步形成自有身份与权限体系。

## 位置与源码状态

候选源码：本目录；部署/备份/兼容实验：docs/local-handoff/；独立 QA：其 qa/；旧 fork 溯源与身份合同：环境目录 outputs/统一执行看板研究-20261003/，不是另一正式运行源码。

codex/casdoor-fork-v4.13.0-integration @ 351d8057：源码迁前干净。旧 CI 工作树已退役，原 HEAD 保存在 Git 标签 `retired/casdoor-ci-20261006`；同库逐文件恢复核验见环境 cleanup-20261006/。新增 docs/local-handoff 与首页为本次本地资料，不自动提交。

## 已保留与缺口

源码 1,286 个文件与 CI 612 个文件迁移一致，分支/HEAD/原差异保持；身份合同、升级/备份与诊断证据保留。

历史 TEST 已升级兼容候选，生产仍旧版；本地 HEAD 不等于已部署源。四客户端真实登录、旧 ID、撤权与 2533 同请求链失败根因未完整验收。

## 从哪里启动、继续

官方 README 的 `go run main.go` + web/yarn 为服务方式；go.mod 要 Go 1.25.8，本机已有 Go 1.24.4，不在此轮安装工具链。启动还需要隔离数据库/配置，禁止直接拿生产 conf/app.conf 启动。本次未启动/构建/连接 DB。

读 `docs/local-handoff/TEST-Casdoor正式升级实录-20261005.md`、`Casdoor-fork源码升级检查点-20261003.md` 与客户端合同。先验兼容和回滚再决定生产升级。

## 原目录与恢复

2026-10-03/task-2；2026-10-04/task。

历史原记录保持原文；旧绝对路径按 [迁移映射](/Users/luban/codebase/agents/workspace-management/migration/path-mapping.json) 查新位置。逐文件清单、Git 前后状态和路径修改前副本在 `workspace-management/migration/`。保留的 SDK/缓存见各项目迁移回执；清理不属于本轮。

测试/生产描述来自 2026-10-05/06 已有回执，本次未刷新线上状态。

## 2026-10-06 本地收口

本项目现只有本目录一个工作树。旧CI认证代码已被当前更严格实现替代，旧workflow已经并入并增强测试；旧22种语言标签保留在历史提交中，未作为本次新功能移植。当前源码的真实客户端与生产验收继续按前述缺口处理。Git原提交和标签保留，不推送或发布。

## 2026-10-06 退役补充

当前交接初次本地提交 `41d7298e`；旧 CI 612 个现存源文件同库核验后退役，旧 HEAD 保留标签 `retired/casdoor-ci-20261006`。`docs/local-handoff/compat-proposal/app-login-log-risk` 的客户端临时副本、Git 和必要证据已在 `casdoor-source-history.tar.gz.age` 验证后退役；原路径已不存在。安全移植提案和诊断概要仍在外层 compat-proposal，冷存储原路径/权限/哈希见环境恢复清单。

前端 node_modules 已原位迁入本项目；不是重新安装或升级。两处无使用者的临时 Go 编译缓存已按纯哈希缓存布局退役；Go 模块和工具链缓存保留。当前运行版本、生产升级与客户端验收没有改变。
