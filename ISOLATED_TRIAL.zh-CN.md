# 合成资料隔离试装

此分支用于在独立目录中验证合成资料、账号和工具回执。**不代表真实业务、真实供应商或完整数字员工平台已通过上线验收。** 不填真实模型密钥、不接业务工具、不导入内部资料；无来源或缺许可的旧调用保持拒绝，不能关闭门禁恢复功能。

## 环境与源码准备

已验证路径为Linux x86_64、CPython3.12.14、官方uv0.12.23。Windows原生、WSL、Docker及其他Python版本的实际安装尚未核验。项目声明Python>=3.11，Harness声明Node ^22.19.0或>=24；声明不等于全部环境已验收。

解压本分支源码ZIP到新的独立目录，无需另找基线或打补丁。源码不含安装环境、数据库或密钥，不是预编译安装器。保留原LICENSE和第三方声明。

在根目录使用已安装的Python3.12和uv，创建新的测试venv：

```sh
UV_PROJECT_ENVIRONMENT="$PWD/.venv-smoke" uv sync --project backend --locked --extra dev --no-python-downloads --python python3.12 --default-index https://pypi.org/simple
uv pip check --python .venv-smoke/bin/python
uv lock --check --offline --project backend --no-python-downloads --default-index https://pypi.org/simple
```

SQLModel锁定0.0.38，满足pyproject声明。不要替换已有安装的venv或复用实际数据目录。安装未缓存依赖需要官方包源连接，这不代表允许模型或业务外发。

## 无真实外发的最小验证

以下为Linux/POSIX示例；其他环境须先确认路径与shell。只使用新的临时目录、空dotenv、合成账号和本地MockTransport：

```sh
STAFFDECK_TEST_ROOT="$(mktemp -d)"
ULTRARAG_DATA_DIR="$STAFFDECK_TEST_ROOT/data" ULTRARAG_DOTENV=/dev/null DATABASE_URL="sqlite:///$STAFFDECK_TEST_ROOT/test.sqlite" HARNESS_CONTROL_AUTH_PROVIDER= PYTHONPATH=backend:backend/src:scripts STAFFDECK_NETWORK_GUARD_REPORT="$STAFFDECK_TEST_ROOT/network-guard.json" .venv-smoke/bin/python -m pytest -p local_network_guard -q backend/tests/test_local_session_revocation.py backend/tests/test_tool_test_idempotency.py
```

该组合验证登录/退出、会话撤销、租户/用户隔离、稳定请求号、并发、冲突及未知结果防重。网络保护仅作用于测试进程，拒绝非loopback连接，不修改主机防火墙。测试口令不用于实际账号。

前端检查：

```sh
npm --prefix frontend-enterprise ci
npm --prefix frontend-enterprise test
npm --prefix frontend-enterprise run build
npm --prefix frontend-enterprise run i18n:check
npm --prefix frontend-enterprise run config:check
```

部分既有模型/Node工具调用及旧恢复用例尚未满足当前契约。局部测试通过不等于全部历史测试或全平台通过。

## 页面与启动边界

合成MD/TXT可验证本地解析、入库检索、授权、归档/恢复；可验证分类/许可草稿、管理员手写答复视图与版本失效。不开真实模型不能验收答案质量或智能解析。

无密钥结构模板为`config/local-synthetic.env.example`，不要原样导入占位路径。新安装通过既有bootstrap生成并持久化安装材料；升级保留原APP_SECRET/seed，不使用示例或测试口令作为实际凭据。

源码准备和开发启动沿用README、`python3 prepare.py --no-cli-link`及`scripts/dev_up.sh --detach`。Python安装本身不生成Harness构建产物；普通开发启动会开启后台服务，**不属于上述无服务smoke**。先确认目标环境与组件，再用新的合成目录试装，不连接真实渠道、模型、外部工具或定时业务。

## 权限和失败行为

- 本地登录默认refresh_mode=none，过期需重新登录。退出在服务器确认后清理本地身份，旧token持久拒绝。外部control provider须单独验收。
- 检索可见、允许原文引用、向指定供应商发送是不同权限。只有管理员能按供应商、用途及资料版本明确批准；无标签/未知或混合来源中任一不允许时整次请求拒绝。
- 准备和审批不发送，提问者另行点击才生成。禁止原文的模式只发送批准答复视图，由服务器校验并渲染；提示词或模型改写不能替代许可。
- 来源/供应商撤回或版本变化使旧快照失效；历史和派生内容不自动获得外发许可。
- 保存工具的client_request_id绑定租户/用户/工具/员工/参数。同键复用回执，换参数冲突；超时、断线、重开、取消/过期或未知结果先查询，不能自动重放。仅在确认完成后明确开始新的独立操作。任意非幂等外部系统无法由此获得exactly-once保证。

## 备份、恢复与回退

接入已有安装前停止所有写入、worker、渠道及定时任务。一致备份SQLite/WAL、完整附件/知识/运行目录、安装seed及原APP_SECRET/有效配置，保护权限，不提交到Git。

仅在离线恢复副本使用项目venv及`PYTHONPATH=backend:backend/src`，依次执行：

```sh
.venv-smoke/bin/python -m app.security.data_policy_migrations --database /absolute/path/restored.sqlite --reset-after-restore
.venv-smoke/bin/python -m app.security.auth_sessions --database /absolute/path/restored.sqlite --invalidate-after-restore
.venv-smoke/bin/python -m app.tools.tool_test_requests --database /absolute/path/restored.sqlite --freeze-after-restore
```

这些步骤关闭恢复的模型许可、使旧本地token失效、冻结备份中的待处理工具测试。备份里完全没有记录的外部操作仍须对账，404不代表肯定没执行。既有启动迁移可能新增知识分支和规范化模型协议元数据；先在副本核验，不把源码恢复校验当真实数据灾备。

回退前停止入口与worker，新旧worker不得混跑；旧版本不识别新撤销/幂等信息，不能回退后保持外部连通。真实资料许可、供应商条款/保留策略、异机灾备、容量与长期运行均须另行验收。
