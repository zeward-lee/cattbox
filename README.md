# Bettbox

个人自用的 Bettbox 构建（基于 Mihomo 内核）。

构建产物见 Releases。

本项目：[zeward-lee/cattbox](https://github.com/zeward-lee/cattbox)

上游代码基线：appshubcc/Bettbox（仅作来源说明；发布包与升级源均以本项目为准）

## 更新方式

客户端内置更新检查：启动后读取本仓库 `releases/latest` 的 302 跳转拿版本号，有新版本直接下载并在应用内安装，**不需要手动下载安装包**。

- Windows：自动下载安装器并静默覆盖安装（需管理员权限）
- Android：应用内下载 APK 后调起系统安装器

升级链路依赖三条约定：tag 为纯数字（如 `v1.19.13`）、`pubspec.yaml` 版本同步递增、校验文件资产名固定小写 `sha256sums.txt`。

## 当前版本

- **1.19.10**（2026-11-23）：合并上游 Bettbox v1.19.10（24 个提交），新增每订阅「直连更新 / 跳过证书验证」、连接页一键建规则、批量导入节点、测速卡死修复、FakeIP 走 TUN 等。版本号与上游保持一致。

## 构建

定制构建流水线见 `.github/workflows/build-custom.yaml`（上游 `build.yaml` 保持原样并以 `if: ${{ false }}` 关闭，避免跟版冲突）。
