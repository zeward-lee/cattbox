# Bettbox

个人自用的 Bettbox 构建（基于 Mihomo 内核）。

构建产物见 Releases。

本项目：[zeward-lee/cattbox](https://github.com/zeward-lee/cattbox)

上游代码基线：appshubcc/Bettbox（仅作来源说明；发布包与升级源均以本项目为准）

## 更新方式

客户端内置更新检查：启动后读取本仓库 `releases/latest` 的 302 跳转拿版本号，有新版本直接下载并在应用内安装，**不需要手动下载安装包**。

- Windows：自动下载安装器并静默覆盖安装（需管理员权限）
- Android：应用内下载 APK 后调起系统安装器

升级链路依赖四条约定：

1. **版本号与上游 Bettbox 严格同号**（上游发 1.19.10，本仓库就发 1.19.10，不自增、不逾越）；
2. tag 为纯数字（如 `v1.19.10`）；
3. `pubspec.yaml` 版本与 tag 一致；
4. 校验文件资产名固定小写 `sha256sums.txt`。

## 当前版本

- **1.20.2**（2026-11-26）：合并上游 Bettbox v1.20.2（12 个提交）。
  - 内核空闲内存回收：内存清理分三档（普通 GC / 释放 OS 内存 / 只清空闲连接），内核流量忙时自动跳过
  - 切换代理模式时主动关闭旧连接；anytls / xhttp 等协议的空闲会话随网络切换回收
  - 内核补丁目录化（dns / mmdb / ipcidr / classical provider），geo 数据库更新失败改为容错而非整份失败
  - 托管脚本 DNS 策略重写：`nameserver` 固定走代理组、按直连规则集自动生成分流 DNS、新增 sniffer 配置，新增 `nvidia_cn` / `synology` 规则集
  - bundle 脚本改为按成员逐个执行；通知栏测速刷新节流；配置文件非法节容错、默认绕过域名恢复
  - 本仓库侧保留：私有协议全量（x365 / xhttp / ninja / sntp-eclipse / miu / oppa / FastUP / ViewTurbo / BLACKSTONE / OIX / smart 选路 / Shanlian raw16）、健康检查超时 3000ms 下限、内网规则集镜像与测速地址
- **1.20.1**（2026-11-25）：合并上游 Bettbox v1.20.1；移除旧的「更新时使用代理」开关，统一到上游「直连更新 / 跳过证书验证」。
- **1.20.0**（2026-11-24）：合并上游 Bettbox v1.20.0（25 个提交）。
- **1.19.10**（2026-11-23）：合并上游 Bettbox v1.19.10（24 个提交），新增每订阅「直连更新 / 跳过证书验证」、连接页一键建规则、批量导入节点、测速卡死修复、FakeIP 走 TUN 等。版本号与上游保持一致。

## 构建

定制构建流水线见 `.github/workflows/build-custom.yaml`（上游 `build.yaml` 保持原样并以 `if: ${{ false }}` 关闭，避免跟版冲突）。
