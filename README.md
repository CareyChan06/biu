# biu

个人使用的 HarmonyOS GitHub 加速器。通过 `VpnExtensionAbility` 建立一个本地 TUN，
在设备内部完成 DNS 解析和流量转发，不依赖任何外部代理服务器，也不上传任何数据。

- 应用名：biu
- Bundle Name：`com.biu.app`
- 版本：0.1.0
- 目标平台：HarmonyOS 7 / API 26
- 用途：个人自用，不上架应用市场

## 功能

- **DNS 加速**：拦截发往 `10.0.0.1:53` 的 DNS 查询。对白名单域名
  （github.com、api.github.com、raw.githubusercontent.com、github.githubassets.com、
  avatars/objects.githubusercontent.com、gist.github.com 等）在本地直接应答，
  不再向上游查询。
- **优选 IP**：对每个域名的候选 IP 并行发起 TLS ClientHello 探测，
  选择握手最快且可用的地址写进 DNS 应答；结果带 TTL 缓存（成功 10 分钟 / 失败 30 秒）。
- **全流量转发**：TUN 捕获的 TCP / UDP 流量由用户态转发器接管。
  TCP 由一个精简状态机实现（三次握手、MSS 1200 分段、ACK/序号跟踪、
  FIN/RST、超时回收），UDP 按五元组维护独立 socket。
- **状态统计**：扩展进程把运行状态和计数写入
  `/data/storage/el2/base/haps/entry/files/biu_stats.json`，
  UI 轮询该文件并校验新鲜度后展示。
- **连通性测试**：首页可随时对 `github.com` 做 DNS 解析，并对
  `github.com` / `api.github.com` 发起 HTTPS HEAD 探测，显示解析地址、
  响应状态与耗时，用于确认加速是否真正生效。

## 工作原理

```
App (浏览器等)
   │  IPv4 流量（默认路由 vpn-tun）
   ▼
VpnExtensionAbility ── create(VpnConfig) ──► tunFd
   │                                           │
   │  dnsAddresses = 10.0.0.1                  │ read()
   ▼                                           ▼
DNS 处理线程（最多 4 个）               tun_reader.cpp
   │  ├─ 白名单 A 查询 → 本地应答               │
   │  └─ 其他查询 → 上游转发                    ├─ UDP:53 → DNS 队列
   ▼                                           ├─ TCP    → 转发队列
写回 tunFd                                     └─ 其他 UDP → 转发队列
                                                  │
                                            tun_forward.cpp
                                            ├─ TCP 状态机（非阻塞 connect）
                                            └─ UDP 五元组转发
                                                  │
                                                  ▼
                                          物理网络（protectProcessNet）
```

### 两个关键的平台约束

1. **默认路由写法**：只有

   ```ts
   routes: [{
     interface: 'vpn-tun',
     destination: { address: { address: '0.0.0.0', family: 1 }, prefixLength: 0 },
     gateway: { address: '10.0.0.1', family: 1 },
     hasGateway: true,
     isDefaultRoute: true
   }]
   ```

   才会让应用 TCP 流量真正进入 TUN。`gateway: '0.0.0.0'` 或空网关会被系统静默忽略，
   此时只有 DNS 能到达虚拟网卡。

2. **转发线程唤醒**：转发线程通过管道唤醒。管道读端必须设置 `O_NONBLOCK`，
   否则 `while (read(pipe) > 0)` 在读空后会永久阻塞，队列中的 SYN 永远不会被处理。

## 目录结构

```
biu/
├─ AppScope/                       应用级配置与图标
├─ entry/
│  └─ src/main/
│     ├─ ets/
│     │  ├─ entryability/          入口 Ability
│     │  ├─ pages/Index.ets        主界面（启动/停止、统计展示）
│     │  └─ vpn/BiuVpnExtAbility.ets  VPN 扩展，创建 TUN 并启动原生层
│     ├─ cpp/
│     │  ├─ tun_reader.cpp         从 TUN 读取并按协议分发
│     │  ├─ tun_forward.cpp        TCP / UDP 用户态转发
│     │  ├─ dns_handler.cpp        DNS 拦截、本地应答与上游转发
│     │  ├─ ip_prober.cpp          TLS 握手探测与候选 IP 缓存
│     │  ├─ napi_init.cpp          NAPI 绑定
│     │  └─ CMakeLists.txt         原生库构建（libbiu.so）
│     └─ module.json5              权限与扩展声明
├─ design/                         设计参考图（不参与构建）
└─ build-profile.json5             构建与签名配置（本地文件，未入库）
```

## 构建

环境：DevEco Studio（含 API 26 SDK）、HarmonyOS SDK、NDK、Node.js。

`build-profile.json5` 已被 `.gitignore` 忽略，克隆后先复制模板，再在
DevEco Studio 中配置自动签名（会生成 `signingConfigs`）：

```bash
cp build-profile.example.json5 build-profile.json5
```

```bash
export DEVECO_SDK_HOME='D:\Program Files\Huawei\DevEco Studio\sdk'
export JAVA_HOME='D:\Program Files\Huawei\DevEco Studio\jbr'
export PATH="/d/Program Files/Huawei/DevEco Studio/jbr/bin:/d/Program Files/Huawei/DevEco Studio/tools/node:$PATH"

"/d/Program Files/Huawei/DevEco Studio/tools/hvigor/bin/hvigorw" \
  --mode module -p product=default -p buildMode=debug assembleHap --no-daemon
```

产物：`entry/build/default/outputs/default/entry-default-signed.hap`

> `build-profile.json5` 中的 `signingConfigs` 包含本机证书路径和加密后的口令，
> 属于本地配置，已加入 `.gitignore`。仓库只保留不含签名的
> `build-profile.example.json5`。

## 安装与使用

```bash
hdc install -r entry/build/default/outputs/default/entry-default-signed.hap
```

1. 打开 biu，点击“开始加速”，在系统弹窗中允许创建 VPN 连接。
2. 状态栏出现 VPN 图标后，浏览器访问 GitHub 即可。
3. 首页展示 DNS 请求数、已加速数、TCP 包数与连接数。

也可以直接启动扩展（已授权过一次后）：

```bash
hdc shell aa start -a BiuVpnExtAbility -b com.biu.app
```

## 已知限制

- **仅 IPv4**：`isIPv6Accepted` 关闭，IPv6 流量不经过 VPN。
- **TCP 实现是精简版**：不支持窗口缩放、SACK、拥塞控制优化；
  大文件传输或弱网下吞吐不如系统协议栈。
- **UDP 转发为尽力而为**：按五元组维护 socket，60 秒空闲回收，
  不保证 QUIC 等协议的完整行为。
- **依赖系统 DNS 路径**：如果目标应用绕过系统 DNS（例如浏览器自带的 HTTPDNS），
  白名单应答可能不生效；当前华为浏览器实测走系统 DNS 路径。
- **网络侧封锁**：如果运营商或网络环境直接封锁目标 IP 的 TCP 443，
  本地加速也无法绕过。
- **仅个人使用**：未做多用户、日志脱敏、流量审计等产品化处理。

## 安全说明

- 不修改或解密 TLS 流量，只做 DNS 优选与 TCP/UDP 转发（MITM 属于后续规划）。
- 所有探测和转发均在本机完成，不上传域名、IP 或统计信息。
- 仓库不包含签名证书、口令或任何设备凭据。

## 后续计划

- 按域名/IP 集合做更细粒度的分流，减少对非目标流量的接管。
- 更好的 TCP 拥塞与重传策略，提升大文件场景下的表现。
- 可选的应用级代理列表（`trustedApplications`）与开关。
