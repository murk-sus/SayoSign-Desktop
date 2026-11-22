<p align="center"><img src="sayosign_desktop/web/icon.png" width="96" alt="SayoSign"></p>
<h1 align="center">SayoSign Desktop</h1>
<p align="center">
  <b>在 Linux、Windows 和 macOS 上为 iPhone 签名并安装 IPA。</b><br>
  .p12 或 Apple ID · 插件注入 · 2026 年仍可用的 Apple ID 登录 · 电脑上的 Anisette 服务器
</p>
<p align="center"><a href="https://github.com/murk-sus/SayoSign-Desktop/releases/latest"><b>⬇ 下载</b></a> · <a href="README.md">English</a> · <a href="https://github.com/murk-sus/SayoSign">iOS 应用</a></p>

## 功能

- 通过 USB **签名并安装**，或仅签名后下载。原生窗口。
- **证书**：`.p12` + `.mobileprovision`（实时 OCSP 吊销检查），或**使用免费/付费 Apple ID 登录**，自动创建证书、注册设备并为每个应用生成描述文件。
- **插件**：注入 `.deb` 和 `.dylib`。
- **Anisette 标签页**：一键设置、自定义服务器、服务器数据，以及给 iPhone 用的**本机 Anisette 服务器**（扫描二维码）。
- 主题：自动、浅色、**黑色**。

## 为什么 2026 年 10 月 Apple ID 登录失效

自 2026 年 10 月中旬起，Apple 拒绝与其客户端不匹配的 Anisette 数据：基于 **Android** 库生成的数据（`ani.sidestore.io`、`ani.sidestore.zip`、自建 `anisette-v3-server`）会出现 `-80045`、HTTP `503` 或 `finishMachineProvisioning` 返回 `401`。**基于 Mac 的服务器**仍然可用，前提是每个请求都使用该服务器自己的 client info 和 user agent。SayoSign Desktop 已全面支持 Anisette v3 协议并按此发送请求，2026-11-22 已与 Apple 实测通过。

## 安装（Linux）
```sh
git clone --recursive https://github.com/murk-sus/SayoSign-Desktop && cd SayoSign-Desktop
./install-linux.sh
sayosign-desktop
```
Windows / macOS 请在 [Releases](https://github.com/murk-sus/SayoSign-Desktop/releases) 下载。

💖 支持作者：**[murk-sus.github.io/donate](https://murk-sus.github.io/donate/)**
