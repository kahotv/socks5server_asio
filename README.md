## 说明

基于asio (non-boost) + coroutine的socks5服务端

## 编译
- msvc142（vs2019）
- c++20以上
- x86

## 已实现

- TCP代理(IPv4/IPv6/域名IPv4)
- UDP代理(IPv4/域名IPv4)
- 2种认证模式(无认证/账号密码)

## 已知问题

- UDP代理的IPv6有bug导致失效
- UDP分片未实现

## 特点

- coroutine天然就能解决两个关键问题：
  - TCP大小水管的问题
  - 一端发送数后立即关闭时，另一端可能会收不到的问题
- 当转发的线程不访问公共资源时，coroutine还天然支持：
  - 多线程协同工作，不需要加锁。
