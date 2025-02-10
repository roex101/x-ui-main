# 关于
📮Roex101@126.com
Admin：@Roex101

个人博客：https://blog.0102019.xyz/

名下所有的频道

❶主频道：[t.me/Roex10](https://t.me/Roex10)
❷HTTP/HTTPS代理蜜罐监测：[t.me/Roex101_Proxy_honeypot](https://t.me/Roex101_Proxy_honeypot)

不做任何违法行为，仅个人学习
持续更新中…

#使用教程
1. 准备工作
创建Telegram机器人：

在Telegram中搜索 @BotFather

发送 /newbot 按提示操作，获得 Bot Token

获取Chat ID：

2. 配置环境变量
```
export TG_BOT_TOKEN="your_bot_token"
export TG_CHAT_ID="your_chat_id"
```
3. 编译运行
编译
```
go build -o xui-scanner main.go
```
运行（10并发）
```
./scanner -c 10 targets.txt
```
效果示例
成功检测时会收到如下Telegram消息：
```
🚨 发现弱密码漏洞!

🔗 目标地址: http://vuln-server:54321
👤 用户名: admin
🔑 密码: 123456
```

- 输入文件格式为
```
{"host":"43.163.194.245:54321","ip":"43.163.194.245","port":"54321"}
{"host":"23.105.208.54:54321","ip":"23.105.208.54","port":"54321"}
{"host":"14.22.83.130:54321","ip":"14.22.83.130","port":"54321"}
```

