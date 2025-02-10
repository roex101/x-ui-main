package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	logFile     *os.File
	tgBotToken  string
	tgChannelID string
)

func main() {
	// 初始化配置
	tgBotToken = os.Getenv("TG_BOT_TOKEN")
	tgChannelID = os.Getenv("TG_CHANNEL_ID")
	if tgBotToken == "" || tgChannelID == "" {
		log.Fatal("必须设置环境变量: TG_BOT_TOKEN 和 TG_CHANNEL_ID")
	}

	// 初始化日志
	initLogSystem()
	defer logFile.Close()

	// 启动服务
	go startHTTPSServer()
	startHTTPServer()
}

func initLogSystem() {
	var err error
	logFile, err = os.OpenFile("/var/log/honeypot.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal("日志系统初始化失败: ", err)
	}
	log.SetOutput(io.MultiWriter(os.Stdout, logFile))
}

// ========================
// HTTP/HTTPS 代理核心逻辑
// ========================

func handleRequest(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	clientIP := extractClientIP(r)

	defer func() {
		log.Printf("请求处理完成 客户端: %s 耗时: %v", clientIP, time.Since(startTime))
	}()

	if r.Method == http.MethodConnect {
		handleHTTPSProxy(w, r)
	} else {
		handleHTTPProxy(w, r)
	}
}

func handleHTTPProxy(w http.ResponseWriter, r *http.Request) {
	// 解析目标URL
	targetURL, err := url.ParseRequestURI(r.RequestURI)
	if err != nil {
		http.Error(w, "无效的请求URL", http.StatusBadRequest)
		return
	}

	// 修改请求头
	r.URL.Scheme = "http"
	if targetURL.Scheme == "https" {
		r.URL.Scheme = "https"
	}
	r.URL.Host = targetURL.Host
	r.RequestURI = ""

	// 记录访问日志
	logAccess(r.RemoteAddr, targetURL.Host)

	// 转发请求
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 复制响应头
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	// 复制响应体
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("响应传输错误: %v", err)
	}
}

func handleHTTPSProxy(w http.ResponseWriter, r *http.Request) {
	// 建立目标连接
	target := r.URL.Host
	if !strings.Contains(target, ":") {
		target += ":443"
	}

	// 记录访问日志
	logAccess(r.RemoteAddr, target)

	// 连接目标服务器
	dstConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		http.Error(w, "无法连接目标服务器", http.StatusServiceUnavailable)
		return
	}
	defer dstConn.Close()

	// 劫持客户端连接
	w.WriteHeader(http.StatusOK)
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "连接劫持不支持", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, "连接劫持失败", http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// 启动双向数据传输
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go tunnelConnection(ctx, clientConn, dstConn)
	go tunnelConnection(ctx, dstConn, clientConn)

	<-ctx.Done()
}

// ========================
// 工具函数
// ========================

func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.Split(xff, ",")[0]
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func tunnelConnection(ctx context.Context, dst net.Conn, src net.Conn) {
	defer dst.Close()
	defer src.Close()

	_, err := io.Copy(dst, src)
	if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		log.Printf("隧道传输错误: %v", err)
	}
}

// ========================
// 日志和通知系统
// ========================

func logAccess(clientAddr, target string) {
	clientIP := extractClientIP(&http.Request{RemoteAddr: clientAddr})
	logEntry := fmt.Sprintf(
		"<b>[%s]</b>\n🌐 代理活动检测\n├ 客户端: <code>%s</code>\n└ 目标: <code>%s</code>",
		time.Now().Format("2006-01-02 15:04:05"),
		clientIP,
		target,
	)

	// 本地日志
	logFile.WriteString(fmt.Sprintf("[%s] %s -> %s\n",
		time.Now().Format(time.RFC3339),
		clientIP,
		target))

	// 异步推送
	go func(entry string) {
		retries := 0
		for retries < 3 {
			if err := sendTelegram(entry); err == nil {
				return
			}
			retries++
			time.Sleep(2 * time.Second)
		}
		log.Printf("Telegram推送失败: %s", logEntry)
	}(logEntry)
}

func sendTelegram(message string) error {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", tgBotToken)
	payload := map[string]string{
		"chat_id":    tgChannelID,
		"text":       message,
		"parse_mode": "HTML",
	}

	jsonData, _ := json.Marshal(payload)
	resp, err := http.Post(apiURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API响应错误: %s", resp.Status)
	}
	return nil
}

// ========================
// 服务启动
// ========================

func startHTTPSServer() {
	// 加载SSL证书
	cert, err := tls.LoadX509KeyPair("/etc/ssl/certs/fullchain.pem", "/etc/ssl/private/privkey.pem")
	if err != nil {
		log.Fatal("SSL证书加载失败: ", err)
	}

	server := &http.Server{
		Addr:    ":443",
		Handler: http.HandlerFunc(handleRequest),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	log.Println("HTTPS代理服务已启动 :443")
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatal("HTTPS服务启动失败: ", err)
	}
}

func startHTTPServer() {
	server := &http.Server{
		Addr:    ":80",
		Handler: http.HandlerFunc(handleRequest),
	}

	log.Println("HTTP代理服务已启动 :80")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal("HTTP服务启动失败: ", err)
	}
}
