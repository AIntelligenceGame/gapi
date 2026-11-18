package mail

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"crypto/tls"
	"net"
	"net/smtp"
	"time"

	"gopkg.in/gomail.v2"
)

// SMTPConfig 结构体包含 SMTP 服务器的配置信息
type SMTPConfig struct {
	Host string
	Port int
	User string
	Auth string
	Addr string
	// TLSMode 加密方式(可留空,留空按 gomail 默认:465 走隐式 TLS,其余端口自动尝试 STARTTLS):
	//
	//	"starttls" —— 明文握手后升级加密(QQ 587 / 163 25);
	//	"tls"     —— 隐式 TLS,连接即加密(QQ/163 465);
	//	"none"    —— 不强制加密(仅内网自建服务器)。
	TLSMode string
	// TLSConfig 自定义 TLS 配置(如指定证书校验策略)。
	//
	// 为 nil 时保持历史行为(不校验服务器证书);
	// 需要校验证书时传 &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}。
	TLSConfig *tls.Config
}

// EmailParams 结构体包含发送邮件所需的参数
type EmailParams struct {
	To       string
	Code     string
	Name     string
	Value    string
	SMTPInfo SMTPConfig
}

// 函数：发送邮件
func Email(params EmailParams) error {
	m := gomail.NewMessage()
	// 设置发件人，显示公司名称而非邮箱地址
	m.SetAddressHeader("From", params.SMTPInfo.Addr, params.Name) // 替换成你的发件人名称和邮箱
	m.SetHeader("To", params.To)
	m.SetHeader("Subject", params.Value)

	// 补 Message-ID。
	//
	// gomail 只会自动补 Mime-Version 和 Date,**不会**生成 Message-ID,
	// 而 RFC 5322 要求每封邮件都有唯一的 Message-ID。
	// 网易 163 这类收件方对缺少 Message-ID 的邮件是**静默丢弃**:
	// SMTP 那边照样回「250 已入队」,发件人以为发出去了,收件人就是收不到。
	// 发件地址里的域名拿来做 Message-ID 的域部分。
	if len(m.GetHeader("Message-ID")) == 0 {
		m.SetHeader("Message-ID", generateMessageID(params.SMTPInfo.Addr))
	}

	// 邮件正文内容。
	//
	// 用 plain 优先的 multipart/alternative(text/plain 在前、text/html 在后):
	//
	//   - 很多收件方(网易 163 尤其明显)把「只有 text/html、没有纯文本兜底」的邮件
	//     当成可疑内容,轻则进垃圾箱、重则直接丢弃;
	//   - 正文写成完整中文句子,而不是一行 "[验证码]: 246813"。
	//     QQ 的出站内容审核对「短到没有自然语言 + 纯数字」的报文有直接丢弃的先例,
	//     同样的正文发到 QQ 自己能收到,发到别的域就没了。
	plain := fmt.Sprintf("您正在使用%s进行身份验证。\n\n验证码:%s\n\n验证码仅用于本次操作,10 分钟内有效,请勿告知他人。\n如非本人操作,请忽略本邮件。", params.Name, params.Code)
	html := fmt.Sprintf(`<p>您正在使用%s进行身份验证。</p>`+
		`<p>验证码:<strong style="font-size:20px;">%s</strong></p>`+
		`<p>验证码仅用于本次操作,10 分钟内有效,请勿告知他人。</p>`+
		`<p>如非本人操作,请忽略本邮件。</p>`, params.Name, params.Code)
	m.SetBody("text/plain", plain)
	m.AddAlternative("text/html", html)

	// 创建邮件发送器，配置 SMTP 服务器
	d := gomail.NewDialer(params.SMTPInfo.Host, params.SMTPInfo.Port, params.SMTPInfo.User, params.SMTPInfo.Auth)

	// 加密方式:gomail 默认 port==465 走隐式 TLS,其余端口自动尝试 STARTTLS。
	// 这里按显式配置覆盖,让调用方(支付平台)能精确控制通道。
	switch strings.ToLower(strings.TrimSpace(params.SMTPInfo.TLSMode)) {
	case "tls", "ssl", "implicit":
		d.SSL = true
	case "none", "off", "plain":
		d.SSL = false
	}

	// TLS 配置:调用方显式指定就用它的;没指定则保持历史行为(不校验证书)。
	if params.SMTPInfo.TLSConfig != nil {
		d.TLSConfig = params.SMTPInfo.TLSConfig
	} else {
		d.TLSConfig = &tls.Config{InsecureSkipVerify: true} // 跳过证书验证（仅用于开发环境）
	}

	// starttls 模式下要求服务器必须支持 STARTTLS:
	// gomail 在服务器不支持时会静默走明文,验证码就这么裸奔出去了。
	if strings.EqualFold(strings.TrimSpace(params.SMTPInfo.TLSMode), "starttls") {
		if err := requireSTARTTLS(params.SMTPInfo.Host, params.SMTPInfo.Port); err != nil {
			return err
		}
	}

	// 发送邮件
	if err := d.DialAndSend(m); err != nil {
		return fmt.Errorf("发送邮箱失败: %v", err)
	}
	return nil
}

// generateMessageID 生成一封邮件的唯一标识,形如 <1752880000.a1b2c3d4e5f6@qq.com>。
//
// 域部分取发件地址的域名(没有就退回 localhost);
// 左半部分用「秒级时间戳 + 随机十六进制」,保证并发发送时也不会重复。
func generateMessageID(from string) string {
	domain := "localhost"
	if i := strings.LastIndex(from, "@"); i >= 0 && i < len(from)-1 {
		domain = from[i+1:]
	}
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// 随机数拿不到也要有个能用的 ID:用纳秒时间戳顶上。
		return fmt.Sprintf("<%d@%s>", time.Now().UnixNano(), domain)
	}
	return fmt.Sprintf("<%d.%s@%s>", time.Now().Unix(), hex.EncodeToString(buf[:]), domain)
}

// requireSTARTTLS 探测 SMTP 服务器是否支持 STARTTLS 扩展。
//
// 只在 starttls 模式下调用:服务器不支持时宁可报错,也不能悄悄明文把验证码发出去。
func requireSTARTTLS(host string, port int) error {
	if port <= 0 {
		port = 587
	}
	addr := net.JoinHostPort(host, fmt.Sprint(port))
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("连接 SMTP 服务器 %s 失败: %v", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("SMTP 握手失败: %v", err)
	}
	defer func() { _ = client.Close() }()
	if ok, _ := client.Extension("STARTTLS"); !ok {
		return fmt.Errorf("SMTP 服务器 %s 不支持 STARTTLS;"+
			"可改用 465 端口(隐式 TLS),或把加密方式改成「不加密」", addr)
	}
	return nil
}
