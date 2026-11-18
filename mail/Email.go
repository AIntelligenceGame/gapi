package mail

import (
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

	// 邮件正文内容
	m.SetBody("text/html", fmt.Sprintf("[验证码]: <i>%s</i>", params.Code))

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
