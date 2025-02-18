package mail

import (
	"fmt"

	"crypto/tls"

	"gopkg.in/gomail.v2"
)

// SMTPConfig 结构体包含 SMTP 服务器的配置信息
type SMTPConfig struct {
	Host string
	Port int
	User string
	Auth string
	Addr string
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
	m.SetBody("text/html", fmt.Sprintf("【验证码】:<i>%s</i>", params.Code))

	// 创建邮件发送器，配置 SMTP 服务器
	d := gomail.NewDialer(params.SMTPInfo.Host, params.SMTPInfo.Port, params.SMTPInfo.User, params.SMTPInfo.Auth)
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true} // 跳过证书验证（仅用于开发环境）

	// 发送邮件
	if err := d.DialAndSend(m); err != nil {
		return fmt.Errorf("发送邮箱失败: %v", err)
	}
	return nil
}
