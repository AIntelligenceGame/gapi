package valid

import (
	"regexp"

	"github.com/go-playground/validator/v10"
)

type Mail struct {
	Code  string `json:"code" validate:"required,numeric,len=6"` // 非空，必须是6位数字
	Email string `json:"email" validate:"required,email"`        // 非空，且为有效邮箱格式
}

// 定义一个 Validator 实例
var validate = validator.New()

// 使用正则表达式和自定义校验规则增加复杂度校验
func init() {
	// 注册自定义的 "is6digits" 校验规则
	validate.RegisterValidation("is6digits", func(fl validator.FieldLevel) bool {
		code := fl.Field().String()
		// 6位数字的正则表达式
		var codeRegex = `^\d{6}$`
		matched, _ := regexp.MatchString(codeRegex, code)
		return matched
	})
}

// 验证函数，方便在创建用户或更新用户前进行校验
func (u *Mail) Validate() error {
	return validate.Struct(u)
}
