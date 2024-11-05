package main

import (
	"fmt"
	"net/http"

	"github.com/AIntelligenceGame/gapi/auth"
	"github.com/AIntelligenceGame/gapi/login"
	"github.com/gin-gonic/gin"
)

// 自定一个需要被 鉴权 结构体
type UserLoginRequest struct {
	Email    string `json:"email,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password"`
}

func (r *UserLoginRequest) GetCredentials() map[string]interface{} {
	return map[string]interface{}{
		"email":    r.Email,
		"username": r.Username,
		"password": r.Password,
	}
}
func CustomAuthenticate(credentials map[string]interface{}) login.AuthResult {
	email := credentials["email"].(string)
	username := credentials["username"].(string)
	password := credentials["password"].(string)

	// 实际验证逻辑（比如数据库查询）
	if username == "" || email == "" || password != "password" {
		return login.AuthResult{IsAuthenticated: false, StatusCode: http.StatusNotFound, ErrorMessage: "User not found"}
	}
	return login.AuthResult{IsAuthenticated: true}
}

func main() {
	r := gin.Default()

	r.POST("/login", func(c *gin.Context) {
		req := &UserLoginRequest{}
		login.Login(c, req, CustomAuthenticate)
	})

	r.POST("/refresh", login.RefreshToken)

	// 受保护路由
	api := r.Group("/auth")
	api.Use(auth.AuthMiddleware())
	api.GET("/protected", func(c *gin.Context) {
		username, _ := c.Get("username")
		email, _ := c.Get("email")
		c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Hello %s (%s)", username.(string), email.(string))})
	})

	r.Run(":8080")
}
