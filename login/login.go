package login

import (
	"net/http"

	"github.com/AIntelligenceGame/gapi/auth"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// 认证结果和状态码
type AuthResult struct {
	IsAuthenticated bool
	StatusCode      int
	ErrorMessage    string
}

// 请求结构体接口
type LoginRequest interface {
	GetCredentials() map[string]interface{}
}

// 登录接口
func Login(c *gin.Context, req LoginRequest, validate func(credentials map[string]interface{}) AuthResult) {
	// 解析请求体
	if err := c.ShouldBindJSON(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// 获取请求字段
	credentials := req.GetCredentials()

	// 调用验证函数
	authResult := validate(credentials)
	if !authResult.IsAuthenticated {
		c.JSON(authResult.StatusCode, gin.H{"error": authResult.ErrorMessage})
		return
	}

	// 生成 Token
	token, err := auth.GenerateToken(credentials)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

// 刷新 Token
func RefreshToken(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Request does not contain an access token"})
		return
	}

	var claims auth.Claims
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return auth.JwtKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	newToken, err := auth.GenerateToken(claims.Data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate new token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": newToken})
}
