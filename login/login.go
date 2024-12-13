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
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request", "statusCode": http.StatusBadRequest})
		return
	}

	// 获取请求字段
	credentials := req.GetCredentials()

	// 调用验证函数
	authResult := validate(credentials)
	if !authResult.IsAuthenticated {
		c.JSON(authResult.StatusCode, gin.H{"error": authResult.ErrorMessage, "statusCode": authResult.StatusCode})
		return
	}

	// 生成 Token
	token, err := auth.GenerateToken(credentials)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token", "statusCode": http.StatusInternalServerError})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token, "statusCode": http.StatusOK})
}

// 刷新 Token
func RefreshToken(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Request does not contain an access token", "statusCode": http.StatusUnauthorized})
		return
	}
	var claims auth.Claims
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return auth.JwtKey, nil
	})

	// 如果 token 过期,则允许刷新
	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			// 如果是过期错误
			if ve.Errors&jwt.ValidationErrorExpired != 0 {
				// token 过期,可以生成新的 token
				newToken, err := auth.GenerateToken(claims.Data)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate new token", "statusCode": http.StatusInternalServerError})
					return
				}
				c.JSON(http.StatusOK, gin.H{"token": newToken, "statusCode": http.StatusOK})
				return
			}
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token" + err.Error(), "statusCode": http.StatusUnauthorized})
		return
	}

	// 如果token有效，则直接生成新的token
	if token.Valid {
		c.JSON(http.StatusOK, gin.H{"token": tokenString})
		return
	}

	// 如果没有有效的token
	c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
}
