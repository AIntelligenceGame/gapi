package login

import (
	"net/http"

	"github.com/AIntelligenceGame/gapi/auth"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// 登录接口
func Login(c *gin.Context) {
	var creds struct {
		Email    string `json:"email,omitempty"`
		Username string `json:"username,omitempty"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// 这里使用硬编码的用户信息进行验证，实际中请替换为数据库查询
	// 验证逻辑，使用邮箱或用户名
	if (creds.Email == "" && creds.Username == "") || creds.Password != "password" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// 生成 Token
	token, err := auth.GenerateToken(creds.Email, creds.Username)
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

	claims := &auth.Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return auth.JwtKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	// 生成新的 Token，保留原有的用户名和邮箱
	newToken, err := auth.GenerateToken(claims.Username, claims.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": newToken})
}
