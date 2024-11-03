package auth

import (
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var JwtKey = []byte("your_secret_key")

// Claims 是JWT的有效负载
type Claims struct {
	Email    string `json:"email,omitempty"`
	Username string `json:"username,omitempty"`
	jwt.StandardClaims
}

// 生成 Token
func GenerateToken(email, username string) (string, error) {
	expirationTime := time.Now().Add(15 * time.Minute)
	claims := &Claims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	if email != "" {
		claims.Email = email
	}
	if username != "" {
		claims.Username = username
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(JwtKey)
}

// 验证 Token 的中间件
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Request does not contain an access token"})
			c.Abort()
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return JwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// 根据需要设置上下文
		if claims.Email != "" {
			c.Set("email", claims.Email)
		}
		if claims.Username != "" {
			c.Set("username", claims.Username)
		}

		c.Next()
	}
}
