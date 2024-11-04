package main

import (
	"fmt"
	"net/http"

	"github.com/AIntelligenceGame/gapi/auth"
	"github.com/AIntelligenceGame/gapi/login"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	r.POST("/login", login.Login)
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
