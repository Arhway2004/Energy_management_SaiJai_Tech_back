package routes

import (
	"net/http"
	"SaijaiTech_back/api/handlers"
	"gorm.io/gorm"
)

// SetupRoutes configures all API routes
func SetupRoutes(db *gorm.DB, jwtSecret string) {
	// Initialize auth handler
	authHandler := handlers.NewAuthHandler(db, jwtSecret)

	// Auth routes
	http.HandleFunc("/api/auth/register", authHandler.Register)
	http.HandleFunc("/api/auth/login", authHandler.Login)

}