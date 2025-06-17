package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"SaijaiTech_back/api/models"
	"SaijaiTech_back/api/routes"

	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	// Load .env variables
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_PORT"),
	)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		fmt.Println("❌ Error connecting to the database:", err)
		return
	}

	fmt.Println("✅ Connected to the database successfully!")

	// Migrate schema
	db.AutoMigrate(&models.User{})

	// Get JWT secret from environment (add this to your .env file)
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "your-default-secret-key" // Change this in production!
		fmt.Println("⚠️  Warning: Using default JWT secret. Set JWT_SECRET in .env file for production!")
	}

	// Setup routes
	routes.SetupRoutes(db, jwtSecret)

	// Get port from environment or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Start server
	fmt.Printf("Server starting on port %s\n", port)
	fmt.Println("API Endpoints:")
	fmt.Println("  POST /api/auth/register - Register new user")
	fmt.Println("  POST /api/auth/login    - Login user")

	log.Fatal(http.ListenAndServe(":"+port, nil))
}
