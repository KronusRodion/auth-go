package config

import (
    "github.com/joho/godotenv"
    "log"
    "os"
)

type Config struct {
	DatabaseURL string
	JWT string
    SecurityWebhookURL string `mapstructure:"SECURITY_WEBHOOK_URL"`
}

func LoadConfig() (*Config, error) {
	
    err := godotenv.Load()
    if err != nil {
        log.Printf("Warning: unable to load .env file: %v. Falling back to environment variables.", err)
    }

    databaseURL := os.Getenv("DATABASE_URL")
    jwt := os.Getenv("JWT")

    if databaseURL == "" {
        log.Fatal("DATABASE_URL is not set!")
    }

    if jwt == "" {
        log.Fatal("jwt is not set!")
    }


    return &Config{
        DatabaseURL: databaseURL,
        JWT: jwt,
	    }, nil
}