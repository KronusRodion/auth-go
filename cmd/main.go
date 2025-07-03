package main

import (
	routes "auth-go/internal/app"
	"auth-go/internal/config"
	"auth-go/internal/database"
	"log"
	"net/http"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal("Unable to load config:", err)
	}

	err = database.Init(cfg.DatabaseURL)
	if err != nil {
		log.Fatal("Unable to load database:", err)
	}
	defer database.CloseDB()

	//Убрать чтобы ключ подгружался из конфига
	// jwtkey := cfg.JWT
	jwtkey := "JWTkey"

	mux := routes.SetupRoutes(jwtkey, cfg.SecurityWebhookURL)

	log.Println("Server starting on :80...")
	err = http.ListenAndServe(":80", mux)
	if err != nil {
		log.Fatal("Server error:", err)
	}
}
