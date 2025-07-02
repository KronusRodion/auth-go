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

    err = database.InitDB(cfg.DatabaseURL)
	if err != nil {
        log.Fatal("Unable to load database:", err)
    }
    defer database.CloseDB()

    mux := routes.SetupRoutes(cfg.JWT)

	log.Println("Server starting on :80...")
	err = http.ListenAndServe(":80", mux)
	if err != nil {
		log.Fatal("Server error:", err)
	}
}