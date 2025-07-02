package routes

import (
	"auth-go/internal/app/handlers"
	tokens "auth-go/internal/app/services"
	"auth-go/internal/database"
	"net/http"
)

func SetupRoutes(jwtSecret string) *http.ServeMux {
	mux := http.NewServeMux()
	authService := tokens.NewTokenService(database.DB, jwtSecret)
	authHandler := handlers.NewAuthHandler(authService)
	mux.HandleFunc("/getTokens", authHandler.GetTokens)
	mux.HandleFunc("/updateTokens", authHandler.UpdateTokens)
	mux.HandleFunc("/GetGUID", authHandler.GetGUID)
	mux.HandleFunc("/DeAutharization", authHandler.DeAuthorization)

	return mux
}