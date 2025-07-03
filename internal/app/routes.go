package routes

import (
	"auth-go/internal/app/handlers"
	"auth-go/internal/app/services"
	"auth-go/internal/database"
	"net/http"
	"auth-go/internal/app/middlewares"
)

func SetupRoutes(jwtSecret, webhookURL string) *http.ServeMux {
	mux := http.NewServeMux()
	authService := tokens.NewTokenService(database.DB, jwtSecret, webhookURL)
	authHandler := handlers.NewAuthHandler(authService)
	mux.HandleFunc("/getTokens", authHandler.GetTokens)
	mux.HandleFunc("/updateTokens", authHandler.UpdateTokens)

	//Миддлвар только для получение GUID и удаления токенов
	authMiddleware := middlewares.NewAuthMiddleware(authService)
	mux.Handle("/GetGUID", authMiddleware.Handler(http.HandlerFunc(authHandler.GetGUID)))
	mux.Handle("/DeAutharization", authMiddleware.Handler(http.HandlerFunc(authHandler.DeAuthorization)))

	return mux
}