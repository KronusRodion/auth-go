package routes

import (
	"auth-go/internal/app/handlers"
	"auth-go/internal/app/services"
	"auth-go/internal/database"
	"net/http"
	"auth-go/internal/app/middlewares"
)

func SetupRoutes(jwtSecret string) *http.ServeMux {
	mux := http.NewServeMux()
	authService := tokens.NewTokenService(database.DB, jwtSecret)
	authHandler := handlers.NewAuthHandler(authService)
	mux.HandleFunc("/getTokens", authHandler.GetTokens)
	mux.HandleFunc("/updateTokens", authHandler.UpdateTokens)
	mux.HandleFunc("/DeAutharization", authHandler.DeAuthorization)

	//Миддлвар только для получение GUID
	authMiddleware := middlewares.NewAuthMiddleware(authService)
	mux.Handle("/GetGUID", authMiddleware.Handler(http.HandlerFunc(authHandler.GetGUID)))

	return mux
}