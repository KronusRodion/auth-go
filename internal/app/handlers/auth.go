package handlers

import (
	"auth-go/internal/app/services"
	"encoding/json"
	"net/http"
)

type AuthHandler struct {
	tokenService *tokens.TokenService
}

func NewAuthHandler(tokenService *tokens.TokenService) *AuthHandler {
	return &AuthHandler{
		tokenService: tokenService,
	}
}

func (h *AuthHandler) GetTokens(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("userID")
	clientIP := r.RemoteAddr

	accessToken, err := h.tokenService.GenerateAccessToken(userID, clientIP)
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := h.tokenService.GenerateRefreshToken()
	if err != nil {
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	err = h.tokenService.StoreRefreshToken(userID, refreshToken, clientIP, r.Context())
	if err != nil {
		http.Error(w, "Failed to store refresh token", http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *AuthHandler) UpdateTokens(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.FormValue("refresh_token")
	userID := r.URL.Query().Get("userID")
	clientIP := r.RemoteAddr

	valid, err := h.tokenService.VerifyRefreshToken(userID, refreshToken, clientIP, r.Context())
	if err != nil || !valid {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	refreshToken, err = h.tokenService.GenerateRefreshToken()
	if err != nil {
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	accessToken, err := h.tokenService.GenerateAccessToken(userID, clientIP)
	if err != nil {
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	err = h.tokenService.StoreRefreshToken(userID, refreshToken, clientIP, r.Context())
	if err != nil {
		http.Error(w, "Failed to store refresh token", http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *AuthHandler) GetGUID(w http.ResponseWriter, r *http.Request) {
}

func (h *AuthHandler) DeAuthorization(w http.ResponseWriter, r *http.Request) {

}


