package handlers

import (
	"auth-go/internal/app/services"
	"encoding/json"
	"log"
	"net/http"
	"time"
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
	userGUID := r.FormValue("userGUID") 
	clientIP := r.RemoteAddr

	accessToken, err := h.tokenService.GenerateAccessToken(userGUID, clientIP)
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := h.tokenService.GenerateRefreshToken()
	if err != nil {
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	err = h.tokenService.StoreRefreshToken(userGUID, refreshToken, clientIP, r.Context())
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
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	
	refreshToken := r.FormValue("refresh_token")
	userGUID := r.FormValue("userGUID") 
	clientIP := getClientIP(r) 
	
	valid, err := h.tokenService.VerifyRefreshToken(userGUID, refreshToken, clientIP, r.Context())
	if err != nil || !valid{
		log.Printf("Token verification error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	newAccess, err := h.tokenService.GenerateAccessToken(userGUID, clientIP)
	if err != nil {
		http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}
	
	newRefresh, err := h.tokenService.GenerateRefreshToken()
	if err != nil {
		http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}
	
	if err := h.tokenService.StoreRefreshToken(userGUID, newRefresh, clientIP, r.Context()); err != nil {
		http.Error(w, "Failed to store token", http.StatusInternalServerError)
		return
	}
	
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  newAccess,
		"refresh_token": newRefresh,
	})
}


func (h *AuthHandler) GetGUID(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	
	access := r.FormValue("access_token")
	
	//Проверяем, но по факту просто достаем id из валидного токена
	user_GUID, err := h.tokenService.VerifyAccessToken(access)

	if err != nil {
		log.Printf("Access Token verification error: %v", err)
		http.Error(w, "Failed to validate token", http.StatusUnauthorized)
		return
	} else if user_GUID == "" {
		http.Error(w, "Failed to validate token", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"user_GUID":  user_GUID,
	})}




func (h *AuthHandler) DeAuthorization(w http.ResponseWriter, r *http.Request) {
	
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	
	access := r.FormValue("access_token")
	user_GUID, err := h.tokenService.VerifyAccessToken(access)

	if err != nil {
		log.Printf("Access Token verification error: %v", err)
		http.Error(w, "Failed to validate token", http.StatusUnauthorized)
		return
	} else if access == "" || user_GUID == "" {
		log.Println("Access Token verification error: empty resourses: ", access, user_GUID)
		http.Error(w, "Failed to validate token", http.StatusUnauthorized)
		return
	}


	h.tokenService.Delete(user_GUID, access, time.Now().Add(15 * time.Minute), r.Context())
}


func getClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}