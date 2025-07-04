package middlewares

import (
	tokens "auth-go/internal/app/services"
	"log"
	"net/http"
)

type AuthMiddleware struct {
	tokenService *tokens.TokenService
}

func NewAuthMiddleware(tokenService *tokens.TokenService) *AuthMiddleware {
	return &AuthMiddleware{
		tokenService: tokenService,
	}
}

func (m *AuthMiddleware) Handler(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	
		accessString := r.FormValue("access_token")
		log.Println("accses token - ", accessString)
		
		if ok := m.tokenService.IsTokenInvalid(accessString); !ok {
			http.Error(w, "Token has been revoked", http.StatusUnauthorized)
			return
		}
		
		userID, err := m.tokenService.VerifyAccessToken(accessString)
		
		if err != nil || userID == "" {
			log.Println("Ошибка доступа - ", err, userID)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		
		next.ServeHTTP(w, r.WithContext(r.Context()))
	})
}