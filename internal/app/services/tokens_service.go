package tokens

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type TokenService struct {
	db        *pgxpool.Pool
	jwtSecret []byte
	blacklist     map[string]time.Time
    blacklistMux  sync.RWMutex 
}

func (ts *TokenService) InvalidateToken(token string, expiry time.Time) {
    ts.blacklistMux.Lock()
    defer ts.blacklistMux.Unlock()
    ts.blacklist[token] = expiry
}

func (ts *TokenService) IsTokenInvalid(token string) bool {
    ts.blacklistMux.RLock()
    defer ts.blacklistMux.RUnlock()
    
    expiry, exists := ts.blacklist[token]
    if !exists {
        return false
    }
    
    if time.Now().After(expiry) {
        ts.blacklistMux.Lock()
        delete(ts.blacklist, token)
        ts.blacklistMux.Unlock()
        return false
    }
    
    return true
}

func NewTokenService(db *pgxpool.Pool, jwtSecret string) *TokenService {
	return &TokenService{
		db:        db,
		jwtSecret: []byte(jwtSecret),
	}
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshToken struct {
	UserID           string
	RefreshTokenHash string
	ClientIP         string
	CreatedAt        time.Time
}

func (ts *TokenService) GenerateAccessToken(userGUID, clientIP string) (string, error) {
	claims := jwt.MapClaims{
		"user_id":   userGUID,
		"client_ip": clientIP,
		"exp":       time.Now().Add(time.Minute * 15).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString(ts.jwtSecret)
}

func (ts *TokenService) GenerateRefreshToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(raw), nil
}

//Сохраняем рефреш в бд
func (ts *TokenService) StoreRefreshToken(userGUID, token, clientIP string, ctx context.Context) error {
	if _, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(token); err != nil {
		return fmt.Errorf("invalid base64 token: %w", err)
	}
	
	hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash token: %w", err)
	}
	
	_, err = ts.db.Exec(ctx,
		"INSERT INTO refresh_tokens (user_id, refresh_token_hash, client_ip, created_at) VALUES ($1, $2, $3, $4)",
		userGUID, hash, clientIP, time.Now(),
	)
	return err
}

//Проверяем рефреш
func (ts *TokenService) VerifyRefreshToken(userGUID, token, clientIP string, ctx context.Context) (bool, error) {
	if _, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(token); err != nil {
		return false, fmt.Errorf("invalid base64 format: %w", err)
	}
	
	var entry RefreshToken
	err := ts.db.QueryRow(ctx,
		`SELECT refresh_token_hash, client_ip 
		 FROM refresh_tokens 
		 WHERE user_id = $1 
		 ORDER BY created_at DESC LIMIT 1`,
		userGUID,
	).Scan(&entry.RefreshTokenHash, &entry.ClientIP)
	
	if err != nil {
		return false, fmt.Errorf("database error: %w", err)
	}
	
	if err := bcrypt.CompareHashAndPassword(
		[]byte(entry.RefreshTokenHash), 
		[]byte(token),
	); err != nil {
		return false, nil 
	}
	
	if entry.ClientIP != clientIP {
		log.Printf("Security warning: IP changed for user %s (%s -> %s)", 
			userGUID, entry.ClientIP, clientIP)
	}
	
	if _, err := ts.db.Exec(ctx,
		"DELETE FROM refresh_tokens WHERE user_id = $1 AND refresh_token_hash = $2",
		userGUID, entry.RefreshTokenHash,
	); err != nil {
		log.Printf("Failed to delete used token: %v", err)
	}
	
	return true, nil
}

//проверяем аксес
func (ts *TokenService) VerifyAccessToken(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("bad token algo")
		}
		return ts.jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return "", errors.New("unvalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("unvalid claims format")
	}

	claimUserID, ok := claims["user_id"].(string)
	if !ok {
		return "", errors.New("unvalid user_id")
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return "", errors.New("no exp")
	}

	if time.Now().Unix() > int64(exp) {
		return "", errors.New("yoken expired")
	}

	if ok = ts.IsTokenInvalid(tokenString); !ok {
		return "", errors.New("token is unvalid")
	}

	return claimUserID, nil
}

func (ts *TokenService) Delete(userGUID, access_token string, expiry time.Time, ctx context.Context) (error) {
	if _, err := ts.db.Exec(ctx, "DELETE FROM refresh_tokens WHERE user_id = $1", userGUID);
 	err != nil {
		log.Printf("Failed to delete refresh_token token: %v", err)
		return err
	}
	ts.InvalidateToken(access_token, expiry)


	return nil
}

