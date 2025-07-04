package tokens

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

var base64Encoder = base64.URLEncoding.WithPadding(base64.NoPadding)


type TokenService struct {
	db        *pgxpool.Pool
	jwtSecret []byte
	blacklist     map[string]time.Time
    blacklistMux  sync.RWMutex
	SecurityWebhookURL string
}

func (ts *TokenService) InvalidateToken(token string, expiry time.Time) {
    ts.blacklistMux.Lock()
    defer ts.blacklistMux.Unlock()
    ts.blacklist[token] = expiry
	log.Println("Заносим в мапу токен - ", token)
}

func (ts *TokenService) IsTokenInvalid(token string) bool {
    ts.blacklistMux.RLock()
    defer ts.blacklistMux.RUnlock()
    
    expiry, exists := ts.blacklist[token]
    if !exists {
        return true
    }
    
    if time.Now().After(expiry) {
        ts.blacklistMux.Lock()
        delete(ts.blacklist, token)
        ts.blacklistMux.Unlock()
        return false
    }
    
    return false
}

func NewTokenService(db *pgxpool.Pool, jwtSecret, webhookURL string) *TokenService {
	return &TokenService{
		db:                db,
		jwtSecret:         []byte(jwtSecret),
		blacklist:         make(map[string]time.Time),
		blacklistMux:      sync.RWMutex{},
		SecurityWebhookURL: webhookURL,
	}
}


type RefreshToken struct {
	UserID           string
	RefreshTokenHash string
	ClientIP         string
	CreatedAt        time.Time
	UserAgent        string
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
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(raw), nil
}

//Сохраняем рефреш в бд
func (ts *TokenService) StoreRefreshToken(userGUID, token, clientIP, userAgent string, ctx context.Context) error {
    
    hash, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
    if err != nil {
        log.Printf("Ошибка генерации хеша: %v", err)
        return fmt.Errorf("failed to hash token: %w", err)
    }
    
    hashBase64 := base64Encoder.EncodeToString(hash)
    
    _, err = ts.db.Exec(ctx,
        "INSERT INTO refresh_tokens (user_id, refresh_token_hash, client_ip, created_at, user_agent) VALUES ($1, $2, $3, $4, $5)",
        userGUID, hashBase64, clientIP, time.Now(), userAgent,
    )
    
    return err
}

//чек рефреш-токен
func (ts *TokenService) VerifyRefreshToken(userGUID, token, clientIP, userAgent string, ctx context.Context) (bool, error) {
    
    // Получаем все refresh-токены пользователя
    rows, err := ts.db.Query(ctx,
        `SELECT refresh_token_hash, client_ip, user_agent 
         FROM refresh_tokens 
         WHERE user_id = $1`,
        userGUID,
    )
    if err != nil {
        log.Printf("Ошибка запроса токенов из БД: %v", err)
        return false, fmt.Errorf("database error: %w", err)
    }
    defer rows.Close()

    var validToken struct {
        RefreshTokenHash string
        ClientIP         string
        UserAgent        string
    }
    found := false
    tokenCount := 0

    for rows.Next() {
        tokenCount++
        var storedHash string
        if err := rows.Scan(&storedHash, &validToken.ClientIP, &validToken.UserAgent); err != nil {
            log.Printf("Ошибка сканирования токена #%d: %v", tokenCount, err)
            continue
        }

        log.Printf("Токен #%d из БД: %s", tokenCount, storedHash)

        hashBytes, err := base64Encoder.DecodeString(storedHash)
        if err != nil {
            log.Printf("Ошибка декодирования хеша токена #%d: %v", tokenCount, err)
            continue
        }

        err = bcrypt.CompareHashAndPassword(hashBytes, []byte(token))
        
        if err == nil {
            validToken.RefreshTokenHash = storedHash
            found = true
            break
        }
    }


    if !found {
        log.Println("Не найден подходящий токен")
        return false, errors.New("refresh token not found")
    }

    if validToken.UserAgent != userAgent {
        log.Printf("Security warning: user agent changed for user %s (%s -> %s)", 
            userGUID, validToken.UserAgent, userAgent)
        return false, errors.New("different user agent")
    }

    if validToken.ClientIP != clientIP {
        log.Printf("Security warning: IP changed for user %s (%s -> %s)", 
            userGUID, validToken.ClientIP, clientIP)
        ts.notifyIPChange(userGUID, validToken.ClientIP, clientIP)
    }

    // Удаление использованного токена
    log.Printf("Удаляем токен: %s", validToken.RefreshTokenHash)
    if _, err := ts.db.Exec(ctx,
        "DELETE FROM refresh_tokens WHERE refresh_token_hash = $1",
        validToken.RefreshTokenHash,
    ); err != nil {
        log.Printf("Ошибка удаления токена: %v", err)
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



func (ts *TokenService) notifyIPChange(userGUID, oldIP, newIP string) {
    if ts.SecurityWebhookURL == "" {
        return
    }

    payload := map[string]interface{}{
        "event_type":    "ip_change",
        "user_id":       userGUID,
        "previous_ip":   oldIP,
        "current_ip":    newIP,
        "timestamp":    time.Now().UTC().Format(time.RFC3339),
    }

    jsonData, err := json.Marshal(payload)
    if err != nil {
        log.Printf("Failed to marshal webhook payload: %v", err)
        return
    }

    resp, err := http.Post(
        ts.SecurityWebhookURL,
        "application/json",
        bytes.NewBuffer(jsonData),
    )
    
    if err != nil {
        log.Printf("Webhook send error: %v", err)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode >= 300 {
        log.Printf("Webhook responded with status %d", resp.StatusCode)
    }
}
