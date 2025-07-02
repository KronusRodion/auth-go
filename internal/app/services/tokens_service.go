package tokens

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"time"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type TokenService struct {
	db        *pgxpool.Pool
	jwtSecret []byte
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

func (ts *TokenService) GenerateAccessToken(userID, clientIP string) (string, error) {
	claims := jwt.MapClaims{
		"user_id":   userID,
		"client_ip": clientIP,
		"exp":       time.Now().Add(time.Minute * 15).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString(ts.jwtSecret)
}

func (ts *TokenService) GenerateRefreshToken() (string, error) {
	raw := make([]byte, 32)
	_, err := rand.Read(raw)
	if err != nil {
		return "", err
	}
	hash := sha512.Sum512(raw)
	return base64.URLEncoding.EncodeToString(hash[:]), nil
}

func (ts *TokenService) StoreRefreshToken(userID, token, clientIP string, ctx context.Context) error {
	trimmedToken := token[:72]
	hash, err := bcrypt.GenerateFromPassword([]byte(trimmedToken), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing refresh token: %v", err)
		return err
	}

	_, err = ts.db.Exec(ctx,
		"INSERT INTO refresh_tokens (user_id, refresh_token_hash, client_ip, created_at) VALUES ($1, $2, $3, $4)",
		userID, hash, clientIP, time.Now(),
	)
	if err != nil {
		log.Printf("Error executing INSERT: %v", err)
		return err
	}

	return nil
}

func (ts *TokenService) VerifyRefreshToken(userID, token, clientIP string, ctx context.Context) (bool, error) {
	var entry RefreshToken
	err := ts.db.QueryRow(ctx,
		"SELECT refresh_token_hash, client_ip FROM refresh_tokens WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1",
		userID,
	).Scan(&entry.RefreshTokenHash, &entry.ClientIP)
	if err != nil {
		return false, fmt.Errorf("database error: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(entry.RefreshTokenHash), []byte(token)); err != nil {
		return false, errors.New("invalid refresh token")
	}

	if entry.ClientIP != clientIP {
		log.Printf("Warning: IP address changed for user %s from %s to %s", userID, entry.ClientIP, clientIP)
	}

	_, err = ts.db.Exec(ctx,
		"DELETE FROM refresh_tokens WHERE user_id = $1 AND refresh_token_hash = $2",
		userID, entry.RefreshTokenHash,
	)
	if err != nil {
		return false, fmt.Errorf("failed to delete used refresh token: %w", err)
	}

	return true, nil
}