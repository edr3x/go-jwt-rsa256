package tokenize

import (
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/golang-jwt/jwt/v5/request"
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)

type TokenType string

const (
	Access  TokenType = "access"
	Refresh TokenType = "refresh"
)

type UserInfo struct {
	Id string `json:"user_id"`
}

type TokenClaims struct {
	Type TokenType `json:"token_type"`
	jwt.RegisteredClaims
	UserInfo
}

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func init() {
	signKeyByte, err := os.ReadFile("internal/tokenize/keys/app.rsa")
	fatal(err)

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signKeyByte)
	fatal(err)

	verifyKeyByte, err := os.ReadFile("internal/tokenize/keys/app.rsa.pub")
	fatal(err)

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyKeyByte)
	fatal(err)
}

func Generate(tokenType TokenType, userId string) (string, error) {
	expirationTime := time.Now().Add(5 * time.Minute)

	t := jwt.New(jwt.SigningMethodRS256)

	t.Claims = &TokenClaims{
		tokenType,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
		UserInfo{
			Id: userId,
		},
	}
	return t.SignedString(signKey)
}

func VerifyToken(r *http.Request) (info UserInfo, err error) {
	clms := &TokenClaims{}

	token, err := request.ParseFromRequest(r, request.OAuth2Extractor, func(tkn *jwt.Token) (any, error) {
		return verifyKey, nil
	}, request.WithClaims(clms))
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return info, fmt.Errorf("invalid token signature")
		}
		if time.Now().After(clms.ExpiresAt.Time) {
			return info, fmt.Errorf("token expired")
		}
		return info, fmt.Errorf("bad token provided")
	}
	if !token.Valid {
		return info, fmt.Errorf("invalid token")
	}
	return clms.UserInfo, nil
}
