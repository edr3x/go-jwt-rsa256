package tokenize

import (
	"crypto/rsa"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
	expirationTime := time.Now().Add(20 * time.Second)

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

func VerifyToken(tokenType TokenType, tokenString string) (*UserInfo, error) {
	clms := TokenClaims{}
	token, _ := jwt.ParseWithClaims(tokenString, &clms, func(tkn *jwt.Token) (any, error) {
		if tkn.Method != jwt.SigningMethodRS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", tkn.Header["alg"])
		}
		return verifyKey, nil
	})

	if clms.Type != tokenType {
		return nil, fmt.Errorf("invalid token type")
	}

	if time.Now().After(clms.ExpiresAt.Time) {
		return nil, fmt.Errorf("token expired")
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return &clms.UserInfo, nil
}
