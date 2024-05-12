package tokenize

import (
	"crypto/rsa"
	"encoding/base64"
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
	/*
	   To generate private key
	   $ openssl genrsa -out app.rsa 1024

	   encode generated rsa to bas64
	   $ cat app.rsa | base64

	   When working with Hashicorp Vault wrap the new lines into single one
	   as it doesn't support multi line string
	   $ cat app.rsa | base64 -w0 >> .env
	*/
	pvtKey, ok := os.LookupEnv("RSA_PRIVATE_KEY")
	if !ok {
		log.Fatal("RSA_PRIVATE_KEY not provided")
	}
	signKeyByte, err := base64.StdEncoding.DecodeString(pvtKey)
	fatal(err)

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signKeyByte)
	fatal(err)

	/*
	   To generate public key from private key
	   $ openssl rsa -in app.rsa -pubout > app.rsa.pub

	   encode generated rsa to bas64
	   $ cat app.rsa.pub | base64

	   When working with Hashicorp Vault wrap the new lines into single one
	   as it doesn't support multi line string
	   $ cat app.rsa | base64 -w0 >> .env
	*/
	publicKey, ok := os.LookupEnv("RSA_PUBLIC_KEY")
	if !ok {
		log.Fatal("RSA_PUBLIC_KEY not provided")
	}
	verifyKeyByte, err := base64.StdEncoding.DecodeString(publicKey)
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
	token, _ := jwt.ParseWithClaims(tokenString, &clms, func(_ *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	if token.Method != jwt.SigningMethodRS256 {
		return nil, fmt.Errorf("invalid signing method")
	}

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
