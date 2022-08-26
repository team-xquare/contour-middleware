package jwt

import (
	"os"

	"github.com/dgrijalva/jwt-go"
)

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

type JWTClaims struct {
	Role        string   `json:"role"`
	Authorities []string `json:"authorities"`
	jwt.StandardClaims
}

func (c JWTClaims) ToJWTToken() string {
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	token, _ := at.SignedString([]byte(jwtSecret))

	return token
}

func ParseJWTToken(jwtToken string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(jwtToken, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}

	return token.Claims.(*JWTClaims), nil
}
