package jwt

import (
	"strings"

	"github.com/dgrijalva/jwt-go"
)

var jwtSecret = []byte("qwertyuiopoiuytrewq")

type ValidationError = jwt.ValidationError

func GetJWTToken(token string) string {
	bearToken := token
	strArr := strings.Split(bearToken, " ")
	if len(strArr) != 2 {
		return ""
	}

	return strArr[1]
}

type JWTClaims struct {
	Role        string   `json:"role"`
	Authorities []string `json:"authorities"`
	jwt.StandardClaims
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
