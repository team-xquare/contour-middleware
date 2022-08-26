package auth

import (
	"strings"

	"github.com/dgrijalva/jwt-go"
)

var jwtSecret = []byte("qwertyuiopoiuytrewq")

func GetJWTToken(request *Request) string {
	bearToken := request.Request.Header.Get("Authorization")
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}

	return ""
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
