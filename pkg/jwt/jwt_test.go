package jwt

import (
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func TestJWTToken(t *testing.T) {
	jwtClaims := &JWTClaims{Role: "STU", Authorities: []string{"학생"}, StandardClaims: jwt.StandardClaims{Subject: "kimxwan0319"}}
	token := jwtClaims.ToJWTToken()

	result, err := ParseJWTToken(token)
	assert.NoError(t, err)
	assert.Equal(t, jwtClaims, result)
}
