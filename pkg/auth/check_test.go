package auth

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/dgrijalva/jwt-go"
)

func prepareCheckService() CheckService {
	l := logrus.New()
	check := NewCheckService(l)

	return check
}

func TestCheckWithoutJWTToken(t *testing.T) {
	ctx := context.Background()
	request := &Request{
		ID:      "100",
		Context: map[string]string{"k1": "v1", "k2": "v2"},
		Request: http.Request{
			Header: http.Header{"User-Agent": {"Foo"}},
			Method: "GET",
			Proto:  "HTTP/1.1",
			URL: &url.URL{
				Scheme:   "https",
				Host:     "example.com",
				Path:     "example",
				RawQuery: "query",
			},
		},
	}

	check := prepareCheckService()

	res, err := check.Check(ctx, request)
	assert.Equal(t, nil, err)
	assert.Equal(t, &Response{
		Allow: true,
		Response: http.Response{
			StatusCode: http.StatusOK,
		},
	}, res)
}

func TestCheckWithJWTToken(t *testing.T) {
	ctx := context.Background()

	atClaims := jwt.MapClaims{}
	atClaims["sub"] = "1"
	atClaims["authorities"] = []string{"auth-1", "auth-2", "auth-3"}
	atClaims["role"] = "STU"
	atClaims["exp"] = time.Now().Add(time.Minute * 15).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, _ := at.SignedString([]byte(jwtSecret))

	request := &Request{
		ID:      "100",
		Context: map[string]string{"k1": "v1", "k2": "v2"},
		Request: http.Request{
			Header: http.Header{"User-Agent": {"Foo"}, "Authorization": {"Bearer " + token}},
			Method: "GET",
			Proto:  "HTTP/1.1",
			URL: &url.URL{
				Scheme:   "https",
				Host:     "example.com",
				Path:     "example",
				RawQuery: "query",
			},
		},
	}

	check := prepareCheckService()

	res, err := check.Check(ctx, request)
	assert.Equal(t, nil, err)

	expect := &Response{
		Allow: true,
		Response: http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Request-User-Id":          {"1"},
				"Request-User-Role":        {"STU"},
				"Request-User-Authorities": {"auth-1", "auth-2", "auth-3"},
				"Request-Id":               {""},
			},
		},
	}
	assert.Equal(t, expect.Allow, res.Allow)
	assert.Equal(t, expect.Response.Header.Get("Request-User-Id"), res.Response.Header.Get("Request-User-Id"))
	assert.Equal(t, expect.Response.Header.Get("Request-User-Role"), res.Response.Header.Get("Request-User-Role"))
	assert.Equal(t, expect.Response.Header.Get("Request-User-Authorities"), res.Response.Header.Get("Request-User-Authorities"))
	assert.Equal(t, 36, len(res.Response.Header.Get("Request-Id")))
}

func TestCheckWithInvalidJWTToken(t *testing.T) {
	ctx := context.Background()

	atClaims := jwt.MapClaims{}
	atClaims["sub"] = "1"
	atClaims["authorities"] = []string{"auth-1", "auth-2", "auth-3"}
	atClaims["role"] = "STU"
	atClaims["exp"] = time.Now().Add(time.Minute * 15).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, _ := at.SignedString([]byte(""))

	request := &Request{
		ID:      "100",
		Context: map[string]string{"k1": "v1", "k2": "v2"},
		Request: http.Request{
			Header: http.Header{"User-Agent": {"Foo"}, "Authorization": {"Bearer " + token}},
			Method: "GET",
			Proto:  "HTTP/1.1",
			URL: &url.URL{
				Scheme:   "https",
				Host:     "example.com",
				Path:     "example",
				RawQuery: "query",
			},
		},
	}

	check := prepareCheckService()

	res, err := check.Check(ctx, request)
	_, ok := err.(*jwt.ValidationError)
	assert.True(t, ok)
	assert.Equal(t, &Response{
		Allow: false,
		Response: http.Response{
			StatusCode: http.StatusUnauthorized,
		},
	}, res)
}
