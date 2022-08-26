package auth

import (
	"context"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type CheckService interface {
	Check(context.Context, *Request) (*Response, error)
}

type checkService struct {
	log *logrus.Logger
}

func NewCheckService(l *logrus.Logger) CheckService {
	return &checkService{
		log: l,
	}
}

func (c *checkService) Check(ctx context.Context, request *Request) (*Response, error) {
	c.log.Infof("checking request host: %s, path:%s, id: %s",
		request.Request.URL.Host,
		request.Request.URL.Path,
		request.ID,
	)

	jwtToken := GetJWTToken(request)
	if len(jwtToken) == 0 {
		return c.responseOKWithoutHeader(), nil
	}

	header, err := c.createHeaderFromJWTToken(jwtToken)
	if err != nil {
		if _, ok := err.(*jwt.ValidationError); ok {
			return c.responseUnauthorizedError(err), err
		}
		return c.responseInternelServerError(err), err
	}

	return c.responseOKWithHeader(header), nil
}

func (c *checkService) createHeaderFromJWTToken(jwtToken string) (http.Header, error) {
	var headers = make(http.Header)

	claims, err := ParseJWTToken(jwtToken)
	if err != nil {
		return nil, err
	}

	headers.Add("Request-User-Id", claims.Subject)
	headers.Add("Request-User-Role", claims.Role)
	for _, v := range claims.Authorities {
		headers.Add("Request-User-Authorities", v)
	}
	headers.Add("Request-Id", c.getRequestId())

	return headers, nil
}

func (c *checkService) getRequestId() string {
	return uuid.NewString()
}

func (c *checkService) responseInternelServerError(err error) *Response {
	c.log.Error(err)
	return &Response{
		Allow: false,
		Response: http.Response{
			StatusCode: http.StatusInternalServerError,
		},
	}
}

func (c *checkService) responseUnauthorizedError(err error) *Response {
	c.log.Info(err)
	return &Response{
		Allow: false,
		Response: http.Response{
			StatusCode: http.StatusUnauthorized,
		},
	}
}

func (c *checkService) responseOKWithoutHeader() *Response {
	return &Response{
		Allow: true,
		Response: http.Response{
			StatusCode: http.StatusOK,
		},
	}
}

func (c *checkService) responseOKWithHeader(header http.Header) *Response {
	response := &Response{
		Allow: true,
		Response: http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{},
		},
	}

	for key, values := range header {
		for i := 0; i < len(values); i++ {
			response.Response.Header.Add(key, values[i])
		}
	}

	return response
}
