package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/team-xquare/contour-middleware/pkg/errors"
	"github.com/team-xquare/contour-middleware/pkg/jwt"
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

	availableHeaders := c.findNotAvailableHeader(request)
	if len(availableHeaders) != 0 {
		err := errors.NewInvalidHeaderError(availableHeaders)
		return c.responseUnauthorizedError(err), err
	}

	tokenType, tokenString := c.getTokenInfo(request)
	if len(tokenType) == 0 && len(tokenString) == 0 {
		return c.responseOKWithoutHeader(), nil
	}
	if tokenType == "basic" || tokenType == "Basic" {
		return c.responseOKWithoutHeader(), nil
	}

	header, err := c.createHeaderFromJWTToken(tokenString)
	if err != nil {
		if _, ok := err.(*jwt.ValidationError); ok {
			return c.responseUnauthorizedError(err), err
		}
		return c.responseInternelServerError(err), err
	}
	return c.responseOKWithHeader(header), nil
}

func (c *checkService) findNotAvailableHeader(request *Request) []string {
	blackList := []string{"Request-User-Id", "Request-User-Role", "Request-User-Authorities"}
	result := []string{}
	for _, key := range blackList {
		if len(request.Request.Header.Get(key)) != 0 {
			result = append(result, key)
		}
	}

	return result
}

func (c *checkService) getTokenInfo(request *Request) (string, string) {
	token := request.Request.Header.Get("Authorization")
	splittedToken := strings.Split(token, " ")
	if len(splittedToken) != 2 {
		return "", ""
	}
	return splittedToken[0], splittedToken[1]
}

func (c *checkService) createHeaderFromJWTToken(jwtToken string) (http.Header, error) {
	var headers = make(http.Header)

	claims, err := jwt.ParseJWTToken(jwtToken)
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
