// Copyright Project Contour Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"

	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type CheckRequestV2 = envoy_service_auth_v2.CheckRequest   //nolint(golint)
type CheckResponseV2 = envoy_service_auth_v2.CheckResponse //nolint(golint)
type CheckRequestV3 = envoy_service_auth_v3.CheckRequest   //nolint(golint)
type CheckResponseV3 = envoy_service_auth_v3.CheckResponse //nolint(golint)

type authV2 struct {
	checkService CheckService
}

func (a *authV2) Check(ctx context.Context, check *CheckRequestV2) (*CheckResponseV2, error) {
	request := Request{}
	request.FromV2(check)

	response, err := a.checkService.Check(ctx, &request)
	if err != nil {
		return nil, err
	}

	return response.AsV2(), nil
}

type authV3 struct {
	checkService CheckService
}

func (a *authV3) Check(ctx context.Context, check *CheckRequestV3) (*CheckResponseV3, error) {
	request := Request{}
	request.FromV3(check)

	response, err := a.checkService.Check(ctx, &request)
	if err != nil {
		return nil, err
	}

	return response.AsV3(), nil
}

func RegisterServer(srv *grpc.Server, c CheckService) {
	v2 := &authV2{checkService: c}
	v3 := &authV3{checkService: c}

	envoy_service_auth_v2.RegisterAuthorizationServer(srv, v2)
	envoy_service_auth_v3.RegisterAuthorizationServer(srv, v3)
}

func RunServer(listener net.Listener, srv *grpc.Server) error {
	errChan := make(chan error)

	go func() {
		errChan <- srv.Serve(listener)
	}()

	err := <-errChan
	return err
}

func NewServerCredentials(certPath string, keyPath string, caPath string) (credentials.TransportCredentials, error) {
	srv, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	p := x509.NewCertPool()

	ca, err := ioutil.ReadFile(caPath)
	if err != nil {
		return nil, err
	}

	p.AppendCertsFromPEM(ca)

	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{srv},
		RootCAs:      p,
	}), nil
}
