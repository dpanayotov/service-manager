/*
 * Copyright 2018 The Service Manager Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package auth

import (
	"github.com/Peripli/service-manager/pkg/filter"
	"github.com/Peripli/service-manager/storage"
	"github.com/Peripli/service-manager/authentication/oidc"
	"github.com/Peripli/service-manager/authentication/basic"
	"errors"
	"strings"
)

type BasicAuthData struct {
	CredentialsStorage storage.Credentials
}

type OAuthData struct {
	TokenIssuerURL string
}


func AuthenticationFilter(req *filter.Request, handler filter.Handler) (*filter.Response, error) {
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		return nil, errors.New("Missing Authorization header!")
	}

	header := strings.Split(authHeader, " ")
	schema := header[0]
	credentials := header[1]

	switch schema {
	case "Basic":
	case "Bearer":
	}


	return handler(req)
}

// Filter which authenticates requests coming from Broker proxies using Basic Authentication
func (data BasicAuthData) basicAuthFilter(req *filter.Request, handler filter.Handler) (*filter.Response, error) {
	authenticator := basic.NewAuthenticator(data.CredentialsStorage)
	_, err := authenticator.Authenticate(req.Request)
	if err != nil {
		return nil, err
	}

	return handler(req)
}

// Filter which authenticates requests coming from Service Manger CLI using OAuth
func (data OAuthData) oAuthCLIFilter(req *filter.Request, handler filter.Handler) (*filter.Response, error) {
	authenticator, err := oidc.NewAuthenticator(req.Request.Context(), oidc.Options{
		IssuerURL:data.TokenIssuerURL,
		ClientID: "cf",
	})
	if err != nil {
		return nil, err
	}

	_, err = authenticator.Authenticate(req.Request)
	if err != nil {
		return nil, err
	}

	return handler(req)
}
