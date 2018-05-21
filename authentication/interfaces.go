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

package authentication

import (
	"context"
	"net/http"
)

// Authenticator extracts the authenticator information from the request and
// returns information about the current user or an error if authentication was not successful
type Authenticator interface {
	Authenticate(req *http.Request) (*User, error)
}

// Token interface provides means to unmarshal the claims in a struct
type Token interface {
	Claims(v interface{}) error
}

// TokenVerifier attempts to verify a token and returns it or an error if the verification was not successful
type TokenVerifier interface {
	Verify(ctx context.Context, token string) (Token, error)
}
