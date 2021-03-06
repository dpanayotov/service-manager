package authn

import (
	"net/http"

	"github.com/Peripli/service-manager/pkg/web"
	"github.com/Peripli/service-manager/security"
	"github.com/Peripli/service-manager/security/basic"
	"github.com/Peripli/service-manager/storage"
)

// BasicAuthnFilterName is the name of the basic authentication filter
const BasicAuthnFilterName string = "BasicAuthnFilter"

// BasicAuthnFilter performs Basic authentication by validating the Authorization header
type BasicAuthnFilter struct {
	Middleware
}

// NewBasicAuthnFilter returns a BasicAuthnFilter using the provided credentials storage
// in order to validate the credentials
func NewBasicAuthnFilter(storage storage.Credentials, encrypter security.Encrypter) *BasicAuthnFilter {
	return &BasicAuthnFilter{
		Middleware: Middleware{
			authenticator: basic.NewAuthenticator(storage, encrypter),
			name:          BasicAuthnFilterName,
		},
	}
}

// Name implements the web.Filter interface and returns the identifier of the filter
func (ba *BasicAuthnFilter) Name() string {
	return BasicAuthnFilterName
}

// FilterMatchers implements the web.Filter interface and returns the conditions on which the filter should be executed
func (ba *BasicAuthnFilter) FilterMatchers() []web.FilterMatcher {
	return []web.FilterMatcher{
		{
			Matchers: []web.Matcher{
				web.Path(web.OSBURL + "/**"),
			},
		},
		{
			Matchers: []web.Matcher{
				web.Methods(http.MethodGet),
				web.Path(web.BrokersURL + "/**"),
			},
		},
	}
}
