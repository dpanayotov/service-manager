package osb

import (
	"context"
	"net/http"

	"github.com/Peripli/service-manager/pkg/log"
	"github.com/Peripli/service-manager/pkg/types"
	"github.com/Peripli/service-manager/pkg/util"
	"github.com/Peripli/service-manager/security"
	"github.com/Peripli/service-manager/storage"
	)

// BrokerTransport provides handler for the Service Manager OSB business logic
type BrokerTransport struct {
	BrokerStorage storage.Broker
	Encrypter     security.Encrypter
	Tr            http.RoundTripper
}

var _ BrokerRoundTripper = &BrokerTransport{}

// RoundTrip implements http.RoundTripper and invokes the RoundTripper delegate
func (bt *BrokerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return bt.Tr.RoundTrip(request)
}

// Broker obtains the broker coordinates (auth and URL)
func (bt *BrokerTransport) Broker(ctx context.Context, brokerID string) (*types.Broker, error) {
	broker, err := bt.BrokerStorage.Get(ctx, brokerID)
	if err != nil {
		log.D().Debugf("Broker with id %s not found in storage", brokerID)
		return nil, util.HandleStorageError(err, "broker", brokerID)
	}

	password := broker.Credentials.Basic.Password
	plaintextPassword, err := bt.Encrypter.Decrypt(ctx, []byte(password))
	if err != nil {
		return nil, err
	}

	broker.Credentials.Basic.Password = string(plaintextPassword)

	return broker, nil
}
