package memstore_test

import (
	"testing"

	"github.com/ez-technologies/passkey"
	"github.com/ez-technologies/passkey/memstore"
	"github.com/ez-technologies/passkey/storetest"
)

func TestStore(t *testing.T) {
	storetest.Run(t, func(*testing.T) passkey.Store { return memstore.New() })
}
