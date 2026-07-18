package security_test

import (
	"testing"

	"github.com/chuckyQ/security"
)

func TestBasicToken(t *testing.T) {

	_, err := security.NewToken(10)
	if err != nil {
		t.Fatalf("failed with error %v", err.Error())
	}

}
