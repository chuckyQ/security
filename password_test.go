package security_test

import (
	"testing"

	"github.com/chuckyQ/security"
)

func TestBasic(t *testing.T) {

	password := "abcdef"
	hashed, err := security.GeneratePasswordHash(password, 100_000, security.GenSalt(10))
	if err != nil {
		t.Fatalf("test failed with error %v", err.Error())
	}
	valid, err := security.CheckPasswordHash(password, hashed)
	if !valid {
		t.Fatal("password is not valid")
	}

}

func TestFail(t *testing.T) {

	password := "abcdef"
	hashed, err := security.GeneratePasswordHash(password, 100, security.GenSalt(10))
	if err != nil {
		t.Fatalf("test failed with error %v", err.Error())
	}
	valid, err := security.CheckPasswordHash("wrong-password", hashed)
	if valid {
		t.Fatal("password should not be valid")
	}

}
