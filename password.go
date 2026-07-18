package security

// Found here: https://github.com/tradingAI/go/blob/d675ba819c87/werkzeug/security.go

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	method = "pbkdf2:sha256"
)

const (
	saltChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	keyLength = 32
)

func GeneratePasswordHash(password string, iterations int, salt string) (string, error) {
	hash, err := hashString(salt, iterations, password)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%v$%s$%s", method, iterations, salt, hash), nil
}

func CheckPasswordHash(password string, hash string) (bool, error) {
	if strings.Count(hash, "$") != 2 {
		return false, nil
	}
	ps := strings.Split(hash, "$")
	headerParts := strings.Split(ps[0], ":")
	if len(headerParts) != 3 {
		return false, nil
	}

	iterations := headerParts[2]
	iters, err := strconv.Atoi(iterations)
	if err != nil {
		return false, nil
	}

	hashed, err := hashString(ps[1], iters, password)
	return ps[2] == hashed, err
}

func GenSalt(size int) string {
	var bytes = make([]byte, size)
	rand.Read(bytes)
	for k, v := range bytes {
		bytes[k] = saltChars[v%byte(len(saltChars))]
	}
	return string(bytes)
}

func hashString(salt string, iterations int, password string) (string, error) {

	if iterations <= 0 {
		return "", errors.New("iterations must be > 0")
	}

	hash := pbkdf2.Key([]byte(password), []byte(salt), iterations, keyLength, sha256.New)
	return hex.EncodeToString(hash), nil
}
