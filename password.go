package security

// Found here: https://github.com/tradingAI/go/blob/d675ba819c87/werkzeug/security.go

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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

func GeneratePasswordHash(password string, iterations int, salt string) string {
	hash := hashString(salt, iterations, password)
	return fmt.Sprintf("%s:%v$%s$%s", method, iterations, salt, hash)
}

func CheckPasswordHash(password string, hash string) bool {
	if strings.Count(hash, "$") != 2 {
		return false
	}
	ps := strings.Split(hash, "$")
	headerParts := strings.Split(ps[0], ":")
	if len(headerParts) != 3 {
		return false
	}

	iterations := headerParts[2]
	iters, err := strconv.Atoi(iterations)
	if err != nil {
		return false
	}

	return ps[2] == hashString(ps[1], iters, password)
}

func GenSalt(size int) string {
	var bytes = make([]byte, size)
	rand.Read(bytes)
	for k, v := range bytes {
		bytes[k] = saltChars[v%byte(len(saltChars))]
	}
	return string(bytes)
}

func hashString(salt string, iterations int, password string) string {
	hash := pbkdf2.Key([]byte(password), []byte(salt), iterations, keyLength, sha256.New)
	return hex.EncodeToString(hash)
}
