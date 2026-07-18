package security

import (
	"crypto/rand"
	"errors"
)

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const length = len(letters)

var (
	errSize = errors.New("size must be > 0")
)

func NewToken(size int) (string, error) {

	if size <= 0 {
		return "", errSize
	}

	buff := make([]byte, size)
	_, err := rand.Reader.Read(buff)
	if err != nil {
		return "", err
	}

	newBuff := make([]byte, size)
	for i, byt := range buff {
		x := int(byt)
		newBuff[i] = letters[x%length]
	}

	return string(newBuff), nil
}
