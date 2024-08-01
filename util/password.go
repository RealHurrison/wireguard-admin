package util

import (
	"crypto/sha256"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) string {
	sha2 := sha256.New()
	sha2.Write([]byte(password))
	bytes, err := bcrypt.GenerateFromPassword(sha2.Sum(nil), 12)
	if err != nil {
		panic("failed to hash password: " + err.Error())
	}

	return string(bytes)
}

func ComparePassword(hashedPassword, password string) bool {
	sha2 := sha256.New()
	sha2.Write([]byte(password))
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), sha2.Sum(nil))

	return err == nil
}
