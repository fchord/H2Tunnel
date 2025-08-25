package rsa_demo

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

// RSAEncryptor 只负责公钥加密
type RSAEncryptor struct {
	publicKey *rsa.PublicKey
}

// LoadPublicKey 从 PEM 文件加载公钥
func (e *RSAEncryptor) LoadPublicKey(pubPath string) error {
	pubPEM, err := os.ReadFile(pubPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(pubPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		return errors.New("invalid public key PEM")
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	rsaPub, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("not an RSA public key")
	}
	e.publicKey = rsaPub
	return nil
}

// Encrypt 使用公钥加密。2048bit密钥最多加密245字节的数据。
func (e *RSAEncryptor) Encrypt(plainText []byte) ([]byte, error) {
	if e.publicKey == nil {
		return nil, errors.New("public key not loaded")
	}
	return rsa.EncryptPKCS1v15(rand.Reader, e.publicKey, plainText)
}
