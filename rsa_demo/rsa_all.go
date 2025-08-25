package rsa_demo

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

// RSAHandler 负责公钥加密 + 私钥解密
type RSAHandler struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

// LoadPublicKey 从 PEM 文件加载公钥
func (h *RSAHandler) LoadPublicKey(pubPath string) error {
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
	h.publicKey = rsaPub
	return nil
}

// LoadPrivateKey 从 PEM 文件加载未加密私钥
func (h *RSAHandler) LoadPrivateKey(privPath string) error {
	privPEM, err := os.ReadFile(privPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(privPEM)
	if block == nil || block.Type != "PRIVATE KEY" && block.Type != "RSA PRIVATE KEY" {
		return errors.New("invalid private key PEM")
	}

	var privKey *rsa.PrivateKey
	if block.Type == "PRIVATE KEY" {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		rsaPriv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return errors.New("not an RSA private key")
		}
		privKey = rsaPriv
	} else {
		// RSA PRIVATE KEY
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		privKey = key
	}
	h.privateKey = privKey
	return nil
}

// Encrypt 使用公钥加密
func (h *RSAHandler) Encrypt(plainText []byte) ([]byte, error) {
	if h.publicKey == nil {
		return nil, errors.New("public key not loaded")
	}
	return rsa.EncryptPKCS1v15(rand.Reader, h.publicKey, plainText)
}

// Decrypt 使用私钥解密
func (h *RSAHandler) Decrypt(cipherText []byte) ([]byte, error) {
	if h.privateKey == nil {
		return nil, errors.New("private key not loaded")
	}
	return rsa.DecryptPKCS1v15(rand.Reader, h.privateKey, cipherText)
}
