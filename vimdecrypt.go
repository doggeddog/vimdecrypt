package vimdecrypt

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/blowfish"
)

func Decrypt(data, passwd []byte) ([]byte, error) {
	if len(data) < 28 {
		return nil, errors.New("unsupported file format")
	}
	encryptType := data[0:12]
	salt := data[12:20]
	iv := data[20:28]
	encryptedData := data[28:]
	if string(encryptType) != "VimCrypt~03!" {
		return nil, errors.New("unsupported encrypt type")
	}

	key := hashPassword(passwd, salt)
	return blowfishDecryptCFB(iv, encryptedData, key), nil
}

func convertEndian(inout []byte) {
	var value uint32
	for i := 0; i < len(inout); i += 4 {
		value = binary.LittleEndian.Uint32(inout[i:])
		binary.BigEndian.PutUint32(inout[i:], value)
	}
}

func sha256Salt(data, salt []byte) []byte {
	// Return sha256 digest of data + salt
	h := sha256.New()
	h.Write(data)
	h.Write(salt)
	return h.Sum(nil)
}

// Convert password to cipher key
func hashPassword(password, salt []byte) []byte {
	key := sha256Salt(password, salt)

	for i := 0; i < 1000; i++ {
		keyHex := fmt.Sprintf("%x", key)
		key = sha256Salt([]byte(keyHex), salt)
	}
	return key
}

type endianCipher struct {
	cipher.Block
}

func NewEndianCipher(block cipher.Block) cipher.Block {
	return &endianCipher{block}
}

func (c *endianCipher) Encrypt(dst, src []byte) {
	convertEndian(src)
	c.Block.Encrypt(dst, src)
	convertEndian(dst)
}

func blowfishDecryptCFB(iv, encrypted, key []byte) (decrypted []byte) {
	block, _ := blowfish.NewCipher(key)
	endianBlock := NewEndianCipher(block)

	decrypted = make([]byte, len(encrypted))
	stream := cipher.NewCFBDecrypter(endianBlock, iv)
	stream.XORKeyStream(decrypted, encrypted)
	return decrypted
}

func Encrypt(data, passwd []byte) ([]byte, error) {
	// Generate random salt and IV
	salt := make([]byte, 8)
	iv := make([]byte, blowfish.BlockSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, errors.New("failed to generate salt")
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, errors.New("failed to generate IV")
	}

	// Derive key from password and salt
	key := hashPassword(passwd, salt)

	// Encrypt data using Blowfish in CFB mode
	encrypted := blowfishEncryptCFB(iv, data, key)

	// Build the final output format
	header := append([]byte("VimCrypt~03!"), salt...)
	header = append(header, iv...)
	return append(header, encrypted...), nil
}

func blowfishEncryptCFB(iv, plaintext, key []byte) []byte {
	block, _ := blowfish.NewCipher(key)
	endianBlock := NewEndianCipher(block)

	encrypted := make([]byte, len(plaintext))
	stream := cipher.NewCFBEncrypter(endianBlock, iv)
	stream.XORKeyStream(encrypted, plaintext)
	return encrypted
}
