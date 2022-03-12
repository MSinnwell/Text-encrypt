package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"flag"
	"fmt"
	"math/rand"
)

func check_err(loc string, err error) {
	if err != nil {
		fmt.Printf("Error in %s: %s\n", loc, err)
	}
}

func encrypt(text string, s_key string) string {
	key, _ := hex.DecodeString(s_key)
	byte_text := []byte(text)
	block, err2 := aes.NewCipher(key)
	check_err("block", err2)
	GCM, err3 := cipher.NewGCM(block)
	check_err("GCM", err3)
	nonce := make([]byte, GCM.NonceSize())
	cipher := GCM.Seal(nonce, nonce, byte_text, nil)
	return fmt.Sprintf("%x", cipher)
}

func decrypt(text string, s_key string) string {
	key, _ := hex.DecodeString(s_key)
	enc_text, _ := hex.DecodeString(text)

	block, err1 := aes.NewCipher(key)
	check_err("block", err1)
	GCM, err2 := cipher.NewGCM(block)
	check_err("GCM", err2)
	noncesize := GCM.NonceSize()
	nonce, cipher := enc_text[:noncesize], enc_text[noncesize:]
	ptext, err3 := GCM.Open(nil, nonce, cipher, nil)
	check_err("open", err3)
	return fmt.Sprintf("%s", ptext)
}

func main() {
	encry := flag.Bool("encrypt", true, "choose true for encrypt/ false for decrypt")
	com_key := flag.String("key", "", "Key for decrypt")
	text := flag.String("text", "", "text to encrypt or decrypt")
	flag.Parse()

	if *encry == false && !(*com_key == "") {
		fmt.Println("Key: ", *com_key)
		de := decrypt(*text, *com_key)
		fmt.Println("Decrypt: ", de)
	} else {
		bytes := make([]byte, 32)
		_, err1 := rand.Read(bytes)
		check_err("rand", err1)
		key := hex.EncodeToString(bytes)
		fmt.Println("Key: ", key)
		en := encrypt(*text, key)
		fmt.Println("Encrypted: ", en)
	}
}
