package main

import (
	"crypto"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

const (
	host     = "localhost"
	port     = 5432
	user     = "jacksonsippe"
	password = "test"
	dbname   = "tls-fingerprint"
)

const (
	ANON  = 0x00
	RSA   = 0x01
	DSA   = 0x02
	ECDSA = 0x03
)

const (
	MD5    = 0x01
	SHA1   = 0x02
	SHA224 = 0x03
	SHA256 = 0x04
	SHA384 = 0x05
	SHA512 = 0x06
)

func main() {
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	type Primer struct {
		ClientRandom []uint8
		ServerRandom []uint8
		SigAlg       []uint8
		SigLength    []uint8
		ServerParams []uint8
		CipherSuite  int64
		TLSAlert     string
		PubKey       []uint8
		Signature    []uint8
	}

	statement := `SELECT client_random, server_random, server_params, cipher_suite, tls_alert, pub_key, signature FROM primers;`
	rows, err := db.Query(statement)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	for rows.Next() {
		var primer Primer
		err = rows.Scan(&primer.ClientRandom, &primer.ServerRandom, &primer.ServerParams, &primer.CipherSuite, &primer.TLSAlert, &primer.PubKey, &primer.Signature)
		if err != nil {
			panic(err)
		}
		primer.SigAlg = primer.Signature[:2]
		primer.SigLength = primer.Signature[2:4]
		primer.Signature = primer.Signature[4:]
		sig_string := append(primer.ClientRandom, primer.ServerRandom...)
		sig_string = append(sig_string, primer.ServerParams...)
		key, err := x509.ParsePKIXPublicKey(primer.PubKey)
		if err != nil {
			panic(err)
		}
		if primer.SigAlg[1] == RSA {
			pubKey := key.(*rsa.PublicKey)
			switch primer.SigAlg[0] {
			case MD5:
				sig_hash := md5.Sum(sig_string)
				err = rsa.VerifyPKCS1v15(pubKey, crypto.MD5, sig_hash[:], primer.Signature)
			case SHA1:
				sig_hash := sha1.Sum(sig_string)
				err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA1, sig_hash[:], primer.Signature)
			case SHA224:
				sig_hash := sha256.Sum224(sig_string)
				err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA224, sig_hash[:], primer.Signature)
			case SHA256:
				sig_hash := sha256.Sum256(sig_string)
				err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, sig_hash[:], primer.Signature)
			case SHA384:
				sig_hash := sha512.Sum384(sig_string)
				err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA384, sig_hash[:], primer.Signature)
			case SHA512:
				sig_hash := sha512.Sum512(sig_string)
				err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA512, sig_hash[:], primer.Signature)
			default:
				fmt.Printf("Unsupported hash algorithm: %#x", primer.SigAlg[0])
			}
			if err != nil {
				fmt.Println(err)
			}
		} else {
			fmt.Printf("Unsupported signature algorithm: %#x\n", primer.SigAlg)
		}
	}
	err = rows.Err()
	if err != nil {
		panic(err)
	}
}
