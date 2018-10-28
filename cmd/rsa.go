package cmd

import (
	"encoding/hex"
	"fmt"
	"github.com/cinus-ue/cryptokit-go/kit"
	"github.com/urfave/cli"
	"io/ioutil"
	"os"
)

var Rsa = cli.Command{
	Name:  "rsa",
	Usage: "RSA Encrypt and Decrypt",
	Subcommands: []cli.Command{
		{
			Name:    "encrypt",
			Aliases: []string{"e"},
			Usage:   "encrypt data using RSA",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "text,t",
					Usage: "encrypt and decrypt hex strings using RSA",
				},
			},
			Action: rsaEncryptAction,
		},
		{
			Name:    "decrypt",
			Aliases: []string{"d"},
			Usage:   "decrypt data using RSA",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "text,t",
					Usage: "encrypt and decrypt hex strings using RSA",
				},
			},
			Action: rsaDecryptAction,
		},
	},
}

func rsaEncryptAction(c *cli.Context) (err error) {
	var (
		text = c.Bool("text")
	)

	switch {
	case text:
		source := kit.GetInput("Please enter the text to encrypt:")
		pubkey := kit.GetInput("Please enter the path of the public key:")
		pubk, err := ioutil.ReadFile(pubkey)
		kit.CheckErr(err)
		ciphertext, err := kit.RSAEncrypt([]byte(source), pubk)
		kit.CheckErr(err)
		fmt.Printf("\n[*]RSA->%s\n", hex.EncodeToString(ciphertext))
		return nil
	default:
		source := kit.GetInput("Please enter the path of the files that you want to encrypt:")
		pubkey := kit.GetInput("Please enter the path of the public key:")
		pubk, err := ioutil.ReadFile(pubkey)
		kit.CheckErr(err)
		if !kit.ValidateFile(source) {
			fmt.Println("File not found")
			os.Exit(1)
		}
		text, err := ioutil.ReadFile(source)
		kit.CheckErr(err)
		fmt.Println("\nEncrypting...")
		ciphertext, err := kit.RSAEncrypt(text, pubk)
		err = kit.SaveFile(source, ciphertext)
		kit.CheckErr(err)
		fmt.Println("\nFile successfully protected")
		return nil
	}
	return nil
}

func rsaDecryptAction(c *cli.Context) (err error) {
	var (
		text = c.Bool("text")
	)

	switch {
	case text:
		source := kit.GetInput("Paste the encrypted code here to decrypt:")
		prikey := kit.GetInput("Please enter the path of the private key:")
		prik, err := ioutil.ReadFile(prikey)
		kit.CheckErr(err)
		ciphertext, _ := hex.DecodeString(source)
		plaintext, err := kit.RSADecrypt(ciphertext, prik)
		kit.CheckErr(err)
		fmt.Printf("\n[*]RSA->%s\n", plaintext)
		return nil
	default:
		source := kit.GetInput("Please enter the path of the files that you want to decrypt:")
		prikey := kit.GetInput("Please enter the path of the private key:")
		prik, err := ioutil.ReadFile(prikey)
		if !kit.ValidateFile(source) {
			fmt.Println("file not found")
			os.Exit(1)
		}
		text, err := ioutil.ReadFile(source)
		kit.CheckErr(err)
		fmt.Println("\nDecrypting...")
		plaintext, err := kit.RSADecrypt(text, prik)
		err = kit.SaveFile(source, plaintext)
		kit.CheckErr(err)
		fmt.Println("\nFile successfully decrypted")
		return nil
	}
	return nil
}
