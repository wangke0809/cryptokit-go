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
	Usage: "RSA Encrypt/Decrypt",
	Subcommands: []cli.Command{
		{
			Name:    "encrypt",
			Aliases: []string{"e"},
			Usage:   "RSA encrypt",
			Subcommands: []cli.Command{
				{
					Name:    "path",
					Aliases: []string{"p"},
					Usage:   "encrypt multiple files at once",
					Action:  enRsaFileAction,
				},
				{
					Name:    "text",
					Aliases: []string{"t"},
					Usage:   "encrypt text messages",
					Action:  enRsaTextAction,
				},
			},
		},
		{
			Name:    "decrypt",
			Aliases: []string{"d"},
			Usage:   "RSA decrypt",
			Subcommands: []cli.Command{
				{
					Name:    "path",
					Aliases: []string{"p"},
					Usage:   "decrypt multiple files at once",
					Action:  deRsaFileAction,
				},
				{
					Name:    "text",
					Aliases: []string{"t"},
					Usage:   "decrypt encrypted text",
					Action:  deRsaTextAction,
				},
			},
		},
	},
}

func enRsaFileAction(c *cli.Context) (err error) {
	source := kit.GetInput("Please enter the file path:")
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

func deRsaFileAction(c *cli.Context) (err error) {
	source := kit.GetInput("Please enter the file path :")
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
	fmt.Println("\nFile successfully decrypted.")
	return nil
}

func enRsaTextAction(c *cli.Context) (err error) {
	source := kit.GetInput("Please enter the text to encrypt:")
	pubkey := kit.GetInput("Please enter the path of the public key:")
	pubk, err := ioutil.ReadFile(pubkey)
	kit.CheckErr(err)
	ciphertext, err := kit.RSAEncrypt([]byte(source), pubk)
	kit.CheckErr(err)
	fmt.Printf("\n[*]RSA->%s\n", hex.EncodeToString(ciphertext))
	return nil
}

func deRsaTextAction(c *cli.Context) (err error) {
	source := kit.GetInput("Paste the encrypted code here to decrypt:")
	prikey := kit.GetInput("Please enter the path of the private key:")
	prik, err := ioutil.ReadFile(prikey)
	kit.CheckErr(err)
	ciphertext, _ := hex.DecodeString(source)
	plaintext, err := kit.RSADecrypt(ciphertext, prik)
	kit.CheckErr(err)
	fmt.Printf("\n[*]RSA->%s\n", plaintext)
	return nil
}
