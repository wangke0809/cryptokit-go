package cmd

import (
	"encoding/hex"
	"fmt"
	"github.com/cinus-ue/cryptokit-go/kit"
	"github.com/urfave/cli"
	"io/ioutil"
	"os"
	"sync"
)


var waitGroup sync.WaitGroup

var Aes = cli.Command{
	Name:  "aes",
	Usage: "AES Encrypt/Decrypt",
	Subcommands: []cli.Command{
		{
			Name:    "encrypt",
			Aliases: []string{"e"},
			Usage:   "AES encrypt",
			Subcommands: []cli.Command{
				{
					Name:    "path",
					Aliases: []string{"p"},
					Usage:   "encrypt multiple files at once",
					Action:  enAesFileAction,
				}, {
					Name:    "text",
					Aliases: []string{"t"},
					Usage:   "encrypt text messages",
					Action:  enAesTextAction,
				},
			},
		},
		{
			Name:    "decrypt",
			Aliases: []string{"d"},
			Usage:   "AES decrypt",
			Subcommands: []cli.Command{
				{
					Name:    "path",
					Aliases: []string{"p"},
					Usage:   "decrypt multiple files at once",
					Action:  deAesFileAction,
				}, {
					Name:    "text",
					Aliases: []string{"t"},
					Usage:   "decrypt encrypted text",
					Action:  deAesTextAction,
				},
			},
		},
	},
}

func enAesFileAction(c *cli.Context) (err error) {
	source := kit.GetInput("Please enter the path:")
	files, err := kit.ScanFile(source)
	kit.CheckErr(err)
	if len(files) == 0 {
		fmt.Println("\nFile not found")
	}
	password := kit.GetPassword()
	for _, source := range files {
		waitGroup.Add(1)
		go fileEncrypt(source, password)
	}
	waitGroup.Wait()
	fmt.Println("\nFile successfully protected")
	return nil
}

func deAesFileAction(c *cli.Context) (err error) {
	source := kit.GetInput("Please enter the path:")
	files, err := kit.ScanFile(source)
	kit.CheckErr(err)
	if len(files) == 0 {
		fmt.Println("\nFile not found")
	}
	password := kit.GetPassword()
	for _, source := range files {
		waitGroup.Add(1)
		go fileDecrypt(source, password)
	}
	waitGroup.Wait()
	fmt.Println("\nFile successfully decrypted.")
	return nil
}

func enAesTextAction(c *cli.Context) (err error) {
	source := kit.GetInput("Please enter the text to encrypt:")
	password := kit.GetPassword()
	ciphertext, err := kit.AESGCMEncrypt([]byte(source), password)
	kit.CheckErr(err)
	fmt.Printf("\n[*]AES->%s\n", hex.EncodeToString(ciphertext))
	return nil
}

func deAesTextAction(c *cli.Context) (err error) {
	source := kit.GetInput("Paste the encrypted code here to decrypt:")
	password := kit.GetPassword()
	ciphertext, _ := hex.DecodeString(source)
	plaintext, err := kit.AESGCMDecrypt(ciphertext, password)
	kit.CheckErr(err)
	fmt.Printf("\n[*]AES->%s\n", plaintext)
	return nil
}

func fileEncrypt(source string, password []byte) {
	if !kit.ValidateFile(source) {
		fmt.Println("File not found")
		os.Exit(1)
	}
	text, err := ioutil.ReadFile(source)
	kit.CheckErr(err)
	fmt.Printf("\n source: %s encrypting...", source)
	cipherText, err := kit.AESGCMEncrypt(text, password)

	err = kit.SaveFile(source, cipherText)
	kit.CheckErr(err)
	waitGroup.Done()
}

func fileDecrypt(source string, password []byte) {

	if !kit.ValidateFile(source) {
		fmt.Println("File not found")
		os.Exit(1)
	}
	text, err := ioutil.ReadFile(source)
	kit.CheckErr(err)
	fmt.Printf("\n source: %s decrypting...", source)
	plaintext, err := kit.AESGCMDecrypt(text, password)
	err = kit.SaveFile(source, plaintext)
	kit.CheckErr(err)
	waitGroup.Done()
}
