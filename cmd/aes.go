package cmd

import (
	"encoding/hex"
	"fmt"
	"github.com/cinus-ue/cryptokit-go/kit"
	"github.com/urfave/cli"
	"os"
	"sync"
)

var waitGroup sync.WaitGroup

var Aes = cli.Command{
	Name:  "aes",
	Usage: "AES-256 Encrypt and Decrypt",
	Subcommands: []cli.Command{
		{
			Name:    "encrypt",
			Aliases: []string{"e"},
			Usage:   "AES encrypt",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "path,p",
					Usage: "encrypt multiple files at once",
				},
				&cli.BoolFlag{
					Name:  "text,t",
					Usage: "encrypt text messages",
				},
				&cli.BoolFlag{
					Name:  "rename,r",
					Usage: "encrypt the name of the file",
				},
				&cli.BoolFlag{
					Name:  "delete,d",
					Usage: "delete origin files",
				},
			},
			Action: aesEncryptAction,
		},
		{
			Name:    "decrypt",
			Aliases: []string{"d"},
			Usage:   "AES decrypt",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "path,p",
					Usage: "decrypt multiple files at once",
				},
				&cli.BoolFlag{
					Name:  "text,t",
					Usage: "decrypt encrypted text",
				},
				&cli.BoolFlag{
					Name:  "rename,r",
					Usage: "decrypt the name of the file",
				},
				&cli.BoolFlag{
					Name:  "delete,d",
					Usage: "delete origin files",
				},
			},
			Action: aesDecryptAction,
		},
	},
}

func aesEncryptAction(c *cli.Context) (err error) {
	var (
		path   = c.Bool("path")
		text   = c.Bool("text")
		rename = c.Bool("rename")
		delete = c.Bool("delete")
	)

	switch {
	case path:
		source := kit.GetInput("Please enter the path:")
		files, err := kit.ScanFile(source)
		kit.CheckErr(err)
		if len(files) == 0 {
			fmt.Println("\nFile not found")
		}
		password := kit.GetPassword()
		for _, source := range files {
			waitGroup.Add(1)
			go fileEncrypt(source, password, rename, delete)
		}
		waitGroup.Wait()
		fmt.Println("\nFile successfully protected")
		return nil
	case text:
		source := kit.GetInput("Please enter the text to encrypt:")
		password := kit.GetPassword()
		ciphertext, err := kit.AESGCMEncrypt([]byte(source), password)
		kit.CheckErr(err)
		fmt.Printf("\n[*]AES->%s\n", hex.EncodeToString(ciphertext))
		return nil
	}
	return nil
}

func aesDecryptAction(c *cli.Context) (err error) {
	var (
		path   = c.Bool("path")
		text   = c.Bool("text")
		rename = c.Bool("rename")
		delete = c.Bool("delete")
	)

	switch {
	case path:
		source := kit.GetInput("Please enter the path:")
		files, err := kit.ScanFile(source)
		kit.CheckErr(err)
		if len(files) == 0 {
			fmt.Println("\nFile not found")
		}
		password := kit.GetPassword()
		for _, source := range files {
			waitGroup.Add(1)
			go fileDecrypt(source, password, rename, delete)
		}
		waitGroup.Wait()
		fmt.Println("\nFile successfully decrypted.")
		return nil
	case text:
		source := kit.GetInput("Paste the encrypted code here to decrypt:")
		password := kit.GetPassword()
		ciphertext, _ := hex.DecodeString(source)
		plaintext, err := kit.AESGCMDecrypt(ciphertext, password)
		kit.CheckErr(err)
		fmt.Printf("\n[*]AES->%s\n", plaintext)
		return nil
	}
	return nil
}

func fileEncrypt(source string, password []byte, rename, delete bool) {
	if !kit.ValidateFile(source) {
		fmt.Println("File not found")
		os.Exit(1)
	}
	fmt.Printf("\n%s encrypting...", source)
	err := kit.AESCFBEncrypt(source, string(password), rename)
	kit.CheckErr(err)
	if delete {
		err := os.Remove(source)
		kit.CheckErr(err)
	}
	waitGroup.Done()
}

func fileDecrypt(source string, password []byte, rename, delete bool) {
	if !kit.ValidateFile(source) {
		fmt.Println("File not found")
		os.Exit(1)
	}
	fmt.Printf("\n%s decrypting...", source)
	err := kit.AESCFBDecrypt(source, string(password), rename)
	kit.CheckErr(err)
	if delete {
		err := os.Remove(source)
		kit.CheckErr(err)
	}
	waitGroup.Done()
}
