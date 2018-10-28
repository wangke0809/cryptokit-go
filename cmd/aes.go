package cmd

import (
	"encoding/hex"
	"fmt"
	"github.com/cinus-ue/cryptokit-go/kit"
	"github.com/urfave/cli"
	"os"
	"path"
	"strings"
	"sync"
)

var waitGroup sync.WaitGroup

var Aes = cli.Command{
	Name:  "aes",
	Usage: "AES-256 Encrypt and Decrypt",
	Subcommands: []cli.Command{
		{
			Name:                   "encrypt",
			Aliases:                []string{"e"},
			Usage:                  "encrypt data using AES-256",
			UseShortOptionHandling: true,
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "text,t",
					Usage: "encrypt and decrypt hex strings using AES-256",
				},
				&cli.BoolFlag{
					Name:  "rename,r",
					Usage: "encrypt and decrypt file names",
				},
				&cli.BoolFlag{
					Name:  "delete,d",
					Usage: "delete origin files",
				},
			},
			Action: aesEncryptAction,
		},
		{
			Name:                   "decrypt",
			Aliases:                []string{"d"},
			Usage:                  "decrypt data using AES-256",
			UseShortOptionHandling: true,
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "text,t",
					Usage: "encrypt and decrypt hex strings using AES-256",
				},
				&cli.BoolFlag{
					Name:  "rename,r",
					Usage: "encrypt and decrypt file names",
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
		text   = c.Bool("text")
		rename = c.Bool("rename")
		delete = c.Bool("delete")
	)

	switch {
	case text:
		source := kit.GetInput("Please enter the text to encrypt:")
		password := kit.GetPassword()
		ciphertext, err := kit.AESGCMEncrypt([]byte(source), password)
		kit.CheckErr(err)
		fmt.Printf("\n[*]AES->%s\n", hex.EncodeToString(ciphertext))
		return nil
	default:
		source := kit.GetInput("Please enter the path of the files that you want to encrypt:")
		files, err := kit.ScanFile(source)
		kit.CheckErr(err)
		if files.Len() == 0 {
			fmt.Println("\nFile not found")
		}
		password := kit.GetPassword()
		for e := files.Front(); e != nil; e = e.Next() {
			waitGroup.Add(1)
			go fileEncrypt(e.Value.(string), password, rename, delete)
		}
		waitGroup.Wait()
		fmt.Println("\nFile successfully protected")
		return nil
	}
	return nil
}

func aesDecryptAction(c *cli.Context) (err error) {
	var (
		text   = c.Bool("text")
		rename = c.Bool("rename")
		delete = c.Bool("delete")
	)

	switch {
	case text:
		source := kit.GetInput("Paste the encrypted code here to decrypt:")
		password := kit.GetPassword()
		ciphertext, _ := hex.DecodeString(source)
		plaintext, err := kit.AESGCMDecrypt(ciphertext, password)
		kit.CheckErr(err)
		fmt.Printf("\n[*]AES->%s\n", plaintext)
		return nil
	default:
		source := kit.GetInput("Please enter the path of the files that you want to decrypt:")
		files, err := kit.ScanFile(source)
		kit.CheckErr(err)
		if files.Len() == 0 {
			fmt.Println("\nFile not found")
		}
		password := kit.GetPassword()
		for e := files.Front(); e != nil; e = e.Next() {
			waitGroup.Add(1)
			go fileDecrypt(e.Value.(string), password, rename, delete)
		}
		waitGroup.Wait()
		fmt.Println("\nFile successfully decrypted")
		return nil
	}
	return nil
}

func fileEncrypt(source string, password []byte, rename, delete bool) {
	if !kit.ValidateFile(source) {
		fmt.Println("File not found")
		os.Exit(1)
	}
	fileSuffix := path.Ext(source)
	if strings.Compare(fileSuffix, kit.Extension) == 0 {
		waitGroup.Done()
		return
	}
	fmt.Printf("\n[*]%s encrypting...", source)
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
	fileSuffix := path.Ext(source)
	if strings.Compare(fileSuffix, kit.Extension) != 0 {
		waitGroup.Done()
		return
	}
	fmt.Printf("\n[*]%s decrypting...", source)
	err := kit.AESCFBDecrypt(source, string(password), rename)
	kit.CheckErr(err)
	if delete {
		err := os.Remove(source)
		kit.CheckErr(err)
	}
	waitGroup.Done()
}
