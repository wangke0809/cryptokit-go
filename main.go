package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/cinus-ue/CryptoKit-Go/kit"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
	"syscall"
)

const VERSION = "0.1"

var waitGroup sync.WaitGroup

func main() {
	
	app := cli.NewApp()
	app.Name = "cryptokit-go"
	app.Version = "0.0.1"
	app.Authors = []cli.Author{
		cli.Author{
			Name:  "Carey Wong",
			Email: "carey.wong@foxmail.com",
		},
	}

	app.Commands = []cli.Command{
		{
			Name:  "Base64",
			Usage: "Base64 Encode/Decode",
			Subcommands: []cli.Command{
				{
					Name:    "encode",
					Aliases: []string{"e"},
					Usage:   "encode the source data to a Base64 string",
					Action: func(c *cli.Context) error {
						text := getInput("Please enter the text to Base64 Encode:")
						result := kit.Base64Encode([]byte(text))
						fmt.Printf("\n[*]Base64->%s\n", string(result))
						return nil
					},
				},
				{
					Name:    "decode",
					Aliases: []string{"d"},
					Usage:   "decode the data from a Base64 string",
					Action: func(c *cli.Context) error {
						text := getInput("Please enter the text to Base64 Decode:")
						ret, err := kit.Base64Decode(text)
						checkErr(err)
						fmt.Printf("\n[*]Base64->%s\n", string(ret))
						return nil
					},
				},
			},
		},
		{
			Name:  "MD5",
			Usage: "MD5 Hash Generator",
			Subcommands: []cli.Command{
				{
					Name:    "encrypt",
					Aliases: []string{"e"},
					Usage:   "generate the MD5 hash of any string",
					Action: func(c *cli.Context) error {
						text := getInput("Please enter the text here to get a MD5 hash:")
						ret32 := kit.Md532(text)
						fmt.Printf("\n[*]Md5-16->%s", hex.EncodeToString(ret32)[8:24])
						fmt.Printf("\n[*]Md5-32->%s\n", hex.EncodeToString(ret32))
						return nil
					},
				},
			},
		},
		{
			Name:  "SHA",
			Usage: "SHA Hash Generator",
			Subcommands: []cli.Command{
				{
					Name:    "encrypt",
					Aliases: []string{"e"},
					Usage:   "generate the SHA hash of any string",
					Action: func(c *cli.Context) error {
						text := getInput("Please enter the text here to get a SHA hash:")
						ret1 := kit.SHA1(text)
						fmt.Printf("\n[*]SHA1->%s", hex.EncodeToString(ret1))
						ret256 := kit.SHA256(text)
						fmt.Printf("\n[*]SHA256->%s", hex.EncodeToString(ret256))
						ret384 := kit.SHA384(text)
						fmt.Printf("\n[*]SHA384->%s", hex.EncodeToString(ret384))
						ret512 := kit.SHA512(text)
						fmt.Printf("\n[*]SHA512->%s\n", hex.EncodeToString(ret512))
						return nil
					},
				},
			},
		},
		{
			Name:  "AES",
			Usage: "AES Encrypt/Decrypt",
			Subcommands: []cli.Command{
				{
					Name:    "encrypt",
					Aliases: []string{"e"},
					Usage:   "AES encrypt",
					Subcommands: []cli.Command{
						{
							Name:    "file",
							Aliases: []string{"f"},
							Usage:   "encrypt a single file",
							Action: func(c *cli.Context) error {
								source := getInput("Please enter the file path:")
								if !kit.ValidateFile(source) {
									fmt.Println("File not found")
									os.Exit(1)
								}
								text, err := ioutil.ReadFile(source)
								checkErr(err)
								password := getPassword()
								fmt.Println("\nEncrypting...")
								ciphertext, err := kit.AESGCMEncrypt(text, password)
								checkErr(err)
								err = kit.SaveFile(source, ciphertext)
								checkErr(err)
								fmt.Println("\nFile successfully protected")
								return nil
							},
						},
						{
							Name:    "text",
							Aliases: []string{"t"},
							Usage:   "encrypt text messages",
							Action: func(c *cli.Context) error {
								source := getInput("Please enter the text to encrypt:")
								password := getPassword()
								ciphertext, err := kit.AESGCMEncrypt([]byte(source), password)
								checkErr(err)
								fmt.Printf("\n[*]AES->%s\n", hex.EncodeToString(ciphertext))
								return nil
							},
						},
						{
							Name:    "path",
							Aliases: []string{"p"},
							Usage:   "encrypt multiple files at once",
							Action: func(c *cli.Context) error {
								source := getInput("Please enter the folder path:")
								files, err := kit.ScanFile(source)
								checkErr(err)
								if len(files) == 0 {
									fmt.Println("\nFile not found")
								}
								password := getPassword()
								for _, source := range files {
									waitGroup.Add(1)
									go fileEncrypt(source, password)
								}
								waitGroup.Wait()
								fmt.Println("\nFile successfully protected")
								return nil
							},
						},
					},
				},
				{
					Name:    "decrypt",
					Aliases: []string{"d"},
					Usage:   "AES decrypt",
					Subcommands: []cli.Command{
						{
							Name:    "file",
							Aliases: []string{"f"},
							Usage:   "decrypt a single file",
							Action: func(c *cli.Context) error {
								source := getInput("Please enter the file path:")
								if !kit.ValidateFile(source) {
									fmt.Println("File not found")
									os.Exit(1)
								}
								text, err := ioutil.ReadFile(source)
								checkErr(err)
								password := getPassword()
								fmt.Println("\nDecrypting...")
								plaintext, err := kit.AESGCMDecrypt(text, password)
								checkErr(err)
								err = kit.SaveFile(source, plaintext)
								checkErr(err)
								fmt.Println("\nFile successfully decrypted.")
								return nil
							},
						},
						{
							Name:    "text",
							Aliases: []string{"t"},
							Usage:   "decrypt encrypted text",
							Action: func(c *cli.Context) error {
								source := getInput("Paste the encrypted code here to decrypt:")
								password := getPassword()
								ciphertext, _ := hex.DecodeString(source)
								plaintext, err := kit.AESGCMDecrypt(ciphertext, password)
								checkErr(err)
								fmt.Printf("\n[*]AES->%s\n", plaintext)
								return nil
							},
						},
						{
							Name:    "path",
							Aliases: []string{"p"},
							Usage:   "decrypt multiple files at once",
							Action: func(c *cli.Context) error {
								source := getInput("Please enter the folder path:")
								files, err := kit.ScanFile(source)
								checkErr(err)
								if len(files) == 0 {
									fmt.Println("\nFile not found")
								}
								password := getPassword()
								for _, source := range files {
									waitGroup.Add(1)
									go fileDecrypt(source, password)
								}
								waitGroup.Wait()
								fmt.Println("\nFile successfully decrypted.")
								return nil
							},
						},
					},
				},
			},
		},
		{
			Name:  "RSA",
			Usage: "RSA Encrypt/Decrypt",
			Subcommands: []cli.Command{
				{
					Name:    "encrypt",
					Aliases: []string{"e"},
					Usage:   "RSA encrypt",
					Subcommands: []cli.Command{
						{
							Name:    "file",
							Aliases: []string{"f"},
							Usage:   "encrypt a single file",
							Action: func(c *cli.Context) error {
								source := getInput("Please enter the file path:")
								pubkey := getInput("Please enter the path of the public key:")
								pubk, err := ioutil.ReadFile(pubkey)
								checkErr(err)
								if !kit.ValidateFile(source) {
									fmt.Println("File not found")
									os.Exit(1)
								}
								text, err := ioutil.ReadFile(source)
								checkErr(err)
								fmt.Println("\nEncrypting...")
								ciphertext, err := kit.RSAEncrypt(text, pubk)
								err = kit.SaveFile(source, ciphertext)
								checkErr(err)
								fmt.Println("\nFile successfully protected")
								return nil
							},
						},
						{
							Name:    "text",
							Aliases: []string{"t"},
							Usage:   "encrypt text messages",
							Action: func(c *cli.Context) error {
								source := getInput("Please enter the text to encrypt:")
								pubkey := getInput("Please enter the path of the public key:")
								pubk, err := ioutil.ReadFile(pubkey)
								checkErr(err)
								ciphertext, err := kit.RSAEncrypt([]byte(source), pubk)
								checkErr(err)
								fmt.Printf("\n[*]RSA->%s\n", hex.EncodeToString(ciphertext))
								return nil
							},
						},
					},
				},
				{
					Name:    "decrypt",
					Aliases: []string{"d"},
					Usage:   "RSA decrypt",
					Subcommands: []cli.Command{
						{
							Name:    "file",
							Aliases: []string{"f"},
							Usage:   "decrypt a single file",
							Action: func(c *cli.Context) error {
								source := getInput("Please enter the file path :")
								prikey := getInput("Please enter the path of the private key:")
								prik, err := ioutil.ReadFile(prikey)
								if !kit.ValidateFile(source) {
									fmt.Println("file not found")
									os.Exit(1)
								}
								text, err := ioutil.ReadFile(source)
								checkErr(err)
								fmt.Println("\nDecrypting...")
								plaintext, err := kit.RSADecrypt(text, prik)
								err = kit.SaveFile(source, plaintext)
								checkErr(err)
								fmt.Println("\nFile successfully decrypted.")
								return nil
							},
						},
						{
							Name:    "text",
							Aliases: []string{"t"},
							Usage:   "decrypt encrypted text",
							Action: func(c *cli.Context) error {
								source := getInput("Paste the encrypted code here to decrypt:")
								prikey := getInput("Please enter the path of the private key:")
								prik, err := ioutil.ReadFile(prikey)
								checkErr(err)
								ciphertext, _ := hex.DecodeString(source)
								plaintext, err := kit.RSADecrypt(ciphertext, prik)
								checkErr(err)
								fmt.Printf("\n[*]RSA->%s\n", plaintext)
								return nil
							},
						},
					},
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

}

func getPassword() []byte {
	fmt.Print("Enter password: ")
	password, _ := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Print("\nConfirm password: ")
	password2, _ := terminal.ReadPassword(int(syscall.Stdin))
	if !validatePassword(password, password2) {
		fmt.Print("\nPasswords do not match. Please try again.\n")
		return getPassword()
	}
	return password
}

func validatePassword(password1 []byte, password2 []byte) bool {
	if len(password1) == 0 || len(password2) == 0 {
		return false
	}
	if !bytes.Equal(password1, password2) {
		return false
	}
	return true
}

func fileEncrypt(source string, password []byte) {
	if !kit.ValidateFile(source) {
		fmt.Println("File not found")
		os.Exit(1)
	}
	text, err := ioutil.ReadFile(source)
	checkErr(err)
	fmt.Printf("\n source: %s encrypting...", source)
	cipherText, err := kit.AESGCMEncrypt(text, password)

	err = kit.SaveFile(source, cipherText)
	checkErr(err)
	waitGroup.Done()
}

func fileDecrypt(source string, password []byte) {

	if !kit.ValidateFile(source) {
		fmt.Println("File not found")
		os.Exit(1)
	}
	text, err := ioutil.ReadFile(source)
	checkErr(err)
	fmt.Printf("\n source: %s decrypting...", source)
	plaintext, err := kit.AESGCMDecrypt(text, password)
	err = kit.SaveFile(source, plaintext)
	checkErr(err)
	waitGroup.Done()
}

func getInput(s string) string {
	var input string
	f := bufio.NewReader(os.Stdin)
	for {
		fmt.Print(s)
		input, _ = f.ReadString('\n')
		input = strings.TrimSpace(input)
		if len(input) == 0 {
			continue
		} else {
			return input
		}
	}
}

func checkErr(err error) {
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}
