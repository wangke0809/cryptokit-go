package main

import (
	"github.com/cinus-ue/cryptokit-go/cmd"
	"github.com/urfave/cli"
	"log"
	"os"
)

const VERSION = "0.1"



func main() {

	app := cli.NewApp()
	app.Name = "cryptokit-go"
	app.Usage = "Encrypt and sign your data"
	app.Version = "0.0.1"
	app.Authors = []cli.Author{
		cli.Author{
			Name:  "Carey Wong",
			Email: "cw.cinus@gmail.com",
		},
	}

	app.Commands = []cli.Command{
		cmd.Md5,
		cmd.Sha,
		cmd.Base64,
		cmd.Aes,
		cmd.Rsa,
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

}

