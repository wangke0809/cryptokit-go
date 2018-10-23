package cmd

import (
	"encoding/hex"
	"fmt"
	"github.com/cinus-ue/cryptokit-go/kit"
	"github.com/urfave/cli"
)

var Md5 = cli.Command{
	Name:  "md5",
	Usage: "MD5 Hash Generator",
	Subcommands: []cli.Command{
		{
			Name:    "encrypt",
			Aliases: []string{"e"},
			Usage:   "generate the MD5 hash of any string",
			Action:md5Action,
		},
	},

}


func md5Action(c *cli.Context) (err error) {
		text := kit.GetInput("Please enter the text here to get a MD5 hash:")
		ret32 := kit.Md532(text)
		fmt.Printf("\n[*]Md5-16->%s", hex.EncodeToString(ret32)[8:24])
		fmt.Printf("\n[*]Md5-32->%s\n", hex.EncodeToString(ret32))
		return nil
}