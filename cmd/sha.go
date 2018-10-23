package cmd

import (
	"encoding/hex"
	"fmt"
	"github.com/cinus-ue/cryptokit-go/kit"
	"github.com/urfave/cli"
)


var Sha = cli.Command{
	Name:  "sha",
		Usage: "SHA Hash Generator",
		Subcommands: []cli.Command{
			{
				Name:    "encrypt",
				Aliases: []string{"e"},
				Usage:   "generate the SHA hash of any string",
				Action:shaAction,
			},
		},
}


func shaAction(c *cli.Context) (err error) {
	text := kit.GetInput("Please enter the text here to get a SHA hash:")
	ret1 := kit.SHA1(text)
	fmt.Printf("\n[*]SHA1->%s", hex.EncodeToString(ret1))
	ret256 := kit.SHA256(text)
	fmt.Printf("\n[*]SHA256->%s", hex.EncodeToString(ret256))
	ret384 := kit.SHA384(text)
	fmt.Printf("\n[*]SHA384->%s", hex.EncodeToString(ret384))
	ret512 := kit.SHA512(text)
	fmt.Printf("\n[*]SHA512->%s\n", hex.EncodeToString(ret512))
	return nil
}