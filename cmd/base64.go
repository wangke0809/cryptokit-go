package cmd

import (
	"fmt"
	"github.com/cinus-ue/cryptokit-go/kit"
	"github.com/urfave/cli"
)

var Base64 = cli.Command{
	Name:  "base64",
	Usage: "Base64 Encode and Decode",
	Subcommands: []cli.Command{
		{
			Name:    "encode",
			Aliases: []string{"e"},
			Usage:   "encode the source data to a Base64 string",
			Action:  encodeAction,
		},
		{
			Name:    "decode",
			Aliases: []string{"d"},
			Usage:   "decode the data from a Base64 string",
			Action:  decodeAction,
		},
	},
}

func encodeAction(c *cli.Context) (err error) {
	text := kit.GetInput("Please enter the text to Base64 Encode:")
	result := kit.Base64Encode([]byte(text))
	fmt.Printf("\n[*]Base64->%s\n", string(result))
	return nil
}

func decodeAction(c *cli.Context) (err error) {
	text := kit.GetInput("Please enter the text to Base64 Decode:")
	ret, err := kit.Base64Decode(text)
	kit.CheckErr(err)
	fmt.Printf("\n[*]Base64->%s\n", string(ret))
	return nil
}
