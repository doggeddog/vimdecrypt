package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/doggeddog/vimdecrypt"
	"golang.org/x/tools/godoc/util"
)

func main() {
	password := flag.String("p", "", "password")
	flag.Usage = func() {
		println("usage: vimdecrypt -p ${password} ${filename}")
		flag.PrintDefaults()
	}
	flag.Parse()

	if len(flag.Args()) < 1 {
		println("no file to decrypt")
		return
	}

	data, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		println("read file error:", err.Error())
		return
	}
	result, err := vimdecrypt.Decrypt(data, []byte(*password))
	if err != nil {
		println("decrypt error:", err.Error())
		return
	}
	if !util.IsText(result) {
		println("fail to decrypt file:", flag.Arg(0))
	}

	fmt.Println(string(result))
}
