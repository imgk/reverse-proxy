package main

import (
	"os"
	"time"

	"github.com/imgk/reverse-proxy/reverse"
)

func main() {
	time.AfterFunc(time.Hour, func() { os.Exit(1) })
	reverse.Run()
}
