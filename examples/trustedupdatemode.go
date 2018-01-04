package main

import (
	"fmt"

	"github.com/jeffthorne/deepsecurity-go"
)

func main() {

	// Authenticate to DSaS
	dsm, err := deepsecurity.NewDSM("username", "password", "", "", "ACME Corp", false)
	if err != nil {
		fmt.Println("Error Authenticating", err)
	} else {

		defer dsm.EndSession()

		//Example 1: Get Trusted Update Mode Status of Host by ID
		resp, ok := dsm.GetTrustedUpdateMode(5205)

		if ok != true {
			fmt.Println(resp)
		} else {
			fmt.Println(resp.State)
		}

	}
}
