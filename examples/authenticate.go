package main

import (
	"fmt"
	"github.com/trend206/deepsecurity-go"
)

func main() {

	//Example #1: Authenticate against an on-prem DSM
	dsm, err := deepsecurity.NewDSM("username", "password", "127.0.0.1", "4119", "", false)
	if err != nil {
		fmt.Println("Error Authenticating", err)
	} else {
		defer dsm.EndSession()
		fmt.Println("Authenticated successcully to DSM.")
	}

	//Example #2: Authenticate against DSas
	dsm, err = deepsecurity.NewDSM("username", "password", "", "", "ACME Corp", false)

	if err != nil {
		fmt.Println("Error Authenticating", err)
	} else {
		defer dsm.EndSession()
		fmt.Println("Authenticated successcully to DSaS.")
	}

}
