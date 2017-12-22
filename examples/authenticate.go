package main

import (

	"github.com/jeffthorne/deepsecurity-go"
	"fmt"
)

func main(){

	//Eample #1: Authenticate against an on-prem DSM
	dsm, err := deepsecurity.NewDSM("username", "password", "127.0.0.1", "4119", "", false)

	if err != nil{
		fmt.Println("Error Authenticating", err)
	}else{
		defer dsm.EndSession()
		fmt.Println("Authenticated successcully to DSM.")
	}

	//Eample #2: Authenticate against DSas
	dsm, err = deepsecurity.NewDSM("username", "password", "", "", "ACME Corp", false)

	if err != nil{
		fmt.Println("Error Authenticating", err)
	}else{
		defer dsm.EndSession()
		fmt.Println("Authenticated successcully to DSaS.")
	}

}

