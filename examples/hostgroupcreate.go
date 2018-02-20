package main

import (
	"fmt"
	"github.com/trend206/deepsecurity-go"
)

func main() {


	// Authenticate against an on-prem DSM
	dsm, err := deepsecurity.NewDSM("username", "password", "127.0.0.1", "4119", "", false)
	if err != nil{
		fmt.Println("Error Authenticating", err)
	}else{
		defer dsm.EndSession()
		fmt.Println("Authenticated successcully to DSM.")
	}


	resp, err := dsm.HostGroupCreate("k8s_test", false,"0",-1)

	if err != nil{
		fmt.Println("Error found")
	}else{
		fmt.Printf("%#v", resp)
	}





}
