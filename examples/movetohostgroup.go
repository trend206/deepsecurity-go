package main

import (
	"github.com/trend206/deepsecurity-go"
	"fmt"
)

func main(){

	// Authenticate against an on-prem DSM
	dsm, err := deepsecurity.NewDSM("username", "password", "127.0.0.1", "4119", "", false)
	if err != nil{
		fmt.Println("Error Authenticating", err)
	}else{
		defer dsm.EndSession()
		fmt.Println("Authenticated successcully to DSM.")
	}


	// Example #1 - Move 2 host to host group by Id
	resp, err := dsm.HostMoveToHostGroup([]int32{11, 12}, 7)

	if err != nil{
		fmt.Println(err)
	}else{
		fmt.Println(resp)
	}


}