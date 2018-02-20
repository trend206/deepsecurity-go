package main

import (
	"github.com/trend206/deepsecurity-go"
	"fmt"
)

func main(){
	//Authenticate against DSas
	dsm, err := deepsecurity.NewDSM("username", "password", "10.45.22.20", "4119", "", false)
	defer dsm.EndSession()
	if err != nil{
		fmt.Println("Error Authenticating", err)
	}else{
		defer dsm.EndSession()
		fmt.Println("Authenticated successcully to DSaS.")
	}

	resp, err := dsm.HostAgentActivate([]int32{5206})

	if err != nil{
		fmt.Println("Error Activating agent", err)
	}else{
		fmt.Println(resp)
	}

	host, err := dsm.HostGetStatus(3)

	if err != nil{
		fmt.Println(err)
	}else{
		fmt.Println(host)
	}
}