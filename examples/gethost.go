package main

import (
	"github.com/jeffthorne/deepsecurity-go"
	"fmt"
)


func main(){

	// Authenticate against an on-prem DSM
	dsm, err := deepsecurity.NewDSM("username", "Password1!", "127.0.0.1", "4119", "", false)
	if err != nil{
		fmt.Println("Error Authenticating", err)
	}else{
		defer dsm.EndSession()
		fmt.Println("Authenticated successcully to DSM.")
	}


	//Example 1 - Retrieve host by name
	webServer, err := dsm.HostRetrieveByName("web_ap0199")
	if webServer != nil{
		fmt.Printf("%s:%s\n", webServer.Name, webServer.Platform)
	}else{
		fmt.Println(err)
	}
}