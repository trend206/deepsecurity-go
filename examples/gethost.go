package main

import (
	"github.com/trend206/deepsecurity-go"
	"fmt"
)


func main(){

	// Authenticate against an on-prem DSM
	dsm, err := deepsecurity.NewDSM("username", "Password1!", "127.0.0.1", "4119", "", false)
	if err != nil{
		fmt.Println("Error Authenticating", err)
	}else {

		defer dsm.EndSession()
		fmt.Println("Authenticated successcully to DSM.")

		//Example 1 - Retrieve host by name
		webServer, err := dsm.HostRetrieveByName("laptop_mneil")

		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Printf("%s:%s\n", webServer.Name, webServer.Platform)
		}

	}

}