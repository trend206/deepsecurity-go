package main

import (
	"github.com/trend206/deepsecurity-go"
	"fmt"
)

func main(){

	dsm, _ := deepsecurity.NewDSM("username", "Password", "","", "ACME CORP", false)

	ats, err := dsm.ApplicationTypeRetrieveAll()

	if err != nil{
		fmt.Println(err)
	}


	for _, at := range ats{
		fmt.Println(at.Name)
	}

}