package main

import (
	"github.com/trend206/deepsecurity-go"
	"fmt"
	"time"
	"github.com/gocarina/gocsv"
	"os"
	"log"
)


func main() {

	// Authenticate against DsaS
	dsm, err := deepsecurity.NewDSM("username", "Password1!", "127.0.0.1", "4119", "", false)
	if err != nil {
		fmt.Println("Error Authenticating", err)
	} else {
		defer dsm.EndSession()
		fmt.Println("Authenticated successcully to DSM.")

		//Example 1: Retrieve Events by Time Range
		events, err := dsm.AntiMalwareEventRetrieve(time.Now().Add(-24*time.Hour), time.Now(), time.Time{}, "CUSTOM_RANGE", 24, 0,
			0, "SPECIFIC_HOST", 1, "GREATER_THAN")

		if err != nil {
			fmt.Println(err)
		} else if events != nil {
			fmt.Printf("%d events found by custom time range.\n", len(events))
		} else {
			fmt.Println("No AM events found")
		}


		//Example 2: Retrieve Events by Specific Time. Note I have yet to get this working or am not sure of time accuracy requirements.
		pastDate := time.Date(2017, time.December, 29, 13, 45, 47, 000, time.UTC)
		events, err = dsm.AntiMalwareEventRetrieve(time.Time{}, time.Time{}, pastDate, "SPECIFIC_TIME", 24, 0,
			0, "SPECIFIC_HOST", 1, "GREATER_THAN")

		if err != nil {
			fmt.Println(err)
		} else if events != nil {
			fmt.Printf("%d events found by specific time.\n", len(events))
		} else {
			fmt.Println("No AM events found by specific time.")
		}


		//Example 3: Retrieve Events by time range
		events, err = dsm.AntiMalwareEventRetrieve(time.Time{}, time.Time{}, time.Time{}, "LAST_24_HOURS", 24, 0,
			0, "HOSTS_IN_GROUP", 1, "GREATER_THAN")

		if err != nil {
			fmt.Println(err)
		} else if events != nil {
			fmt.Printf("%d events found by set time range.\n", len(events))
		} else {
			fmt.Println("No AM events found")
		}




		if err != nil {
			fmt.Println(err)
		} else if events != nil {
			fmt.Printf("%d events found by host group.\n", len(events))
		} else {
			fmt.Println("No AM events found")
		}


		//Example 5: Retrieve Events by Security Policy
		events, err = dsm.AntiMalwareEventRetrieve(time.Time{}, time.Time{}, time.Time{}, "LAST_24_HOURS", 0, 0,
			13, "HOSTS_USING_SECURITY_PROFILE", 1, "GREATER_THAN")

		if err != nil {
			fmt.Println(err)
		} else if events != nil {
			fmt.Printf("%d events found by security policy.\n", len(events))
		} else {
			fmt.Println("No AM events found")
		}



		//Example 6: Retrieve Events by Last 7 days for all hosts
		events, err = dsm.AntiMalwareEventRetrieve(time.Time{}, time.Time{}, time.Time{}, "LAST_7_DAYS", 0, 0,
			0, "ALL_HOSTS", 1, "GREATER_THAN")

		if err != nil {
			fmt.Println(err)
		} else if events != nil {
			fmt.Printf("%d events found for ALL_HOSTS LAST_7_DAYS.\n", len(events))
		} else {
			fmt.Println("No AM events found")
		}



		if err != nil{
			log.Printf("%V error", err)
		}else{
			fmt.Println(events)
		}

		file, _ := os.OpenFile("/Users/jeff/test.txt", os.O_RDWR, 0644)
		defer file.Close()
		err = gocsv.Marshal(&events, file)

	}


}

