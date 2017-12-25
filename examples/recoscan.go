package main

import (
	"github.com/jeffthorne/deepsecurity-go"
	"fmt"
	"time"
	"sync"
	"github.com/jeffthorne/deepsecurity-go/gowsdlservice"
)


func main() {

	// Authenticate against DsaS
	dsm, err := deepsecurity.NewDSM("username", "Password1", "", "", "Tenant", false)
	if err != nil{
		fmt.Println("Error Authenticating", err)
	}else{
		defer dsm.EndSession()
		fmt.Println("Authenticated successcully to DSM.")
	}

	start := time.Now()
	// Retrieve host or list of hosts to initiate recommendation scans on.
	webServer, err := dsm.HostRetrieveByName("34.234.143.68")

	var waitGroup sync.WaitGroup    // goroutine sync mechanism
	waitGroup.Add(1)          // set goroutines to be waited on to 1. Normally would be len of host list.


	go runRecommendationScan(webServer, dsm, &waitGroup)  // concurrently run recommendation scan
	waitGroup.Wait()    //block on goroutine counter
	elapsed := time.Since(start)
	fmt.Printf("\nElapsed time: %.2f seconds\n\n", elapsed.Seconds())



}


func runRecommendationScan(host *gowsdlservice.HostTransport , dsm deepsecurity.DSM, waitGroup *sync.WaitGroup) bool{
	fmt.Printf("Running Recommendation scan on host %s\n", host.Name)
	dsm.HostRecommendationScan([]int32{host.ID})
	fmt.Println("Waiting for recommendation scan to complete")
	scanFishished := confirmHostRecoScanComplete(host.ID, dsm)
	if scanFishished{
		fmt.Printf("Recommendation scan complete: %s\n", host.Name)
	}else{
		fmt.Println("Recommendation scan timed out: %s\n", host.Name)
	}
	waitGroup.Done()           // decrement goroutine wait counter
	return scanFishished
}

// confirmHostRecoScanComplete will consider a recommendation scan complete for any reco scan completed in the last hour.
func confirmHostRecoScanComplete(hostID int32, dsm deepsecurity.DSM) bool{
	scanFinished := false
	events := dsm.SystemEventRetrieve("LAST_HOUR", int(hostID), 0,  0, "SPECIFIC_HOST",
		1, true, "GREATER_THAN")

	timeout := time.Now().Local().Add(time.Minute * time.Duration(30)) // timeout to wait for reco scan to complete
	for {

		found300 := false
		for _, event := range events{
			if event.EventID == 300{                          // an event with and ID of 300 represents reco scan complete.
				found300 = true
				break
			}
		}

		if found300{
			scanFinished = true
			break
		}else if time.Now().After(timeout) {
			break
		}

		events = dsm.SystemEventRetrieve("LAST_HOUR", int(hostID), 0,  0, "SPECIFIC_HOST",
			1, true, "GREATER_THAN")
	}

	return scanFinished

}

