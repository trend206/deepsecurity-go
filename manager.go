// package deepsecurity provides a DSM struct to interface with Deep Security's REST and SOAP APIs
package deepsecurity

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
	"github.com/trend206/deepsecurity-go/gowsdlservice"
	"github.com/levigross/grequests"
)

var dsasHost = "app.deepsecurity.trendmicro.com"
var dsasPort = "443"

// DSM is the main object interface to Deep Security's REST & SOAP APIs
type DSM struct {
	SessionID  string
	Host       string
	Port       string
	Tenant     string
	RestURL    string
	RestClient http.Client
	SoapClient *gowsdlservice.Manager
	SoapURL    string
}

// NewDSM is used to obtain a DSM struct.
// return empty DSM struct if there was a problem with communication or auth.
func NewDSM(username string, password string, host string, port string, tenant string, verifySSL bool) (DSM, error) {

	dsm := DSM{Host: host, Port: port, Tenant: tenant}
	if dsm.Host == "" {
		dsm.Host = dsasHost
		dsm.Port = dsasPort
	}

	dsm.RestURL = fmt.Sprintf("https://%s:%s/rest/", dsm.Host, dsm.Port)
	dsm.SoapURL = fmt.Sprintf("https://%s:%s/webservice/Manager", dsm.Host, dsm.Port)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifySSL}}
	dsm.RestClient = http.Client{Transport: tr}
	sessionID, err := authenticate(username, password, &dsm, verifySSL)

	if err != nil || strings.Contains(sessionID, "error") {
		return DSM{}, errors.New(sessionID)
	}

	dsm.SessionID = sessionID
	return dsm, nil

}

func authenticate(username string, password string, dsm *DSM, verifySSL bool) (string, error) {

	var str string
	auth := gowsdlservice.BasicAuth{Login: username, Password: password}
	dsm.SoapClient = gowsdlservice.NewManager(dsm.SoapURL, true, &auth)

	if dsm.Tenant != "" {
		tenantAuth := gowsdlservice.AuthenticateTenant{TenantName: dsm.Tenant, Username: username, Password: password}
		str = fmt.Sprintf("{\"dsCredentials\":{\"tenantName\": \"%s\", \"password\": \"%s\", \"userName\": \"%s\"}}", dsm.Tenant, password, username)
		authResponse, err := dsm.SoapClient.AuthenticateTenant(&tenantAuth)
		if err != nil {
			return "", err
		} else {
			return authResponse.AuthenticateTenantReturn, nil
		}
	} else {
		str = fmt.Sprintf("{\"dsCredentials\":{\"password\": \"%s\", \"userName\": \"%s\"}}", password, username)
		url := fmt.Sprintf("%sauthentication/login", dsm.RestURL)
		res, err := grequests.Post(url, &grequests.RequestOptions{HTTPClient: &dsm.RestClient, JSON: []byte(str), IsAjax: false})
		if err != nil {
			return "", err
		} else {
			return res.String(), nil
		}
	}

}

// GetTrustedUpdateMode gets the settings for trusted update mode on a host.
// return true of false based on http response code
func (dsm DSM) GetTrustedUpdateMode(hostID int) (TrustedUpdateModeResponse, bool) {
	var describeTUResponse JsonDescribeTrustedUpdateModeResponse
	url := fmt.Sprintf("%shosts/%d/trusted-update-mode", dsm.RestURL, hostID)
	cookies := []*http.Cookie{{Name: "sID", Value: dsm.SessionID}}
	resp, err := grequests.Get(url, &grequests.RequestOptions{HTTPClient: &dsm.RestClient, Cookies: cookies})

	if err != nil {
		log.Printf("Error getting trusted update mode for host %d\n", hostID)
		return TrustedUpdateModeResponse{}, false
	} else if resp.Ok != true {
		log.Printf("Request did not return OK")
		return TrustedUpdateModeResponse{}, false
	}

	err = json.NewDecoder(strings.NewReader(resp.String())).Decode(&describeTUResponse)
	if err != nil {
		log.Printf("Error Parsing Json object")
		return TrustedUpdateModeResponse{}, false
	}

	return describeTUResponse.DescribeTrustedUpdateModeResponse, true
}

// EndSession logs out of the session with the DSM
func (dsm DSM) EndSession() {
	url := fmt.Sprintf("%sauthentication/logout", dsm.RestURL)
	_, err := grequests.Delete(url, &grequests.RequestOptions{HTTPClient: &dsm.RestClient, Params: map[string]string{"sID": dsm.SessionID}})

	if err != nil {
		log.Println("Unable to make request", err)
	}

}

//onlyUnassigned is really bool which is not working so pass string true or false
func (dsm DSM) HostRecommendationRuleIDsRetrieve(hostID int, ruleType int, onlyUnassigned string) ([]int32, error) {

	hrrir := gowsdlservice.HostRecommendationRuleIDsRetrieve{HostID: int32(hostID), Type_: int32(ruleType), Onlyunassigned: onlyUnassigned, SID: dsm.SessionID}
	resp, err := dsm.SoapClient.HostRecommendationRuleIDsRetrieve(&hrrir)
	if err != nil {
		log.Println("Error retrieving host:", err)
	}

	if resp == nil {
		err = errors.New(fmt.Sprintf("Error retrieving host with id %d:", hostID))
		return nil, err
	} else {
		return resp.HostRecommendationRuleIDsRetrieveReturn, err
	}

}

func (dsm DSM) HostDetailRetrieve(hostID int, hostGroup int, securityProfileID int, hostType string, hostDetailLevel string) *gowsdlservice.HostDetailTransport {
	if hostDetailLevel == "" {
		hostDetailLevel = "HIGH"
	}

	var hdl gowsdlservice.EnumHostDetailLevel = ""

	if hostDetailLevel == "HIGH" {
		hdl = gowsdlservice.EnumHostDetailLevelHIGH
	} else if hostDetailLevel == "MEDIUM" {
		hdl = gowsdlservice.EnumHostDetailLevelMEDIUM
	} else {
		hdl = gowsdlservice.EnumHostDetailLevelLOW
	}

	var hostType2 string = "SPECIFIC_HOST"

	hft := gowsdlservice.HostFilterTransport{HostGroupID: int32(hostGroup), HostID: int32(hostID), SecurityProfileID: int32(securityProfileID), Type_: hostType2}
	hdr := gowsdlservice.HostDetailRetrieve{HostFilter: &hft, HostDetailLevel: &hdl, SID: dsm.SessionID}
	resp, err := dsm.SoapClient.HostDetailRetrieve(&hdr)
	if err != nil {
		log.Println("Error retrieving host:", err)
	}

	return resp.HostDetailRetrieveReturn[0]

}

func (dsm DSM) DPIRuleRetrieve(ruleID int) (*gowsdlservice.DPIRuleTransport, error) {
	dpiRuleRetrieve := gowsdlservice.DPIRuleRetrieve{Id: int32(ruleID), SID: dsm.SessionID}
	resp, err := dsm.SoapClient.DPIRuleRetrieve(&dpiRuleRetrieve)
	if err != nil {
		log.Println("Error could not retrieve dpi rule:", err)
	}

	if resp == nil {
		err = errors.New(fmt.Sprintf("Error retrieving rule with id %d:", ruleID))
		return nil, err
	} else {
		return resp.DPIRuleRetrieveReturn, err
	}
}

func (dsm DSM) DPIRuleRetrieveAll() ([]*gowsdlservice.DPIRuleTransport, error) {
	dpiRuleRetrieveAll := gowsdlservice.DPIRuleRetrieveAll{SID: dsm.SessionID}
	resp, err := dsm.SoapClient.DPIRuleRetrieveAll(&dpiRuleRetrieveAll)
	if err != nil {
		log.Println("Error could not retrieve dpi rule:", err)
	}

	if resp == nil {
		err = errors.New(fmt.Sprintf("Error retrieving all dpi rules"))
		return nil, err
	} else {
		return resp.DPIRuleRetrieveAllReturn, err
	}
}

// HostGroupCreate creates a host group. Pass -1 for parentGroupId if not associated with a parent group.
// If external is false externalID is ignored.
func (dsm DSM) HostGroupCreate(name string, external bool, externalID string, parentGroupId int32) (*gowsdlservice.HostGroupTransport, error) {
	hgt := gowsdlservice.HostGroupTransport{Name: name, External: external}
	if parentGroupId != -1 {
		hgt.ParentGroupID = parentGroupId
	}

	if external {
		hgt.ExternalID = externalID
	}

	hgc := gowsdlservice.HostGroupCreate{HostGroup: &hgt, SID: dsm.SessionID}
	resp, err := dsm.SoapClient.HostGroupCreate(&hgc)
	if err != nil {
		log.Println("Error creating host group:", err)
		return nil, err
	} else {
		return resp.HostGroupCreateReturn, nil
	}

}

// HostRetrieveAll retrieves all hosts from the DSM
// returns empty slice if none found or error occurs
func (dsm DSM) HostRetrieveAll() ([]*gowsdlservice.HostTransport, error) {
	hra := gowsdlservice.HostRetrieveAll{SID: dsm.SessionID}
	resp, err := dsm.SoapClient.HostRetrieveAll(&hra)
	if err != nil {
		return make([]*gowsdlservice.HostTransport, 0), errors.New("Unable to retrieve all hosts.")
	} else {
		return resp.HostRetrieveAllReturn, nil
	}
}

// HostRetrieveByHostGroup retrieves all hosts in a dsm group by id.
// returns empty slice if none found or error occurs
func (dsm DSM) HostRetrieveByHostGroup(hostGroupId int) ([]*gowsdlservice.HostTransport, error) {
	hrgh := gowsdlservice.HostRetrieveByHostGroup{HostGroupID: int32(hostGroupId), SID: dsm.SessionID}
	resp, err := dsm.SoapClient.HostRetrieveByHostGroup(&hrgh)
	if err != nil {
		return make([]*gowsdlservice.HostTransport, 0), errors.New("Host Group was not found.")
	} else {
		return resp.HostRetrieveByHostGroupReturn, nil
	}
}

// HostGroupRetrieveAll retrieves all hostgroups
// returns empty list if error or none found
func (dsm DSM) HostGroupRetrieveAll() ([]*gowsdlservice.HostGroupRetrieveAllReturnTransport, error) {
	hgra := gowsdlservice.HostGroupRetrieveAll{SID: dsm.SessionID}
	resp, err := dsm.SoapClient.HostGroupRetrieveAll(&hgra)
	if err != nil {
		return make([]*gowsdlservice.HostGroupRetrieveAllReturnTransport, 0), errors.New("Could not retreive host groups.")
	} else {
		return resp.HostGroupRetrieveAllReturn, nil
	}
}

// HostClearWarningsErrors clears warning and errors on a single host of list of hosts
// in all cases it returns an empty HostClearWarningsErrorsResponse object. note* I have yet to find error condition.
func (dsm DSM) HostClearWarningsErrors(hosts []int32) *gowsdlservice.HostClearWarningsErrorsResponse {
	hce := gowsdlservice.HostClearWarningsErrors{HostIDs: hosts, SID: dsm.SessionID}
	response, _ := dsm.SoapClient.HostClearWarningsErrors(&hce)
	return response
}

// HostGetStatus retrieves a host status transport for a host by id
// returns nil for HostStatusTransport if error found
func (dsm DSM) HostGetStatus(host int32) (*gowsdlservice.HostStatusTransport, error) {
	hgs := gowsdlservice.HostGetStatus{Id: host, SID: dsm.SessionID}
	response, err := dsm.SoapClient.HostGetStatus(&hgs)

	if err != nil {
		return nil, errors.New(fmt.Sprintf("Unable to get host status for host: %d", host))
	} else {
		return response.HostGetStatusReturn, nil
	}
}

// HostRecommendationScan initiates a host recommendation scan for an individual or list of hosts
// returns nil if no error found
func (dsm DSM) HostRecommendationScan(hosts []int32) error {
	hrs := gowsdlservice.HostRecommendationScan{HostIDs: hosts, SID: dsm.SessionID}
	_, err := dsm.SoapClient.HostRecommendationScan(&hrs)
	if err != nil {
		return errors.New(fmt.Sprintf("Error intiating host reccomentdation scan on hosts %d", hosts))
	} else {
		return nil
	}

}

// HostRetrieveByName retrieves a host by name
// returns nil if error or host not found
func (dsm DSM) HostRetrieveByName(hostName string) (*gowsdlservice.HostTransport, error) {
	hrbn := gowsdlservice.HostRetrieveByName{Hostname: hostName, SID: dsm.SessionID}
	resp, err := dsm.SoapClient.HostRetrieveByName(&hrbn)
	if err != nil || resp.HostRetrieveByNameReturn.Platform == "" {
		return nil, errors.New(fmt.Sprintf("Unable to retrieve host %s", hostName))
	} else {
		hostTransPort := resp.HostRetrieveByNameReturn
		return hostTransPort, nil
	}
}

// HostMoveToHostGroup moves list of hosts or single host to host group
// returns nil if error
func (dsm DSM) HostMoveToHostGroup(hostIDs []int32, hostGroupID int32) (*gowsdlservice.HostMoveToHostGroupResponse, error) {
	hmtg := gowsdlservice.HostMoveToHostGroup{HostIDs: hostIDs, HostGroupID: hostGroupID, SID: dsm.SessionID}
	resp, err := dsm.SoapClient.HostMoveToHostGroup(&hmtg)

	if err != nil {
		return nil, errors.New(fmt.Sprint("Unable to move hosts to host group: ", err))
	} else {
		return resp, nil
	}

}

func (dsm DSM) HostAgentActivate(hosts []int32) (*gowsdlservice.HostAgentActivateResponse, error) {
	haa := gowsdlservice.HostAgentActivate{HostIDs: hosts, SID: dsm.SessionID}
	resp, err := dsm.SoapClient.HostAgentActivate(&haa)

	if err != nil {
		return nil, errors.New(fmt.Sprint("Unable to activate host: ", err))
	} else {
		return resp, nil
	}
}

// AntiMalwareEventRetrieve retreives AM events by time and host filter
//
// timeType: options are "LAST_HOUR", "LAST_24_HOURS", "LAST_7_DAYS". if set range_from, range_to, timeType and specificTime are not to be specified.
//
// hostType: optional. options are "ALL_HOSTS", "HOSTS_IN_GROUP", "HOSTS_USING_SECURITY_PROFILE","HOSTS_IN_GROUP_AND_ALL_SUBGROUPS","SPECIFIC_HOST", "MY_HOSTS"
//
// eventOperator: options "GREATER_THAN", "LESS_THAN", "EQUAL". if not set will default to "GREATER_THAN"
//Note: specific times do not work
func (dsm DSM) AntiMalwareEventRetrieve(rangeFrom time.Time, rangeTo time.Time, specificTime time.Time, timeType string,
	hostID int, hostGroupID int, securityProfileID int, hostType string, eventID int,
	eventOperator string) ([]*gowsdlservice.AntiMalwareEventTransport, error) {

	tft := buildTimeFilterTransport(rangeFrom, rangeTo, specificTime, timeType)
	hft := builtHostFilterTransport(hostID, hostGroupID, securityProfileID, hostType)
	eidf := gowsdlservice.IDFilterTransport{Id: int32(eventID), Operator: eventOperator}
	amer := gowsdlservice.AntiMalwareEventRetrieve{TimeFilter: &tft, HostFilter: &hft, EventIdFilter: &eidf, SID: dsm.SessionID}
	resp, err := dsm.SoapClient.AntiMalwareEventRetrieve(&amer)

	if err != nil {
		return nil, errors.New(fmt.Sprint("Unable to retrieve AM events: ", err))
	} else {
		return resp.AntiMalwareEventRetrieveReturn.AntiMalwareEvents.Item, nil
	}

}

// SystemEventRetrieve retreives system events by time and host filter
//
// timeType: options are "LAST_HOUR", "LAST_24_HOURS", "LAST_7_DAYS". if set range_from, range_to, timeType and specificTime are not to be specified.
//
// hostType: optional. options are "ALL_HOSTS", "HOSTS_IN_GROUP", "HOSTS_USING_SECURITY_PROFILE","HOSTS_IN_GROUP_AND_ALL_SUBGROUPS","SPECIFIC_HOST", "MY_HOSTS"
//
// eventOperator: options "GREATER_THAN", "LESS_THAN", "EQUAL". if not set will default to "GREATER_THAN"
//Note: specific times do not work
func (dsm DSM) SystemEventRetrieve(rangeFrom time.Time, rangeTo time.Time, specificTime time.Time, timeType string,
	hostID int, hostGroupID int, securityProfileID int, hostType string, eventID int,
	eventOperator string, includeNonHostEvents bool) ([]*gowsdlservice.SystemEventTransport, error) {

	tft := buildTimeFilterTransport(rangeFrom, rangeTo, specificTime, timeType)
	hft := builtHostFilterTransport(hostID, hostGroupID, securityProfileID, hostType)
	idf := gowsdlservice.IDFilterTransport{Id: int32(eventID), Operator: eventOperator}
	ser := gowsdlservice.SystemEventRetrieve{TimeFilter: &tft, HostFilter: &hft, EventIdFilter: &idf, IncludeNonHostEvents: includeNonHostEvents, SID: dsm.SessionID}
	resp, err := dsm.SoapClient.SystemEventRetrieve(&ser)
	if err != nil {
		return nil, fmt.Errorf("error retrieving system event:", err)
	}

	return resp.SystemEventRetrieveReturn.SystemEvents.Item, nil

}

func builtHostFilterTransport(hostID int, hostGroupID int, securityProfileID int, hostType string) gowsdlservice.HostFilterTransport {
	hft := gowsdlservice.HostFilterTransport{}
	if hostID != 0 {
		hft.HostID = int32(hostID)
		hft.Type_ = "SPECIFIC_HOST"
	} else if hostGroupID != 0 {
		hft.HostGroupID = int32(hostGroupID)
		hft.Type_ = "HOSTS_IN_GROUP"
	} else if securityProfileID != 0 {
		hft.SecurityProfileID = int32(securityProfileID)
		hft.Type_ = "HOSTS_USING_SECURITY_PROFILE"
	} else {
		hft.Type_ = "ALL_HOSTS"
	}

	return hft

}

func buildTimeFilterTransport(rangeFrom time.Time, rangeTo time.Time, specificTime time.Time, timeType string) gowsdlservice.TimeFilterTransport {
	tft := gowsdlservice.TimeFilterTransport{}

	if rangeFrom == (time.Time{}) && rangeTo == (time.Time{}){
		tft.Type_ = timeType
	}else if rangeFrom.Year() == 0001 && specificTime.Year() == 001 {
		if timeType == "" {
			tft.Type_ = "LAST_HOUR"
		} else {
			tft.Type_ = timeType
		}
	} else if rangeFrom.Year() != 0001 && rangeTo.Year() != 0001 {
		tft.RangeFrom = rangeFrom //rangeFrom.Format("2006-01-02 15:04:05")
		tft.RangeTo = rangeTo     //rangeTo.Format("2006-01-02 15:04:05")
		tft.Type_ = "CUSTOM_RANGE"
	} else if specificTime.Year() != 0001 {
		tft.SpecificTime = specificTime //specificTime.Format("2006-01-02 15:04:05")
		tft.Type_ = "SPECIFIC_TIME"
	}
	return tft
}
