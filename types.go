package deepsecurity

import (

)

type JsonDescribeTrustedUpdateModeResponse struct {
	DescribeTrustedUpdateModeResponse TrustedUpdateModeResponse `json: "DescribeTrustedUpdateModeResponse"`
}

type TrustedUpdateModeResponse struct {
	State string `json: "state"`
}
