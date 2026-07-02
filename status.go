package messaging

import "github.com/eclipse-xfsc/nats-message-library/common"

const (
	EventTypeStatus       = "status.data"
	TopicStatusData       = "status.data.create"
	TopicStatusDataVerify = "status.data.verify"
)

type CreateStatusListEntryRequest struct {
	common.Request
	Origin string `json:"origin"`
	// Signer binding for the status list.
	// Diese Werte bleiben für die erzeugte Liste stabil.
	Key       string `json:"key"`
	DID       string `json:"did"`
	Namespace string `json:"namespace"`
	// Optional, aber praktisch für Signer-Service / OCM-Kontext.
	Group string `json:"group,omitempty"`
	// Optional: StatusList2021, statuslist+jwt, etc.
	Type    string `json:"type,omitempty"`
	Purpose string `json:"purpose,omitempty"`
}

type CreateStatusListEntryReply struct {
	common.Reply
	Index     int    `json:"index"`
	StatusUrl string `json:"statusUrl"`
	Type      string `json:"type"`
	Purpose   string `json:"purpose"`
}

type VerifyStatusListEntryRequest struct {
	common.Request
	Index     int    `json:"index"`
	StatusUrl string `json:"statusUrl"`
	Type      string `json:"type"`
	Purpose   string `json:"purpose"`
}

type VerifyStatusListEntryReply struct {
	common.Reply
	Revocated bool `json:"revocated"`
	Suspended bool `json:"suspended"`
}
