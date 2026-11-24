package messaging

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/eclipse-xfsc/nats-message-library/common"
)

const (
	MessageTypeTenantManagement        = "tenant.management"
	TenantIdentityCreate               = "tenant.management.identity.create"
	TenantIdentityUpdate               = "tenant.management.identity.update"
	TenantIdentityDelete               = "tenant.management.identity.delete"
	TenantIdentityAppCreate            = "tenant.management.identity.app.create"
	TenantIdentityAppUpdate            = "tenant.management.identity.app.update"
	TenantIdentityAppDelete            = "tenant.management.identity.app.delete"
	TenantIdentityUserCreated          = "tenant.management.identity.user.created"
	TenantIdentityUserDeleted          = "tenant.management.identity.user.deleted"
	TenantIdentityUserCreatedEventType = "org.eclipse.xfsc.identity.user.created"
	TenantIdentityUserDeletedEventType = "org.eclipse.xfsc.identity.user.deleted"
)

type TenantIdentityRequest struct {
	common.Request
	Enabled             *bool  `json:"enabled,omitempty"`
	RegistrationAllowed *bool  `json:"registrationAllowed,omitempty"`
	DisplayName         string `json:"displayName,omitempty"`
}

type TenantIdentityDeleteRequest struct{ common.Request }

type TenantIdentityAppRequest struct {
	common.Request
	AppId         string                       `json:"appId"`
	Name          string                       `json:"name,omitempty"`
	Enabled       *bool                        `json:"enabled,omitempty"`
	Authorization *TenantIdentityAuthorization `json:"authorization,omitempty"`
	Client        *TenantIdentityClient        `json:"client,omitempty"`
}

type TenantIdentityAppDeleteRequest struct {
	common.Request
	AppId string `json:"appId"`
}

type TenantIdentityAuthorization struct {
	GrantTypes   []string `json:"grantTypes,omitempty"`
	RedirectURIs []string `json:"redirectUris,omitempty"`
	PKCERequired bool     `json:"pkceRequired"`
	PKCEMethod   string   `json:"pkceMethod,omitempty"`
}

type TenantIdentityClient struct {
	Type string `json:"type"`
}
type TenantIdentityReply struct{ common.Reply }
type TenantIdentityAppReply struct {
	common.Reply
	AppID string `json:"appId,omitempty"`
}

func validateTenant(r common.Request) error {
	if strings.TrimSpace(r.TenantId) == "" {
		return errors.New("tenant_id is required")
	}
	if strings.TrimSpace(r.RequestId) == "" {
		return errors.New("request_id is required")
	}
	return nil
}

func (r TenantIdentityRequest) Validate() error       { return validateTenant(r.Request) }
func (r TenantIdentityDeleteRequest) Validate() error { return validateTenant(r.Request) }
func (r TenantIdentityAppDeleteRequest) Validate() error {
	if err := validateTenant(r.Request); err != nil {
		return err
	}
	if strings.TrimSpace(r.AppId) == "" {
		return errors.New("appId is required")
	}
	return nil
}

// Validate checks the mandatory identifiers and any supplied application configuration.
// For create operations, use ValidateCreate to require full OIDC configuration.
func (r TenantIdentityAppRequest) Validate() error {
	if err := validateTenant(r.Request); err != nil {
		return err
	}
	if strings.TrimSpace(r.AppId) == "" {
		return errors.New("appId is required")
	}
	if r.Client != nil && r.Client.Type != "public" && r.Client.Type != "confidential" {
		return errors.New("client.type must be public or confidential")
	}
	if a := r.Authorization; a != nil {
		for _, grant := range a.GrantTypes {
			if grant != "authorization_code" {
				return fmt.Errorf("unsupported grant type %q", grant)
			}
		}
		for _, raw := range a.RedirectURIs {
			u, err := url.Parse(raw)
			if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
				return fmt.Errorf("invalid redirect URI %q", raw)
			}
			if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "[::1]" || u.Hostname() == "::1")) {
				return fmt.Errorf("redirect URI must use HTTPS except loopback: %q", raw)
			}
		}
		if a.PKCEMethod != "" && a.PKCEMethod != "S256" {
			return errors.New("pkceMethod must be S256")
		}
		if a.PKCERequired && a.PKCEMethod != "S256" {
			return errors.New("pkceMethod must be S256 when PKCE is required")
		}
	}
	return nil
}

func (r TenantIdentityAppRequest) ValidateCreate() error {
	if err := r.Validate(); err != nil {
		return err
	}
	if r.Client == nil {
		return errors.New("client is required")
	}
	if r.Authorization == nil {
		return errors.New("authorization is required")
	}
	a := r.Authorization
	if len(a.GrantTypes) != 1 || a.GrantTypes[0] != "authorization_code" {
		return errors.New("authorization_code grant is required")
	}
	if len(a.RedirectURIs) == 0 {
		return errors.New("at least one redirect URI is required")
	}
	if r.Client.Type == "public" && (!a.PKCERequired || a.PKCEMethod != "S256") {
		return errors.New("public clients require PKCE S256")
	}
	return nil
}

// TenantIdentityUserEvent contains user information from an identity provider.
type TenantIdentityUserEvent struct {
	RealmID   string `json:"realmId"`
	UserID    string `json:"userId"`
	Email     string `json:"email,omitempty"`
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
}

func (e TenantIdentityUserEvent) Validate() error {
	if strings.TrimSpace(e.RealmID) == "" {
		return errors.New("realmId is required")
	}
	if strings.TrimSpace(e.UserID) == "" {
		return errors.New("userId is required")
	}
	return nil
}

// TenantIdentityUserCloudEvent models the structured CloudEvents 1.0 JSON payload.
type TenantIdentityUserCloudEvent struct {
	SpecVersion     string                  `json:"specversion"`
	ID              string                  `json:"id"`
	Source          string                  `json:"source"`
	Type            string                  `json:"type"`
	Subject         string                  `json:"subject,omitempty"`
	Time            time.Time               `json:"time"`
	DataContentType string                  `json:"datacontenttype,omitempty"`
	Data            TenantIdentityUserEvent `json:"data"`
}

func (e TenantIdentityUserCloudEvent) Validate() error {
	if e.SpecVersion != "1.0" {
		return errors.New("specversion must be 1.0")
	}
	if strings.TrimSpace(e.ID) == "" {
		return errors.New("CloudEvent id is required")
	}
	if strings.TrimSpace(e.Source) == "" {
		return errors.New("CloudEvent source is required")
	}
	switch e.Type {
	case TenantIdentityUserCreatedEventType, TenantIdentityUserDeletedEventType:
	default:
		return fmt.Errorf("unsupported user event type %q", e.Type)
	}
	if e.DataContentType != "" && e.DataContentType != "application/json" {
		return errors.New("datacontenttype must be application/json")
	}
	if err := e.Data.Validate(); err != nil {
		return fmt.Errorf("invalid user event data: %w", err)
	}
	if e.Subject != "" && e.Subject != e.Data.UserID {
		return errors.New("CloudEvent subject must match userId")
	}
	return nil
}

func ParseTenantIdentityUserEvent(payload []byte) (*TenantIdentityUserCloudEvent, error) {
	var event TenantIdentityUserCloudEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return nil, fmt.Errorf("decode user CloudEvent: %w", err)
	}
	if err := event.Validate(); err != nil {
		return nil, err
	}
	return &event, nil
}

func ParseTenantIdentityUserEventForSubject(subject string, payload []byte) (*TenantIdentityUserCloudEvent, error) {
	event, err := ParseTenantIdentityUserEvent(payload)
	if err != nil {
		return nil, err
	}
	var expectedType string
	switch subject {
	case TenantIdentityUserCreated:
		expectedType = TenantIdentityUserCreatedEventType
	case TenantIdentityUserDeleted:
		expectedType = TenantIdentityUserDeletedEventType
	default:
		return nil, fmt.Errorf("unsupported identity user subject %q", subject)
	}
	if event.Type != expectedType {
		return nil, fmt.Errorf("CloudEvent type %q does not match NATS subject %q", event.Type, subject)
	}
	return event, nil
}
