package messaging

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/eclipse-xfsc/nats-message-library/common"
)

func TestTenantIdentityRequestUsesCommonTenantID(t *testing.T) {
	r := TenantIdentityRequest{Request: common.Request{TenantId: "demo", RequestId: "r1"}}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"tenant_id":"demo"`) || strings.Contains(string(b), `"tenantId"`) {
		t.Fatalf("unexpected JSON: %s", b)
	}
}
func TestAppCreateValidation(t *testing.T) {
	r := TenantIdentityAppRequest{
		Request: common.Request{TenantId: "demo", RequestId: "r1"}, AppId: "portal",
		Client:        &TenantIdentityClient{Type: "public"},
		Authorization: &TenantIdentityAuthorization{GrantTypes: []string{"authorization_code"}, RedirectURIs: []string{"https://example.org/callback"}, PKCERequired: true, PKCEMethod: "S256"},
	}
	if err := r.ValidateCreate(); err != nil {
		t.Fatal(err)
	}
	r.Authorization.RedirectURIs = []string{"https://*.example.org/callback"}
	if err := r.ValidateCreate(); err == nil {
		t.Fatal("wildcard redirect accepted")
	}
	r.Authorization.RedirectURIs = []string{"https://example.org/callback"}
	r.Authorization.PKCERequired = false
	if err := r.ValidateCreate(); err == nil {
		t.Fatal("public client without PKCE accepted")
	}
}
func TestDeleteValidation(t *testing.T) {
	r := TenantIdentityAppDeleteRequest{Request: common.Request{TenantId: "demo", RequestId: "r1"}}
	if r.Validate() == nil {
		t.Fatal("missing appId accepted")
	}
	r.AppId = "portal"
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
}
