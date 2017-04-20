package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"reflect"

	goldap "github.com/go-ldap/ldap"
	"github.com/kismatic/kubernetes-ldap/token"
	"github.com/kismatic/kubernetes-ldap/ldap"
)

type dummyLDAP struct {
	authResult *ldap.AuthenticationResult
	err   error
}

func (d dummyLDAP) Authenticate(username, password string) (*ldap.AuthenticationResult, error) {
	return d.authResult, d.err
}

type dummySigner struct {
	signed string
	err    error
}

func (d dummySigner) Sign(token *token.AuthToken) (string, error) {
	return d.signed, d.err
}

func TestTokenIssuer(t *testing.T) {
	cases := []struct {
		basicAuth    bool
		authResult    *ldap.AuthenticationResult
		expectedCode int
		ldapErr      error
		signerErr    error
	}{
		{
			// Happy path, user was authenticated against LDAP server
			basicAuth:    true,
			authResult:    &ldap.AuthenticationResult{},
			expectedCode: http.StatusOK,
		},
		{
			// Invalid LDAP creds provided by user
			basicAuth:    true,
			ldapErr:      errors.New("Invalid username/password"),
			expectedCode: http.StatusUnauthorized,
		},
		{
			// User did not provide credentials via Basic Auth
			basicAuth:    false,
			expectedCode: http.StatusUnauthorized,
		},
		{
			// Signing token failed
			basicAuth:    true,
			expectedCode: http.StatusInternalServerError,
			authResult:    &ldap.AuthenticationResult{},
			signerErr:    errors.New("Something failed while signing token"),
		},
	}

	for i, c := range cases {
		lti := LDAPTokenIssuer{
			LDAPAuthenticator: dummyLDAP{c.authResult, c.ldapErr},
			TokenSigner:       dummySigner{"signedToken", c.signerErr},
		}

		req, err := http.NewRequest("GET", "", nil)
		if err != nil {
			t.Errorf("Case: %d. Failed to create request: %v", i, err)
		}
		if c.basicAuth {
			req.SetBasicAuth("user", "password")
		}

		rec := httptest.NewRecorder()
		lti.ServeHTTP(rec, req)

		if rec.Code != c.expectedCode {
			t.Errorf("Case: %d. Expected %d, got %d", i, c.expectedCode, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "signedToken") && c.expectedCode == http.StatusOK {
			t.Errorf("Case: %d. body did not contain expected token. body contents: %q", i, rec.Body.String())
		}
	}
}

func TestCreateToken(t *testing.T) {
	authRes := &ldap.AuthenticationResult{
		LdapEntry: &goldap.Entry{
			DN: "some-dn",
			Attributes: []*goldap.EntryAttribute{},
		},
		Username: "user1",
		Groups: []string{"group1", "group3"},
	}
	lti := &LDAPTokenIssuer{
		LDAPServer: "some-ldap-server",
	}
	expectedAssertions := map[string][]string{
		"ldapServer": []string{lti.LDAPServer},
		"userDN":     []string{authRes.LdapEntry.DN},
	}

	tok := lti.createToken(authRes)
	if tok.Username != authRes.Username {
		t.Errorf("Unexpected username in token. Expected: '%s'. Got: '%s'.", authRes.Username, tok.Username)
	}

	if !reflect.DeepEqual(tok.Groups, authRes.Groups) {
		t.Errorf("Unexpected groups in token. Expected: '%s'. Got: '%s'.", authRes.Groups, tok.Groups)
	}

	for k, v := range expectedAssertions {
		if !reflect.DeepEqual(tok.Assertions[k], v) {
			t.Errorf("Expected assertion '%s' to be '%s'. Got '%s'", k, v, tok.Assertions[k])
		}
	}
}
