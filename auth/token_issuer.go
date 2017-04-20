package auth

import (
	"net/http"

	"github.com/golang/glog"
	"github.com/kismatic/kubernetes-ldap/ldap"
	"github.com/kismatic/kubernetes-ldap/token"
)

// LDAPTokenIssuer issues cryptographically secure tokens after authenticating the
// user against a backing LDAP directory.
type LDAPTokenIssuer struct {
	LDAPServer        string
	LDAPAuthenticator ldap.Authenticator
	TokenSigner       token.Signer
}

func (lti *LDAPTokenIssuer) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	user, password, ok := req.BasicAuth()
	if !ok {
		resp.Header().Add("WWW-Authenticate", `Basic realm="kubernetes ldap"`)
		resp.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Authenticate the user via LDAP
	authRes, err := lti.LDAPAuthenticator.Authenticate(user, password)
	if err != nil {
		glog.Errorf("Error authenticating user: %v", err)
		resp.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Auth was successful, create token
	token := lti.createToken(authRes)

	// Sign token and return
	signedToken, err := lti.TokenSigner.Sign(token)
	if err != nil {
		glog.Errorf("Error signing token: %v", err)
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp.Header().Add("Content-Type", "text/plain")
	resp.Write([]byte(signedToken))
}

func (lti *LDAPTokenIssuer) createToken(authResult *ldap.AuthenticationResult) *token.AuthToken {
	ldapEntry := authResult.LdapEntry

	attrMap := map[string][]string {
		"ldapServer": []string{lti.LDAPServer},
	}

	if ldapEntry != nil {
		attrMap["userDN"] = []string{authResult.LdapEntry.DN}
	}

	// TODO(sbower) strip out all ldap stuff
	if ldapEntry != nil && ldapEntry.Attributes != nil {
		for _, attr := range ldapEntry.Attributes {
			attrMap[attr.Name] = attr.Values
		}
	}

	return &token.AuthToken{
		Username: authResult.Username,
		Groups: authResult.Groups,
		Assertions: attrMap,
	}
}
