package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/go-ldap/ldap"
)

// Authenticator authenticates a user against an LDAP directory
type Authenticator interface {
	Authenticate(username, password string) (*AuthenticationResult, error)
}

// Client represents a connection, and associated lookup strategy,
// for authentication via an LDAP server.
type Client struct {
	BaseDN             string
	LdapServer         string
	LdapPort           uint
	AllowInsecure      bool
	UserLoginAttribute string
	GroupsAttribute 	 string
	Attributes 				 []string
	SearchUserDN       string
	SearchUserPassword string
	TLSConfig          *tls.Config
}

type AuthenticationResult struct {
	LdapEntry *ldap.Entry
	Username string
	Groups []string
}

// Authenticate a user against the LDAP directory. Returns an LDAP entry if password
// is valid, otherwise returns an error.
func (c *Client) Authenticate(username, password string) (*AuthenticationResult, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, fmt.Errorf("Error opening LDAP connection: %v", err)
	}
	defer conn.Close()

	// Bind user to perform the search
	if c.SearchUserDN != "" && c.SearchUserPassword != "" {
		err = conn.Bind(c.SearchUserDN, c.SearchUserPassword)
	} else {
		err = conn.Bind(username, password)
	}
	if err != nil {
		return nil, fmt.Errorf("Error binding user to LDAP server: %v", err)
	}

	req := c.newUserSearchRequest(username)

	// Do a search to ensure the user exists within the BaseDN scope
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("Error searching for user %s: %v", username, err)
	}

	switch {
	case len(res.Entries) == 0:
		return nil, fmt.Errorf("No result for the search filter '%s'", req.Filter)
	case len(res.Entries) > 1:
		return nil, fmt.Errorf("Multiple entries found for the search filter '%s': %+v", req.Filter, res.Entries)
	}

  // TODO(sbower): how I'd like to move this after the bind but this won't work if bound
	//               as the user itself in most cases
	groupCNs, err := c.lookupGroupCNs(conn, res.Entries[0])
	if err != nil {
		return nil, fmt.Errorf("Error retrieving group CNs: %v", err)
	}

	entry := res.Entries[0]

	// Now that we know the user exists within the BaseDN scope
	// let's do user bind to check credentials using the full DN instead of
	// the attribute used for search
	if c.SearchUserDN != "" && c.SearchUserPassword != "" {
		err = conn.Bind(entry.DN, password)
		if err != nil {
			return nil, fmt.Errorf("Error binding user %s, invalid credentials: %v", username, err)
		}
	}

	ldapUsername := entry.GetAttributeValue(c.UserLoginAttribute)

	filteredAttrs := []*ldap.EntryAttribute{}
	if c.Attributes != nil && len(c.Attributes) > 0 {
		for _, attrName := range c.Attributes {
			for _, attr := range entry.Attributes {
				if attr.Name == attrName {
					filteredAttrs = append(filteredAttrs, attr)
				}
			}
		}
	}
	entry.Attributes = filteredAttrs

	authRes := &AuthenticationResult{
		Username: ldapUsername,
		Groups: groupCNs,
		LdapEntry: res.Entries[0],
	}

	// Single user entry found
	return authRes, nil
}

// Create a new TCP connection to the LDAP server
func (c *Client) dial() (*ldap.Conn, error) {
	address := fmt.Sprintf("%s:%d", c.LdapServer, c.LdapPort)

	if c.TLSConfig != nil {
		return ldap.DialTLS("tcp", address, c.TLSConfig)
	}

	// This will send passwords in clear text (LDAP doesn't obfuscate password in any way),
	// thus we use a flag to enable this mode
	if c.TLSConfig == nil && c.AllowInsecure {
		return ldap.Dial("tcp", address)
	}

	// TLSConfig was not specified, and insecure flag not set
	return nil, errors.New("The LDAP TLS Configuration was not set.")
}

func (c *Client) newUserSearchRequest(username string) *ldap.SearchRequest {
	// TODO(abrand): sanitize
	userFilter := fmt.Sprintf("(%s=%s)", c.UserLoginAttribute, username)

  attr := mergeLists([]string{"dn", c.GroupsAttribute, c.UserLoginAttribute}, c.Attributes)

	return &ldap.SearchRequest{
		BaseDN:       c.BaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases, // ????
		SizeLimit:    2,
		TimeLimit:    10, // make configurable?
		TypesOnly:    false,
		Filter:       userFilter,
		Attributes:   attr,
	}
}

func (c *Client) lookupGroupCNs(conn *ldap.Conn, entry *ldap.Entry) ([]string, error) {
	groupDNs := entry.GetAttributeValues(c.GroupsAttribute)

	groups := []string{}

	//groupFilter := "(|("+strings.Join(groupDNs, ")(")+"))"
	for _, g := range groupDNs {
		req := &ldap.SearchRequest{
			BaseDN:       g,
			Scope:        ldap.ScopeBaseObject,
			DerefAliases: ldap.NeverDerefAliases, // ????
			SizeLimit:    2,
			TimeLimit:    10, // make configurable?
			TypesOnly:    false,
			Filter:				"(objectclass=*)",
			Attributes:   []string{"dn","cn"},
		}

		res, err := conn.Search(req)
		if err != nil {
			return nil, fmt.Errorf("Error searching for groups %s: %v", g, err)
		}

		switch {
		case len(res.Entries) == 0:
			return nil, fmt.Errorf("No result for DN '%s'", g)
		case len(res.Entries) > 1:
			return nil, fmt.Errorf("Multiple entries found for the DN '%s': %+v", g, res.Entries)
		}

		cn := res.Entries[0].GetAttributeValue("cn")
		groups = append(groups,cn)
	}

	return groups,nil
}

func mergeLists(lists ...[]string) ([]string) {
	m := map[string]bool{}
  for _, l := range lists {
    if l != nil {
      for _, v := range l {
        m[v] = true
      }
    }
  }

	out := make([]string, len(m))
	i := 0
	for k := range m {
	    out[i] = k
			i++
	}
  return out
}
