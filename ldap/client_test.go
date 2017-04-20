package ldap

import (
  "gopkg.in/ory-am/dockertest.v3"
  "testing"
  "strconv"
	"log"
	"os"
	"fmt"
	//"github.com/go-ldap/ldap"
)

type LdapServer struct {
	Hostname string
	Port uint
	Pool *dockertest.Pool
	Resource *dockertest.Resource
}

var ldapServer *LdapServer
func TestMain(m *testing.M) {
	var err error

  ldapHost := "localhost"
	ldapServer, err = startLdapServer(ldapHost)
	if err != nil {
  	os.Exit(-1)
	}

	res := m.Run()

	err = stopLdapServer(ldapServer)
	if err != nil {
  	os.Exit(-1)
	}

  os.Exit(res)
}

func TestLdap(t *testing.T) {
	ldapClient, err := createClient(ldapServer.Hostname, ldapServer.Port)
  if err != nil {
    t.Errorf("Failed to create client: %v", err)
  }

  authRes, err := ldapClient.Authenticate("user1", "pass1")
  if err != nil {
    t.Errorf("Failed to auth: %v", err)
  }

	fmt.Printf("Authentication Result: %v\n", authRes)
}

func stopLdapServer(server *LdapServer) (error) {
  err := ldapServer.Pool.Purge(ldapServer.Resource)
  if err != nil {
    log.Fatalf("Failed to purge: %v", err)
		return err
  }
	return nil
}

func startLdapServer(host string) (*LdapServer, error) {

  pool, err := dockertest.NewPool("")
  if err != nil {
    log.Fatalf("Could not connect to docker: %s", err)
		return nil, err
  }

	options := &dockertest.RunOptions{
		Repository: "kubernetes-ldap/openldap-test",
		Tag:        "0.1.0",
	}

  resource, err := pool.RunWithOptions(options)
  if err != nil {
    log.Fatalf("Could not start ldap server: %s", err)
		return nil, err
  }

	ldp, err := strconv.ParseUint(resource.GetPort("389/tcp"), 10, 32)
  if err != nil {
    log.Fatalf("Could not get container port: %v", err)
		return nil, err
	}
	port := uint(ldp)

  if err := pool.Retry(func() error {
			var err error
			cl, err := createClient(host, port)
			if err != nil {
				return err;
			}

			conn, err := cl.dial()
			if err != nil {
				return err
			}
			defer conn.Close()

			err = conn.Bind(cl.SearchUserDN, cl.SearchUserPassword)
			if err != nil {
				return err
			}
			return nil
  }); err != nil {
    log.Fatalf("Could not connect to docker: %s", err)
		return nil, err
  }

	server := &LdapServer {
		Pool: pool,
		Port: port,
		Resource: resource,
	}
	return server, nil
}

func createClient(ldapHost string, ldapPort uint) (*Client, error) {
  ldapClient := &Client{
    BaseDN:             "ou=people,dc=example,dc=org",
    LdapServer:         ldapHost,
    LdapPort:           ldapPort,
    AllowInsecure:      true,
    UserLoginAttribute: "uid",
    GroupsAttribute:    "memberOf",
    SearchUserDN:       "cn=admin,dc=example,dc=org",
    SearchUserPassword: "admin",
    TLSConfig:          nil,
		Attributes: 				[]string{"uidNumber", "gidNumber"},
  }

  return ldapClient, nil
}
