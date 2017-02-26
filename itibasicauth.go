package itibasicauth

import (
	"encoding/base64"
	"net/http"
	"strings"
)

// BasicAuthMatcher Store the credentials to match with the request
type BasicAuthMatcher struct {
	username string
	password string
}

// New is the constructor to ItiBasicAuth
func New(username, password string) *BasicAuthMatcher {
	return &BasicAuthMatcher{username: username, password: password}
}

// Match if the request are using one the provided credentials.
func (ba *BasicAuthMatcher) Match(req *http.Request) bool {
	if ba.username == "" || ba.password == "" {
		return true
	}
	auth := req.Header.Get("Authorization")
	p := strings.Split(auth, " ")
	if len(p) != 2 {
		return false
	}
	if p[0] != "Basic" {
		return false
	}

	decode, err := base64.StdEncoding.DecodeString(p[1])
	if err != nil {
		return false
	}
	cred := strings.Split(string(decode), ":")
	return cred[0] == ba.username && cred[1] == ba.password
}
