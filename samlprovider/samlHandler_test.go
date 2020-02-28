package samlprovider

import (
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gotest.tools/assert"
	"net/http"
	"net/url"
	"testing"
)

var (
	samlHandler *SamlHandler
)

func TestSamlHandler(t *testing.T) {
	setup()
	t.Run("Test IssamlRequest", testIsSamlRequest)
	t.Run("Test GetSessionId", testGetSessionId)
}

func setup() {
	c := new(SamlServiceProviderConfig)
	c.SamlMetadataPath = "/saml/metadata"
	c.SamlLogoutPath = "/saml/logout"
	c.SamlSLOPath = "/saml/SLO"
	c.SamlSSOPath = "/saml/SSO"
	c.SessionHeaderName = "MySessionCookie"
	c.ExternalUrl = "http://localhost:8787"
	c.CookieDomain = ""
	c.CookiePath = "/"
	c.Logger = zap.NewNop().Sugar()
	samlHandler = NewSamlHandler(c, nil)
}

func testGetSessionId(t *testing.T) {
	headerWithCookie := http.Header{}
	sessionId := uuid.New().String()
	headerWithCookie.Add("Cookie", samlHandler.sessionHeaderName+"="+sessionId+";")
	foundInCookie, err := samlHandler.GetSessionId(&http.Request{Header: headerWithCookie})
	assert.NilError(t, err)
	assert.Equal(t, sessionId, foundInCookie)

	header := http.Header{}
	header.Add(samlHandler.sessionHeaderName, sessionId)
	foundInHeader, err := samlHandler.GetSessionId(&http.Request{Header: header})
	assert.NilError(t, err)
	assert.Equal(t, sessionId, foundInHeader)

	headerWithNoSession := http.Header{}
	notFound, err := samlHandler.GetSessionId(&http.Request{Header: headerWithNoSession})
	assert.NilError(t, err)
	assert.Equal(t, "", notFound)

}

func testIsSamlRequest(t *testing.T) {
	assert.Assert(t, samlHandler.isSamlProtocol(&http.Request{URL: &url.URL{Path: samlHandler.metadataPath}}))
	assert.Assert(t, samlHandler.isSamlProtocol(&http.Request{URL: &url.URL{Path: samlHandler.logoutPath}}))
	assert.Assert(t, samlHandler.isSamlProtocol(&http.Request{URL: &url.URL{Path: samlHandler.callbackPath}}))
	assert.Assert(t, samlHandler.isSamlProtocol(&http.Request{URL: &url.URL{Path: samlHandler.sloCallbackPath}}))
	assert.Assert(t, !samlHandler.isSamlProtocol(&http.Request{URL: &url.URL{Path: "/noget" + samlHandler.sloCallbackPath}}))
	assert.Assert(t, !samlHandler.isSamlProtocol(&http.Request{URL: &url.URL{Path: "/saml"}}))

}
