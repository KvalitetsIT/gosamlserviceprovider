package gosamlserviceprovider

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
	c.SamlMetadataUrl = "/saml/metadata"
	c.SamlLogoutUrl = "/saml/logout"
	c.SamlCallbackUrl = "/saml/SSO"
	c.SessionHeaderName = "MySessionCookie"
	c.SLOConsumerServiceUrl = "http://localhost:8787/saml/SSO"
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
	assert.Assert(t, samlHandler.isSamlProtocol(&http.Request{URL: &url.URL{Path: samlHandler.metadataUrl}}))
	assert.Assert(t, samlHandler.isSamlProtocol(&http.Request{URL: &url.URL{Path: samlHandler.logoutUrl}}))
	assert.Assert(t, samlHandler.isSamlProtocol(&http.Request{URL: &url.URL{Path: samlHandler.callbackUrl}}))
	assert.Assert(t, samlHandler.isSamlProtocol(&http.Request{URL: &url.URL{Path: samlHandler.sloCallbackUrl}}))
	assert.Assert(t, !samlHandler.isSamlProtocol(&http.Request{URL: &url.URL{Path: "/noget" + samlHandler.sloCallbackUrl}}))
	assert.Assert(t, !samlHandler.isSamlProtocol(&http.Request{URL: &url.URL{Path: "/saml"}}))

}