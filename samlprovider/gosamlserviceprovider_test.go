package samlprovider

import (
	"crypto/tls"
	"fmt"
	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gotest.tools/assert"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

var (
	httpServer          *httptest.Server
	service             securityprotocol.HttpHandler
	validSessionId      string
	samlServiceProvider *SamlServiceProvider
)

func TestSaml(t *testing.T) {
	httpServer = startHttpServer()
	t.Run("Test SAML Metadata", samlMetadata)
	t.Run("Test Loginflow without sessionId", loginFlow_Basic)
	t.Run("Test Loginflow with sessionId Cookie doesn't trigger login", valid_SessionId_Cookie)
	t.Run("Test Loginflow with sessionId Header doesn't trigger login", valid_SessionId_Header)
	t.Run("Test LoginFlow with invalid sessionId", invalid_SessionId_TriggersLogin)

	//TODO test logout flow
	httpServer.Close()
}

func TestBuildUrl(t *testing.T) {
	assert.Equal(t, "http://localhost:665/test/saml/sso", buildUrl("http://localhost:665/test/", "/saml/sso"))
	assert.Equal(t, "http://localhost:665/test/saml/sso", buildUrl("http://localhost:665/test", "saml/sso"))
	assert.Equal(t, "http://localhost:665/test/saml/sso", buildUrl("http://localhost:665/test", "/saml/sso"))
	assert.Equal(t, "http://localhost:665/test/saml/sso", buildUrl("http://localhost:665/test/", "saml/sso"))
}

func TestVenligLoginMetadata(t *testing.T) {
	config := &SamlServiceProviderConfig{}
	config.Logger = zap.NewNop().Sugar()
	bytes, _ := ioutil.ReadFile("./testdata/venligdata.xml")
	metadata, _ := EntityDescriptor(bytes)
	assert.Equal(t, string(bytes), string(metadata))
}

func samlMetadata(t *testing.T) {
	httpClient := httpServer.Client()
	metadataRequest, _ := http.NewRequest("GET", "http://localhost:8787/saml/metadata", nil)
	response, _ := httpClient.Do(metadataRequest)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	responseBody, _ := ioutil.ReadAll(response.Body)
	assert.Check(t, strings.HasPrefix(string(responseBody), "<EntityDescriptor"))
}

/**
This method tests the complete login flow
* An unauthenticated user request a resource on the server
* The user is redirected by the SAML to the Keycloak login screen
* The user enters a valid username and password
* The user is redirected to the callback url
* The SAML module validates the SAML response from keycloak
* After validating the SAML response the user is logged in and receives data from the embedded service
*/
func loginFlow_Basic(t *testing.T) {
	requestedPath := "/test/redirect?noget=1"
	httpClient := httpServer.Client()
	cookieJar, _ := cookiejar.New(nil)
	httpClient.Jar = cookieJar
	res, err := httpClient.Get(httpServer.URL + requestedPath)
	if err != nil {
		panic(err)
	}
	assert.Equal(t, http.StatusOK, res.StatusCode)
	loginResponse := createLoginRequest(httpClient, res, "eva", "kuk")
	assert.Equal(t, http.StatusOK, loginResponse.StatusCode)
	loginResponseBody, _ := ioutil.ReadAll(loginResponse.Body)
	samlResponse := extractString(string(loginResponseBody), "name=\"SAMLResponse\" value=\"", "\"/>")
	relayState := extractString(string(loginResponseBody), "name=\"RelayState\" value=\"", "\"/>")
	callbackURL := extractString(string(loginResponseBody), "action=\"", "\">")
	callbackResponse := doCallback(httpClient, samlResponse, relayState, callbackURL, loginResponse)
	//After the callback, login should be succesful,
	//and we should get the Teapot status code from the backend service
	//On the original requested path
	sessionCookie, _ := callbackResponse.Request.Cookie("MySessionCookie")
	validSessionId = sessionCookie.Value
	assert.Equal(t, http.StatusTeapot, callbackResponse.StatusCode)
	assert.Equal(t, requestedPath, callbackResponse.Request.URL.Path+"?"+callbackResponse.Request.URL.RawQuery)
}

/**
This method tests the complete login flow
* An user request a resource on the server with an invalid sessionID
* The user is redirected by the SAML to the Keycloak login screen
* The user enters a valid username and password
* The user is redirected to the callback url
* The SAML module validates the SAML response from keycloak
* After validating the SAML response the user is logged in and receives data from the embedded service
*/
func invalid_SessionId_TriggersLogin(t *testing.T) {
	wrongSessionCookie := http.Cookie{
		Name:     "MySessionCookie",
		Value:    uuid.New().String(),
		Expires:  time.Now().AddDate(0, 0, 1),
		Path:     "/",
		HttpOnly: true,
	}
	requestedPath := "/test/redirect?noget=1"
	httpClient := httpServer.Client()
	cookieJar, _ := cookiejar.New(nil)
	httpClient.Jar = cookieJar
	initialRequest, _ := http.NewRequest("GET", httpServer.URL+requestedPath, nil)
	initialRequest.AddCookie(&wrongSessionCookie)
	res, err := httpClient.Do(initialRequest)
	if err != nil {
		panic(err)
	}
	assert.Equal(t, "keycloak:8080", res.Request.URL.Host)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	loginResponse := createLoginRequest(httpClient, res, "eva", "kuk")
	assert.Equal(t, http.StatusOK, loginResponse.StatusCode)
	loginResponseBody, _ := ioutil.ReadAll(loginResponse.Body)
	samlResponse := extractString(string(loginResponseBody), "name=\"SAMLResponse\" value=\"", "\"/>")
	relayState := extractString(string(loginResponseBody), "name=\"RelayState\" value=\"", "\"/>")
	callbackURL := extractString(string(loginResponseBody), "action=\"", "\">")
	callbackResponse := doCallback(httpClient, samlResponse, relayState, callbackURL, loginResponse)
	//After the callback, login should be succesful,
	//and we should get the Teapot status code from the backend service
	//On the original requested path
	assert.Equal(t, http.StatusTeapot, callbackResponse.StatusCode)
	assert.Equal(t, requestedPath, callbackResponse.Request.URL.Path+"?"+callbackResponse.Request.URL.RawQuery)

}

/**
This method tests that valid requests with a valid sessionId, does not trigger a login
* An user request a resource on the server with an valid sessionID
* The SAML module validates the SessionId
* After validating the SessionId the user is logged in and receives data from the embedded service
*/
func valid_SessionId_Cookie(t *testing.T) {
	validSessionCookie := http.Cookie{
		Name:     "MySessionCookie",
		Value:    validSessionId,
		Expires:  time.Now().AddDate(0, 0, 1),
		Path:     "/",
		HttpOnly: true,
	}
	requestedPath := "/test/redirect?noget=1"
	httpClient := httpServer.Client()
	cookieJar, _ := cookiejar.New(nil)
	httpClient.Jar = cookieJar
	initialRequest, _ := http.NewRequest("GET", httpServer.URL+requestedPath, nil)
	initialRequest.AddCookie(&validSessionCookie)
	res, err := httpClient.Do(initialRequest)
	if err != nil {
		panic(err)
	}
	//We should get the Teapot status code from the backend service
	//On the original requested path
	assert.Equal(t, http.StatusTeapot, res.StatusCode)
	assert.Equal(t, requestedPath, res.Request.URL.Path+"?"+res.Request.URL.RawQuery)
}

/**
This method tests that valid requests with a valid sessionId, does not trigger a login
* An user request a resource on the server with an valid sessionID
* The SAML module validates the SessionId
* After validating the SessionId the user is logged in and receives data from the embedded service
*/
func valid_SessionId_Header(t *testing.T) {
	requestedPath := "/test/redirect?noget=1"
	httpClient := httpServer.Client()
	cookieJar, _ := cookiejar.New(nil)
	httpClient.Jar = cookieJar
	initialRequest, _ := http.NewRequest("GET", httpServer.URL+requestedPath, nil)
	initialRequest.Header.Add("MySessionCookie", validSessionId)
	res, err := httpClient.Do(initialRequest)
	if err != nil {
		panic(err)
	}
	//We should get the Teapot status code from the backend service
	//On the original requested path
	assert.Equal(t, http.StatusTeapot, res.StatusCode)
	assert.Equal(t, requestedPath, res.Request.URL.Path+"?"+res.Request.URL.RawQuery)
}

/**
 *  UTILITES til testen
 */
func noRedirectPolicy(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

func extractString(input string, prefix string, postfix string) string {
	prefixRemoved := strings.SplitN(input, prefix, 2)[1]
	return strings.SplitN(prefixRemoved, postfix, 2)[0]
}

func doCallback(client *http.Client, samlResponse string, relayState string, callbackURL string, loginResponse *http.Response) *http.Response {
	callbackForm := url.Values{"SAMLResponse": {samlResponse}, "RelayState": {relayState}}
	callbackRequest, err := http.NewRequest("POST", callbackURL, strings.NewReader(callbackForm.Encode()))

	callbackRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	cookies := loginResponse.Cookies()
	for _, c := range cookies {
		callbackRequest.AddCookie(c)
	}
	response, err := client.Do(callbackRequest)
	fmt.Println("Received callback response: ", response)
	if err != nil {
		panic(err)
	}
	return response
}

func createLoginRequest(client *http.Client, authnRequestResponse *http.Response, username string, password string) *http.Response {

	authRequestResponseBody, _ := ioutil.ReadAll(authnRequestResponse.Body)
	formUrl := strings.ReplaceAll(extractString(string(authRequestResponseBody), "action=\"", "\" method=\"post\""), "&amp;", "&")
	loginForm := url.Values{"username": {username}, "password": {password}}
	loginFormRequest, err := http.NewRequest("POST", formUrl, strings.NewReader(loginForm.Encode()))
	loginFormRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	cookies := authnRequestResponse.Cookies()
	for _, c := range cookies {
		loginFormRequest.AddCookie(c)
	}
	response, err := client.Do(loginFormRequest)

	if err != nil {
		panic(err)
	}
	return response
}

func startHttpServer() *httptest.Server {
	config := createConfig()
	service = new(mockService)
	sessionCache, err := securityprotocol.NewMongoSessionCache("mongo", "sessions", "session")
	if err != nil {
		panic(err)
	}
	httpServer, _ := setupSamlServiceProvider(config, sessionCache)
	return httpServer
}

func createConfig() *SamlServiceProviderConfig {
	keyPair, err := tls.LoadX509KeyPair("testdata/sp.cer", "testdata/sp.pem")
	handleError(err)
	// download the metadata from keycloak
	c := new(SamlServiceProviderConfig)
	c.IdpMetaDataUrl = "http://keycloak:8080/auth/realms/test/protocol/saml/descriptor"
	c.ServiceProviderKeystore = &keyPair
	c.ExternalUrl = "http://localhost:8787"
	c.EntityId = "test"
	c.AudienceRestriction = "test"
	c.SignAuthnRequest = false
	c.Logger = zap.NewNop().Sugar()
	c.SamlMetadataPath = "/saml/metadata"
	c.SamlLogoutPath = "/saml/logout"
	c.SamlSLOPath = "/saml/SLO"
	c.SamlSSOPath = "/saml/SSO"
	c.SessionHeaderName = "MySessionCookie"
	c.CookieDomain = ""
	c.CookiePath = "/"
	return c
}

func handleError(err error) {
	if err != nil {
		panic(err)
	}
}

type mockService struct {
}

func (m mockService) Handle(http.ResponseWriter, *http.Request) (int, error) {

	return http.StatusTeapot, nil
}

func setupSamlServiceProvider(config *SamlServiceProviderConfig, sessionCache securityprotocol.SessionCache) (*httptest.Server, *SamlServiceProvider) {

	samlServiceProvider, err := NewSamlServiceProviderFromConfig(config, sessionCache)
	handleError(err)

	// Bridge the test server and the wsp
	handler := func(w http.ResponseWriter, r *http.Request) {
		responseCode, err := samlServiceProvider.HandleService(w, r, service)
		w.WriteHeader(responseCode)
		if err != nil {
			w.Write([]byte(err.Error()))
		}
	}

	tlsServer := createTlsServer(handler)

	return tlsServer, samlServiceProvider
}

func createTlsServer(handlerFunc func(http.ResponseWriter, *http.Request)) *httptest.Server {

	l, err := net.Listen("tcp", "127.0.0.1:8787")
	handleError(err)

	ts := httptest.NewUnstartedServer(http.HandlerFunc(handlerFunc))
	ts.Listener.Close()
	ts.Listener = l
	ts.Start()
	return ts
}
