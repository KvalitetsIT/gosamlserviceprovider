package gosamlserviceprovider

import (
	"fmt"
	//"golang.org/x/net/publicsuffix"
	"gotest.tools/assert"
	"strings"
	uuid "github.com/google/uuid"
	"time"
	"testing"
	//	"encoding/json"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
	//"github.com/sclevine/agouti"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
)

var (
  httpServer *httptest.Server
)

func TestSaml(t *testing.T) {
    httpServer = startHttpServer()
    t.Run("Test SAML Metadata", samlMetadata)
    t.Run("Test Loginflow without sessionId", loginFlow_Basic)
    t.Run("Test LoginFlow with invalid sessionId",invalid_SessionId_TriggersLogin)
    httpServer.Close()
}


func samlMetadata(t *testing.T) {
	httpClient := httpServer.Client()
    metadataRequest, _ := http.NewRequest("GET", "http://localhost:8080/saml/metadata",nil)
    response, _ := httpClient.Do(metadataRequest)
    assert.Equal(t, http.StatusOK, response.StatusCode)
    responseBody,_ := ioutil.ReadAll(response.Body)
    assert.Check(t,strings.HasPrefix(string(responseBody),"<EntityDescriptor"))
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
	res, err := httpClient.Get(httpServer.URL+requestedPath)
	if err != nil {
		panic(err)
	}
	assert.Equal(t, http.StatusOK, res.StatusCode)
	loginResponse := createLoginRequest(httpClient, res, "eva", "kuk")
	assert.Equal(t, http.StatusOK, loginResponse.StatusCode)
	loginResponseBody, _ := ioutil.ReadAll(loginResponse.Body)
	samlResponse := extractString(string(loginResponseBody), "name=\"SAMLResponse\" value=\"","\"/>")
	relayState := extractString(string(loginResponseBody), "name=\"RelayState\" value=\"","\"/>")
	callbackURL := extractString(string(loginResponseBody),"action=\"","\">")
    callbackResponse := doCallback(httpClient,samlResponse,relayState,callbackURL,loginResponse)
    //After the callback, login should be succesful,
    //and we should get the Teapot status code from the backend service
    //On the original requested path
    assert.Equal(t, http.StatusTeapot, callbackResponse.StatusCode)
    assert.Equal(t,requestedPath, callbackResponse.Request.URL.Path+"?"+callbackResponse.Request.URL.RawQuery)
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
         Name:"MySessionCookie",
         Value: uuid.New().String(),
         Expires:  time.Now().AddDate(0, 0, 1),
         Path: "/",
         HttpOnly: true,
     }
    requestedPath := "/test/redirect?noget=1"
	httpClient := httpServer.Client()
	cookieJar, _ := cookiejar.New(nil)
	httpClient.Jar = cookieJar
	initialRequest,_ := http.NewRequest("GET", httpServer.URL+requestedPath,nil)
	initialRequest.AddCookie(&wrongSessionCookie)
	res, err := httpClient.Do(initialRequest)
	if err != nil {
		panic(err)
	}
	assert.Equal(t,"keycloak:8080",res.Request.URL.Host)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	loginResponse := createLoginRequest(httpClient, res, "eva", "kuk")
	assert.Equal(t, http.StatusOK, loginResponse.StatusCode)
	loginResponseBody, _ := ioutil.ReadAll(loginResponse.Body)
	samlResponse := extractString(string(loginResponseBody), "name=\"SAMLResponse\" value=\"","\"/>")
	relayState := extractString(string(loginResponseBody), "name=\"RelayState\" value=\"","\"/>")
	callbackURL := extractString(string(loginResponseBody),"action=\"","\">")
    callbackResponse := doCallback(httpClient,samlResponse,relayState,callbackURL,loginResponse)
    //After the callback, login should be succesful,
    //and we should get the Teapot status code from the backend service
    //On the original requested path
    assert.Equal(t, http.StatusTeapot, callbackResponse.StatusCode)
    assert.Equal(t,requestedPath, callbackResponse.Request.URL.Path+"?"+callbackResponse.Request.URL.RawQuery)

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
   	callbackForm := url.Values{"SAMLResponse": {samlResponse},"RelayState": {relayState}}
   	callbackRequest, err := http.NewRequest("POST", callbackURL, strings.NewReader(callbackForm.Encode()))

   	callbackRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")
   	cookies := loginResponse.Cookies()
   	for _, c := range cookies {
   		callbackRequest.AddCookie(c)
   	}
   	response, err := client.Do(callbackRequest)
   	fmt.Println("Received callback response: ",response)
   	if err != nil {
   		panic(err)
   	}
   	return response
}

func createLoginRequest(client *http.Client, authnRequestResponse *http.Response, username string, password string) *http.Response {

	authRequestResponseBody, _ := ioutil.ReadAll(authnRequestResponse.Body)
	formUrl := strings.ReplaceAll(extractString(string(authRequestResponseBody),"action=\"","\" method=\"post\""), "&amp;", "&")
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

func startHttpServer()  *httptest.Server {
    config := createConfig()
    sessionCache, err :=  securityprotocol.NewMongoSessionCache("mongo", "sessions", "session")
    if err != nil {
      panic(err)
    }
    httpServer, _ := createSamlServiceProvider(config, sessionCache)
    return httpServer
}

func createConfig() *SamlServiceProviderConfig {
	metadataFileName := "testdata/keycloak-metadata.xml"
	idpUrl := "http://keycloak:8080/auth/realms/test/protocol/saml/descriptor"

	keyPair, err := tls.LoadX509KeyPair("testdata/sp.cer", "testdata/sp.pem")
	handleError(err)
	// download the metadata from keycloak
	DownloadMetadata(metadataFileName, idpUrl)
	c := new(SamlServiceProviderConfig)
	c.IdpMetaDataFile = metadataFileName
	c.ServiceProviderKeystore = &keyPair
	c.AssertionConsumerServiceUrl = "http://localhost:8080/saml/SSO"
	c.EntityId = "test"
	c.AudienceRestriction = "test"
	c.SignAuthnRequest = false
	c.Service = new(mockService)
	c.SessionHeaderName = "MySessionCookie"
	return c
}

func handleError(err error) {
	if err != nil {
		panic(err)
	}
}

// Fetch metadata from idp. Removing EntitiesDescriptor and keeping EntityDescriptor. NS moved from EntitiesDescriptor to EntityDescriptor
func DownloadMetadata(filePath string, fileUrl string) {

	//download metadata from idp
	resp, err := http.Get(fileUrl)
	handleError(err)
	defer resp.Body.Close()
	var idpMetadata string
	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		handleError(err)
		idpMetadata = string(bodyBytes)
	}

	// read namespace from EntitiesDescriptor
	// array of namespaces
	xmlnsArray := regexp.MustCompile("xmlns(.)*").FindAllString(idpMetadata, -1)
	xmlnsString := ""
	for _, v := range xmlnsArray {
		xmlnsString = xmlnsString + v + " "
	}

	// insert namespaces to EntityDescriptor
	// select the entire EntityDescriptor section
	xmlEntityDescriptor := regexp.MustCompile("<EntityDescriptor(.|\n)*EntityDescriptor>").FindString(idpMetadata)
	// inserts the namespace
	replacePattern := regexp.MustCompile("test\">")
	xmlEntityDescriptor = replacePattern.ReplaceAllLiteralString(xmlEntityDescriptor, "test\" "+xmlnsString)

	// create file
	createFile(filePath, xmlEntityDescriptor)
}

func createFile(filePath string, content string) {
	f, err := os.Create(filePath)
	handleError(err)
	_, err = f.WriteString(content)
	handleError(err)
	err = f.Close()
	handleError(err)
}

type mockService struct {
}

func (m mockService) Handle(http.ResponseWriter, *http.Request) (int, error) {

	return http.StatusTeapot, nil
}

func readCertificate(filename string) *x509.Certificate {
	cert, _ := ioutil.ReadFile(filename)
	certBlock, _ := pem.Decode([]byte(cert))
	res, _ := x509.ParseCertificate(certBlock.Bytes)
	return res
}

func createMongoSessionCache() securityprotocol.SessionCache {

	res, _ := securityprotocol.NewMongoSessionCache("mongo", "sp", "sessions")
	return res
}

func createSamlServiceProvider(config *SamlServiceProviderConfig, sessionCache securityprotocol.SessionCache) (*httptest.Server, *SamlServiceProvider) {

	sp, err := NewSamlServiceProviderFromConfig(config, sessionCache)
	handleError(err)

	// Bridge the test server and the wsp
	handler := func(w http.ResponseWriter, r *http.Request) {
		responseCode, err := sp.Handle(w, r)
		w.WriteHeader(responseCode)
		if err != nil {
			w.Write([]byte(err.Error()))
		}
	}

	tlsServer := createTlsServer(handler)

	return tlsServer, sp
}

func createTlsServer(handlerFunc func(http.ResponseWriter, *http.Request)) *httptest.Server {

	l, err := net.Listen("tcp", "127.0.0.1:8080")
	handleError(err)

	ts := httptest.NewUnstartedServer(http.HandlerFunc(handlerFunc))
	ts.Listener.Close()
	ts.Listener = l
	ts.Start()
	return ts
}
