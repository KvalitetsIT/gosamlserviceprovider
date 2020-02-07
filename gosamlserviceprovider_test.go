package gosamlserviceprovider

import (
	"encoding/xml"
	"fmt"
	"golang.org/x/net/publicsuffix"
	"gotest.tools/assert"
	"strings"
	"testing"
	//	"encoding/json"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
	"github.com/sclevine/agouti"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
)

func TestCallServiceProviderWithoutSessionTriggersALogin(t *testing.T) {

	// Given
	options := cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	}
	jar, err := cookiejar.New(&options)
	if err != nil {
		panic(err)
	}

	config := createConfig()
	httpServer, _ := createSamlServiceProvider(config, nil)

	driver := agouti.ChromeDriver(
		agouti.ChromeOptions("args", []string{"--headless", "--disable-gpu", "--no-sandbox"}),
	)

	if err := driver.Start(); err != nil {
		panic(err)
	}

	page, err := driver.NewPage()
	if err != nil {
		panic(err)
	}

	// rammer en mockserver med SP
	if err := page.Navigate(httpServer.URL); err != nil {
		//	panic(err)
	}

	httpClient := httpServer.Client()
	httpClient.Jar = jar

	// When
	res, err := httpClient.Get(httpServer.URL)
	if err != nil {
		panic(err)
	}

	// Then
	fmt.Println(httpServer.URL)
	assert.Equal(t, http.StatusOK, res.StatusCode)

	// login with testuser. Test users is created the keycloak-add-user.json file
	loginResponse := createLoginRequest(httpClient, res, "eva", "kuk")
	loginResponseBody, _ := ioutil.ReadAll(loginResponse.Body)

	samlResponse := strings.SplitN(string(loginResponseBody), "name=\"SAMLResponse\" value=\"", 2)[1]
	samlResponse = strings.SplitN(samlResponse, "\"/>", 2)[0]
	fmt.Println(samlResponse)

	assert.Equal(t, http.StatusOK, res.StatusCode)
}

/**
 *  UTILITES til testen
 */
func createLoginRequest(client *http.Client, authnRequestResponse *http.Response, username string, password string) *http.Response {

	authRequestResponseBody, _ := ioutil.ReadAll(authnRequestResponse.Body)
	authRequestResponseBodyStr := string(authRequestResponseBody)
	splitOnMethod := strings.SplitN(authRequestResponseBodyStr, "\" method=\"post\"", 2)
	splitOnAction := strings.SplitN(splitOnMethod[0], "action=\"", 2)
	formUrl := strings.ReplaceAll(splitOnAction[1], "&amp;", "&")

	fmt.Println(fmt.Sprintf("formurl: %s", formUrl))

	loginForm := url.Values{"username": {username}, "password": {password}}
	//loginFormRequest, err := http.NewRequest("POST", "http://echo", strings.NewReader(loginForm.Encode()))
	loginFormRequest, err := http.NewRequest("POST", formUrl, strings.NewReader(loginForm.Encode()))

	loginFormRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	fmt.Println(fmt.Sprintf("request: %v", loginForm))
	cookies := authnRequestResponse.Cookies()
	for _, c := range cookies {
		fmt.Println(fmt.Sprintf("adding cookie: %s", c.String()))
		loginFormRequest.AddCookie(c)
	}

	response, err := client.Do(loginFormRequest)

	if err != nil {
		panic(err)
	}
	return response
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
	c.AssertionConsumerServiceUrl = "http://localhost:8080/saml"
	c.EntityId = "test"
	c.SignAuthnRequest = false
	c.Service = new(mockService)
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
	l, err := f.WriteString(content)
	handleError(err)
	fmt.Println(l, "bytes written successfully")
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

	spMetadata, err := sp.SamlServiceProvider.Metadata()
	handleError(err)

	spMetadataXml, err := xml.MarshalIndent(spMetadata, "", "")
	fmt.Println(string(spMetadataXml))

	// Bridge the test server and the wsp
	handler := func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("bridge1")
		responseCode, err := sp.Handle(w, r)
		fmt.Println(fmt.Sprintf("bridge2 %d", responseCode))
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
