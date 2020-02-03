package gosamlserviceprovider

import (
	"golang.org/x/net/publicsuffix"
	"strings"
	"testing"
 	"gotest.tools/assert"
	"fmt"
	"encoding/xml"
//	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/cookiejar"
	"net/url"
	"io/ioutil"
	"crypto/x509"
	"crypto/tls"
	"encoding/pem"
	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
	 "github.com/sclevine/agouti"
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

  if err := page.Navigate(httpServer.URL); err != nil {
//	panic(err)
  }

//  sectionTitle, err := page.FindByID(`getting-agouti`).Text()
//	fmt.Println(fmt.Sprintf("sectiontitle %s", sectionTitle))

	httpClient := httpServer.Client()
	httpClient.Jar = jar

	// When
	res, err := httpClient.Get(httpServer.URL)
	if (err != nil) {
		panic(err)
	}

	// Then
	assert.Equal(t, http.StatusOK, res.StatusCode)

	loginResponse := createLoginRequest(httpClient, res, "eva", "kuk")
	authRequestResponseBody, _ := ioutil.ReadAll(loginResponse.Body)

	assert.Equal(t, "no", string(authRequestResponseBody))
}


/**
  *  UTILITES til testen
  */
func createLoginRequest(client *http.Client, authnRequestResponse *http.Response, username string, password string) *http.Response {


  	authRequestResponseBody, _ := ioutil.ReadAll(authnRequestResponse.Body)
        authRequestResponseBodyStr := string(authRequestResponseBody)
        splitOnMethod := strings.SplitN(authRequestResponseBodyStr, "\" method=\"post\"", 2)
        splitOnAction := strings.SplitN(splitOnMethod[0], "action=\"", 2)
	formUrl := splitOnAction[1]
	
        fmt.Println(fmt.Sprintf("formurl: %s", formUrl))

	loginForm := url.Values{ "username": { username }, "password": { password }}
	loginFormRequest, err := http.NewRequest("POST", formUrl, strings.NewReader(loginForm.Encode()))

        cookies := authnRequestResponse.Cookies()
        for _, c := range cookies {
                fmt.Println(fmt.Sprintf("adding cookie: %s", c.String()))
		loginFormRequest.AddCookie(c)
        }


	//fmt.Println(authRequestResponseBodyStr)

	response, err := client.Do(loginFormRequest)

/*client.PostForm(formUrl, url.Values{
		"username": { username },
		"password": { password }})*/
	if (err != nil) {
		panic(err)
	}
	return response
}

func createConfig() *SamlServiceProviderConfig {


	keyPair, err := tls.LoadX509KeyPair("testdata/sp.cer", "testdata/sp.pem")
        if (err != nil) {
		panic(err)
        }

	c := new(SamlServiceProviderConfig)
	c.IdpMetaDataFile = "testdata/keycloak-metadata.xml"
	c.ServiceProviderKeystore = &keyPair
	c.AssertionConsumerServiceUrl = "http://localhost:8080/saml"
	c.Service = new(mockService)
        return c
}

type mockService struct {
}


func (m mockService) Handle(http.ResponseWriter, *http.Request) (int, error) {

	return http.StatusTeapot, nil
}

func readCertificate(filename string) *x509.Certificate  {
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
	if (err != nil) {
		panic(err)
	}

	spMetadata, err := sp.SamlServiceProvider.Metadata()
	if (err != nil) {
                panic(err)
        }

	spMetadataXml, err := xml.MarshalIndent(spMetadata, "", "")
	fmt.Println(string(spMetadataXml))


	// Bridge the test server and the wsp
	handler := func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("bridge1")
		responseCode, err := sp.Handle(w, r)
		fmt.Println(fmt.Sprintf("bridge2 %d", responseCode))
		w.WriteHeader(responseCode)
		if (err != nil) {
			w.Write([]byte(err.Error()))
		}
	}



        tlsServer := createTlsServer(handler)

	return tlsServer, sp
}


func createTlsServer(handlerFunc func(http.ResponseWriter, *http.Request)) *httptest.Server {

	l, err := net.Listen("tcp", "127.0.0.1:8080")
	if (err != nil) {
		panic(err)
	}

	ts := httptest.NewUnstartedServer(http.HandlerFunc(handlerFunc))
	ts.Listener.Close()
	ts.Listener = l
	ts.Start()
	return ts
}

