package gosamlserviceprovider

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
	"io/ioutil"
	"net/http"
	"regexp"

	dsig "github.com/russellhaering/goxmldsig"

	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"

	"go.uber.org/zap"
)

type SamlServiceProviderConfig struct {
	ServiceProviderKeystore     *tls.Certificate
	EntityId                    string
	AssertionConsumerServiceUrl string
	SLOConsumerServiceUrl       string
	CookieDomain                string
	CookiePath                  string
	AudienceRestriction         string
	SignAuthnRequest            bool
	IdpMetaDataUrl              string
	SessionHeaderName           string
	SamlLogoutUrl               string
	SamlMetadataUrl             string
	Logger                      *zap.SugaredLogger
}

type SamlServiceProvider struct {
	sessionCache        securityprotocol.SessionCache
	sessionHeaderName   string
	SamlServiceProvider *saml2.SAMLServiceProvider
	SamlHandler         *SamlHandler
	Logger              *zap.SugaredLogger
}

func NewSamlServiceProviderFromConfig(config *SamlServiceProviderConfig, sessionCache securityprotocol.SessionCache) (*SamlServiceProvider, error) {

	samlServiceProvider, err := createSamlServiceProvider(config)
	if err != nil {
		return nil, err
	}

	return newSamlServiceProvider(samlServiceProvider, sessionCache, config), nil
}

func newSamlServiceProvider(samlServiceProvider *saml2.SAMLServiceProvider, sessionCache securityprotocol.SessionCache, config *SamlServiceProviderConfig) *SamlServiceProvider {
	s := new(SamlServiceProvider)
	s.SamlServiceProvider = samlServiceProvider
	s.sessionCache = sessionCache
	s.sessionHeaderName = config.SessionHeaderName
	s.SamlHandler = NewSamlHandler(config, s)
	s.Logger = config.Logger
	return s
}

func createSamlServiceProvider(config *SamlServiceProviderConfig) (*saml2.SAMLServiceProvider, error) {
	// Read and parse the IdP metadata
	rawMetadata, err := DownloadIdpMetadata(config)
	if err != nil {
		return nil, err
	}
	idpMetadata := &types.EntityDescriptor{}
	err = xml.Unmarshal(rawMetadata, idpMetadata)
	if err != nil {
		config.Logger.Errorf("Cannot unmarshal IDP metadata: %v", err)
		return nil, err
	}
	certStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{},
	}
	for _, kd := range idpMetadata.IDPSSODescriptor.KeyDescriptors {
		for idx, xcert := range kd.KeyInfo.X509Data.X509Certificates {
			if xcert.Data == "" {
				return nil, fmt.Errorf("metadata certificate(%d) must not be empty", idx)
			}
			certData, err := base64.StdEncoding.DecodeString(xcert.Data)
			if err != nil {
				return nil, err
			}

			idpCert, err := x509.ParseCertificate(certData)
			if err != nil {
				return nil, err
			}

			certStore.Roots = append(certStore.Roots, idpCert)
		}
	}

	spKeyStore := dsig.TLSCertKeyStore(*config.ServiceProviderKeystore)

	sp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      idpMetadata.IDPSSODescriptor.SingleSignOnServices[0].Location,
		IdentityProviderSLOURL:      idpMetadata.IDPSSODescriptor.SingleLogoutServices[0].Location,
		IdentityProviderIssuer:      idpMetadata.EntityID,
		ServiceProviderIssuer:       config.EntityId,
		AssertionConsumerServiceURL: config.AssertionConsumerServiceUrl,
		ServiceProviderSLOURL:       config.SLOConsumerServiceUrl,
		SignAuthnRequests:           config.SignAuthnRequest,
		AudienceURI:                 config.AudienceRestriction,
		IDPCertificateStore:         &certStore,
		SPKeyStore:                  spKeyStore,
	}

	return sp, nil
}

func DownloadIdpMetadata(config *SamlServiceProviderConfig) ([]byte, error) {
	//download metadata from idp
	config.Logger.Infof("Downloading IDP metadata from: %s", config.IdpMetaDataUrl)
	resp, err := http.Get(config.IdpMetaDataUrl)
	if err != nil {
		config.Logger.Errorf("Cannot download metadata: %v", err)
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		config.Logger.Errorf("Cannot download metadata: %v", err)
		return nil, errors.New("Cannot download metadata")
	}
	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		config.Logger.Errorf("Cannot download metadata: %v", err)
		return nil, err
	}
	return fixMetadata(bodyBytes)
}

func fixMetadata(bodyBytes []byte) ([]byte, error) {
	idpMetadata := string(bodyBytes)
	// read namespace from EntitiesDescriptor
	// array of namespaces
	xmlnsArray := regexp.MustCompile("xmlns(:[^=]*)?=\"([^\"])*\"").FindAllString(idpMetadata, -1)
	xmlnsString := ""
	for _, v := range xmlnsArray {
		xmlnsString = xmlnsString + v + " "
	}
	// insert namespaces to EntityDescriptor
	// select the entire EntityDescriptor section
	xmlEntityDescriptor := regexp.MustCompile("<EntityDescriptor(.|\n)*EntityDescriptor>").FindString(idpMetadata)
	// inserts the namespace
	replacePattern := regexp.MustCompile("<EntityDescriptor ")
	xmlEntityDescriptor = replacePattern.ReplaceAllLiteralString(xmlEntityDescriptor, "<EntityDescriptor "+xmlnsString)
	return []byte(xmlEntityDescriptor), nil
}

func (a SamlServiceProvider) HandleService(w http.ResponseWriter, r *http.Request, service securityprotocol.HttpHandler) (int, error) {
	if a.SamlHandler.isSamlProtocol(r) {
		a.Logger.Debugf("Handling request as SAML")
		return a.SamlHandler.Handle(w, r)
	}

	// Get the session id
	sessionId, err := a.SamlHandler.GetSessionId(r)
	a.Logger.Debugf("SessionId: %s", sessionId)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	// The request identifies a session, check that the session is valid and get it
	if sessionId != "" {
		sessionData, err := a.sessionCache.FindSessionDataForSessionId(sessionId)
		if err != nil {
			a.Logger.Debugf("Cannot look up session in cache: %v", err)
			return http.StatusInternalServerError, err
		}

		if sessionData != nil {

			// Check if the user is requesting sessiondata
			handlerFunc := securityprotocol.IsRequestForSessionData(sessionData, a.sessionCache, w, r)
			if handlerFunc != nil {
				a.Logger.Debugf("Handling session data request")
				return handlerFunc()
			}

			// The session id ok ... pass-through to next handler
			return service.Handle(w, r)
		}
	}

	authenticateStatusCode, err := a.GenerateAuthenticationRequest(w, r)
	return authenticateStatusCode, err
}

func (a SamlServiceProvider) GenerateAuthenticationRequest(w http.ResponseWriter, r *http.Request) (int, error) {
	a.Logger.Debugf("No Session found, redirecting to IDP")
	relayState := r.RequestURI
	err := a.SamlServiceProvider.AuthRedirect(w, r, relayState)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusFound, nil
}
