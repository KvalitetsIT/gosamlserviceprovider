package gosamlserviceprovider

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
	"io/ioutil"
	"net/http"

	dsig "github.com/russellhaering/goxmldsig"

	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"

	"go.uber.org/zap"
)

type SamlServiceProviderConfig struct {
	ServiceProviderKeystore *tls.Certificate

	EntityId string

	AssertionConsumerServiceUrl string
	AudienceRestriction         string

	SignAuthnRequest bool

	IdpMetaDataFile string

	SessionHeaderName string

	Service securityprotocol.HttpHandler

	attr string
}

type SamlServiceProvider struct {

	//	matchHandler		*securityprotocol.MatchHandler

	sessionCache securityprotocol.SessionCache

	sessionHeaderName string
	//	tokenAuthenticator	*TokenAuthenticator

	Service securityprotocol.HttpHandler

	//	HoK			bool

	SamlServiceProvider *saml2.SAMLServiceProvider
	//	ClientCertHandler	func(req *http.Request) *x509.Certificate

	SamlHandler *SamlHandler

	Logger *zap.SugaredLogger
}

func NewSamlServiceProviderFromConfig(config *SamlServiceProviderConfig, sessionCache securityprotocol.SessionCache, logger *zap.SugaredLogger) (*SamlServiceProvider, error) {

	samlServiceProvider, err := CreateSamlServiceProvider(config.IdpMetaDataFile, config.AudienceRestriction, config.SignAuthnRequest, config.AssertionConsumerServiceUrl, config.EntityId, config.ServiceProviderKeystore)
	if err != nil {
		return nil, err
	}

	return NewSamlServiceProvider(samlServiceProvider, sessionCache, config.Service, config.SessionHeaderName, logger), nil
}

func CreateSamlServiceProvider(idpMetaDataFile string, audienceUri string, signAuthnRequests bool, assertionConsumerServiceUrl string, serviceProviderIssuer string, spKeyPair *tls.Certificate) (*saml2.SAMLServiceProvider, error) {

	// Read and parse the IdP metadata
	rawMetadata, err := ioutil.ReadFile(idpMetaDataFile)
	if err != nil {
		return nil, err
	}
	idpMetadata := &types.EntityDescriptor{}
	err = xml.Unmarshal(rawMetadata, idpMetadata)
	if err != nil {
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

	spKeyStore := dsig.TLSCertKeyStore(*spKeyPair)

	sp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      idpMetadata.IDPSSODescriptor.SingleSignOnServices[0].Location,
		IdentityProviderIssuer:      idpMetadata.EntityID,
		ServiceProviderIssuer:       serviceProviderIssuer,
		AssertionConsumerServiceURL: assertionConsumerServiceUrl,
		SignAuthnRequests:           signAuthnRequests,
		AudienceURI:                 audienceUri,
		IDPCertificateStore:         &certStore,
		SPKeyStore:                  spKeyStore,
	}

	return sp, nil
}

func NewSamlServiceProvider(samlServiceProvider *saml2.SAMLServiceProvider, sessionCache securityprotocol.SessionCache, service securityprotocol.HttpHandler, sessionHeaderName string, logger *zap.SugaredLogger) *SamlServiceProvider {
	s := new(SamlServiceProvider)
	s.SamlServiceProvider = samlServiceProvider
	s.sessionCache = sessionCache
	s.Service = service
	s.sessionHeaderName = sessionHeaderName
	s.SamlHandler = NewSamlHandler("/saml/SSO", "/saml/logout", "/saml/metadata", s)
	s.Logger = logger
	return s
}

func (a SamlServiceProvider) Handle(w http.ResponseWriter, r *http.Request) (int, error) {
	return a.HandleService(w, r, a.Service)
}

func (a SamlServiceProvider) HandleService(w http.ResponseWriter, r *http.Request, service securityprotocol.HttpHandler) (int, error) {
	if a.SamlHandler.isSamlProtocol(r) {
		return a.SamlHandler.Handle(w, r)
	}

	// Get the session id
	sessionId, err := a.getSessionId(r, a.sessionHeaderName)
	fmt.Println("SessionId: " + sessionId)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	// The request identifies a session, check that the session is valid and get it
	if sessionId != "" {
		sessionData, err := a.sessionCache.FindSessionDataForSessionId(sessionId)
		if err != nil {
			return http.StatusInternalServerError, err
		}

		if sessionData != nil {

			// Check if the user is requesting sessiondata
			handlerFunc := securityprotocol.IsRequestForSessionData(sessionData, a.sessionCache, w, r)
			if handlerFunc != nil {
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

	relayState := r.URL.String()
	err := a.SamlServiceProvider.AuthRedirect(w, r, relayState)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusFound, nil
}

func (a SamlServiceProvider) getSessionId(r *http.Request, sessionHeaderName string) (string, error) {
	sessionId := r.Header.Get(sessionHeaderName)
	cookie, _ := r.Cookie(sessionHeaderName)
	if sessionId != "" {
		return sessionId, nil
	} else {
		fmt.Println("SessionId not found in header: ", r.Header)
	}
	if cookie != nil {
		return cookie.Value, nil
	} else {
		fmt.Println("SessionId not found in cookies: ", r)
	}
	return "", nil
}
