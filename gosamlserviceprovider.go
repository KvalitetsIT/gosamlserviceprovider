package gosamlserviceprovider

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"
	"io/ioutil"
	"net/http"
	uuid "github.com/google/uuid"
	//	"crypto/sha1"
	//	"encoding/hex"
	//	"strings"
	//       uuid "github.com/google/uuid"
	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"

	dsig "github.com/russellhaering/goxmldsig"

	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
)

const HEADER_WWW_AUTHENTICATE = "WWW-Authenticate"
const HEADER_AUTHORIZATION = "Authorization"

type SamlServiceProviderConfig struct {

	//	TrustCertFiles          []string

	ServiceProviderKeystore *tls.Certificate

	EntityId string

	AssertionConsumerServiceUrl string
	AudienceRestriction         string

	SignAuthnRequest bool

	IdpMetaDataFile string

	SessionHeaderName string

	Service securityprotocol.HttpHandler
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
}

func NewSamlServiceProviderFromConfig(config *SamlServiceProviderConfig, sessionCache securityprotocol.SessionCache) (*SamlServiceProvider, error) {

	samlServiceProvider, err := CreateSamlServiceProvider(config.IdpMetaDataFile, config.AudienceRestriction, config.SignAuthnRequest, config.AssertionConsumerServiceUrl, config.EntityId, config.ServiceProviderKeystore)
	if err != nil {
		return nil, err
	}

	return NewSamlServiceProvider(samlServiceProvider, sessionCache, config.Service, config.SessionHeaderName), nil
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

func NewSamlServiceProvider(samlServiceProvider *saml2.SAMLServiceProvider, sessionCache securityprotocol.SessionCache, service securityprotocol.HttpHandler, sessionHeaderName string) *SamlServiceProvider {
	s := new(SamlServiceProvider)
	s.SamlServiceProvider = samlServiceProvider
	s.sessionCache = sessionCache
	s.Service = service
	s.sessionHeaderName = sessionHeaderName
	return s
}

func (a SamlServiceProvider) Handle(w http.ResponseWriter, r *http.Request) (int, error) {
	return a.HandleService(w, r, a.Service)
}

func (a SamlServiceProvider) HandleService(w http.ResponseWriter, r *http.Request, service securityprotocol.HttpHandler) (int, error) {

	// Indsæt tjek om det er en del af samlflow (via url /saml/SSO og /saml/metadata og /saml/logout)
    if strings.HasPrefix(r.URL.Path,"/saml/SSO") {
        //TODO test for HTTP METHOD = POST
        return a.HandleSamlLoginResponse(w,r)
    }

    if strings.HasPrefix(r.URL.Path,"/saml/metadata") {
       //TODO test for HTTP METHOD = GET
       spMetadata, _ := a.SamlServiceProvider.Metadata()
       spMetadataXml, _ := xml.MarshalIndent(spMetadata, "", "")
       w.Write(spMetadataXml)
       return http.StatusOK, nil
    }

    if strings.HasPrefix(r.URL.Path,"/saml/logout") {

    }


	// Get the session id
	sessionId, err := a.getSessionId(r, a.sessionHeaderName)
    fmt.Println("SessionId: "+sessionId)
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

func (a SamlServiceProvider) HandleSamlLoginResponse(w http.ResponseWriter, r *http.Request) (int, error) {

        err := r.ParseForm()
		if err != nil {
		    fmt.Println("Error parsing form data: "+err.Error())
			return http.StatusBadRequest, nil
		}

		assertionInfo, err := a.SamlServiceProvider.RetrieveAssertionInfo(r.FormValue("SAMLResponse"))
		if err != nil {
		    fmt.Fprintf(w, "Invalid assertions: %s", err.Error())
			return http.StatusForbidden, nil
		}
		if assertionInfo.WarningInfo.InvalidTime {
		    fmt.Fprintf(w, "Invalid assertions: %s","InvalidTime")
        	return http.StatusForbidden,nil
        }
   		if assertionInfo.WarningInfo.NotInAudience {
   		    fmt.Fprintf(w, "Invalid assertions: %s","UserNotInAudience")
            return http.StatusForbidden,nil
        }
        // TODO create session and do another redirect
        assertionXml,_ := xml.Marshal(assertionInfo.Assertions[0])
        sessionDataCreator,err := securityprotocol.NewSamlSessionDataCreatorWithId(uuid.New().String(),string(assertionXml))
        if err != nil {
           fmt.Println("Error creating sessionData: "+err.Error())
           return http.StatusBadRequest, nil
        }
        sessionData,err := sessionDataCreator.CreateSessionData()
        if err != nil {
           fmt.Println("Error creating sessionData: "+err.Error())
           return http.StatusBadRequest, nil
        }
        a.sessionCache.SaveSessionData(sessionData)
        cookie := http.Cookie{
            Name: a.sessionHeaderName,
            Value: sessionData.Sessionid,
            Expires: *assertionInfo.SessionNotOnOrAfter,
            Path: "/",
            HttpOnly: true,
        }
        http.SetCookie(w , &cookie)
        w.Header().Add(a.sessionHeaderName,sessionData.Sessionid)
        relayState := r.FormValue("RelayState")
        w.Header().Add("Location",relayState)
        fmt.Println("Returning callback response: ",w)
		return http.StatusFound,nil
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
	cookie,_ := r.Cookie(sessionHeaderName)
	if sessionId != "" {
		return sessionId, nil
	} else {
	    fmt.Println("SessionId not found in header: ", r.Header)
	}
	if cookie != nil {
	    return cookie.Value, nil
	} else {
      	fmt.Println("SessionId not found in cookies: ",r)
    }
	return "", nil
}
