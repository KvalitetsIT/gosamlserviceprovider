package samlprovider

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"

	"go.uber.org/zap"
)

type SamlServiceProviderConfig struct {
	ServiceProviderKeystore *tls.Certificate
	EntityId                string
	CookieDomain            string
	CookiePath              string
	AudienceRestriction     string
	SignAuthnRequest        bool
	IdpMetaDataUrl          string
	SessionHeaderName       string
	SessionExpiryHours      string
	SessiondataHeaderName   string
	SkipSignatureValidation bool

	ExternalUrl       string
	SamlMetadataPath  string
	SamlLogoutPath    string
	SamlSLOPath       string
	SamlSSOPath       string
	LogoutLandingPage string

	RoleAttributeName string
	AllowedRoles      []string

	Logger *zap.SugaredLogger
}

type SamlServiceProvider struct {
	sessionCache          securityprotocol.SessionCache
	sessionHeaderName     string
	SessiondataHeaderName string
	externalUrl           string
	SamlServiceProvider   *saml2.SAMLServiceProvider
	SamlHandler           *SamlHandler
	Logger                *zap.SugaredLogger
	Config                *SamlServiceProviderConfig
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
	s.externalUrl = config.ExternalUrl
	s.SessiondataHeaderName = config.SessiondataHeaderName
	s.SamlHandler = NewSamlHandler(config, s)
	s.Logger = config.Logger
	// todo: ask Eva if this is okay
	s.Config = config
	return s
}

func createSamlServiceProvider(config *SamlServiceProviderConfig) (*saml2.SAMLServiceProvider, error) {
	// Read and parse the IdP metadata
	rawMetadata, err := DownloadIdpMetadata(config)
	if err != nil {
		config.Logger.Errorf("Error downloading IdP metadata: %s", err.Error())
		return nil, err
	}
	idpMetadata := &types.EntityDescriptor{}
	err = xml.Unmarshal(rawMetadata, idpMetadata)
	if err != nil {
		config.Logger.Errorf("Cannot unmarshal IDP metadata: %s", err.Error())
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
				config.Logger.Errorf("Error decoding certificate: %s", err.Error())
				return nil, err
			}

			idpCert, err := x509.ParseCertificate(certData)
			if err != nil {
				config.Logger.Errorf("Error parsing certificate: %s", err.Error())
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
		AssertionConsumerServiceURL: config.AssertionConsumerServiceUrl(),
		ServiceProviderSLOURL:       config.SloConsumerServiceUrl(),
		SignAuthnRequests:           config.SignAuthnRequest,
		AudienceURI:                 config.AudienceRestriction,
		IDPCertificateStore:         &certStore,
		SPKeyStore:                  spKeyStore,
		SkipSignatureValidation:     config.SkipSignatureValidation,
	}

	//signingContext := sp.SigningContext()
	//signingContext.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

	return sp, nil
}

func (config *SamlServiceProviderConfig) AssertionConsumerServiceUrl() string {
	return buildUrl(config.ExternalUrl, config.SamlSSOPath)
}

func (config *SamlServiceProviderConfig) SloConsumerServiceUrl() string {
	return buildUrl(config.ExternalUrl, config.SamlSLOPath)
}

func buildUrl(baseUrl string, path string) string {
	trailingPattern := regexp.MustCompile("/$")
	leadingPattern := regexp.MustCompile("^/?(.*)$")
	baseUrl = trailingPattern.ReplaceAllString(baseUrl, "")
	path = leadingPattern.ReplaceAllString(path, "/${1}")
	return baseUrl + path
}

func DownloadIdpMetadata(config *SamlServiceProviderConfig) ([]byte, error) {
	//download metadata from idp
	config.Logger.Infof("Downloading IDP metadata from: %s", config.IdpMetaDataUrl)
	resp, err := http.Get(config.IdpMetaDataUrl)
	if err != nil {
		config.Logger.Errorf("Cannot download metadata: %s", err.Error())
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		config.Logger.Errorf("Cannot download metadata: %s", err.Error())
		return nil, errors.New("Cannot download metadata")
	}
	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		config.Logger.Errorf("Cannot download metadata: %s", err.Error())
		return nil, err
	}
	return EntityDescriptor(bodyBytes)
}

func validateRole(roles []string, attributeName string, sessionData *securityprotocol.SessionData) error {
	fmt.Println("CHECK ROLES HERE 1234")
	fmt.Println("ATTRIBUTES")
	for k, v := range sessionData.SessionAttributes {
		fmt.Println(k)
		fmt.Println(v)
	}
	fmt.Println("ATTRIBUTES")
	fmt.Println(roles)
	fmt.Println(sessionData.SessionAttributes)
	fmt.Println(sessionData.SessionAttributes["dk:medcom:video:role:"])
	fmt.Println(attributeName)
	fmt.Println(sessionData.SessionAttributes)
	fmt.Println(sessionData.UserAttributes)
	fmt.Println("CHECK ROLES 1234")
	// initialize role map
	containRoles := map[string]bool{}
	for _, role := range roles {
		containRoles[role] = false
	}
	// get available roles
	presentedRolesString, ok := sessionData.SessionAttributes[attributeName]
	if !ok {
		return errors.New(fmt.Sprintf("no field with attribute name %s present", attributeName))
	}
	presentedRolesArray := strings.Fields(presentedRolesString)
	for _, role := range presentedRolesArray {
		if _, ok := containRoles[role]; ok {
			containRoles[role] = true
		}
	}
	// check all roles are set
	for k, v := range containRoles {
		if !v {
			return errors.New(fmt.Sprintf("role %s not set", k))
		}
	}
	return nil
}

func (a SamlServiceProvider) HandleService(w http.ResponseWriter, r *http.Request, service securityprotocol.HttpHandler) (int, error) {
	if a.SamlHandler.isSamlProtocol(r) {
		a.Logger.Debugf("Handling request as SAML")
		return a.SamlHandler.Handle(w, r)
	}

	// Get the session id
	sessionId := a.SamlHandler.GetSessionId(r)
	a.Logger.Debugf("SessionId: %s", sessionId)

	// The request identifies a session, check that the session is valid and get it
	if sessionId != "" {
		sessionData, err := a.sessionCache.FindSessionDataForSessionId(sessionId)
		if err != nil {
			a.Logger.Errorf("Cannot look up session in cache: %v", err.Error())
			return http.StatusInternalServerError, err
		}
		if sessionData != nil {
			// if allowed roles is set, validate if session data contains a valid role
			if a.Config != nil && len(a.Config.AllowedRoles) > 0 {
				// build allowed role list; each item in list means OR and spaces inside item means AND: eg. AllowedRoles=["admin public", "root", "kit test"]
				// translates to (admin AND public) OR (root) OR (kit AND test)
				roleErr := errors.New("could not find a valid role")
				for _, role := range a.Config.AllowedRoles {
					role = strings.TrimSpace(role)
					andRoles := strings.Fields(role)
					// check if roles exist
					if err := validateRole(andRoles, a.Config.RoleAttributeName, sessionData); err == nil {
						// exit out of loop since a valid role is already found
						roleErr = nil
						break
					}
				}
				if roleErr != nil {
					a.Logger.Error(err.Error())
					return http.StatusUnauthorized, err
				}
			}

			// Check if the user is requesting sessiondata
			handlerFunc := securityprotocol.IsRequestForSessionData(sessionData, a.sessionCache, w, r)
			if handlerFunc != nil {
				a.Logger.Debugf("Handling session data request")
				return handlerFunc()
			}

			// The session id ok ... pass-through to next handler
			r.Header.Add(a.sessionHeaderName, sessionId)

			if len(a.SessiondataHeaderName) > 0 {
				sessionDataValue, err := getSessionDataValue(sessionData)
				if err != nil {
					a.Logger.Error(fmt.Sprintf("Error '%s' creating sessiondatavalue for header (sesssionid: %s)", err.Error(), sessionId))
					return http.StatusInternalServerError, err
				}
				r.Header.Set(a.SessiondataHeaderName, sessionDataValue)
			}

			return service.Handle(w, r)
		}
	}

	authenticateStatusCode, err := a.GenerateAuthenticationRequest(w, r)
	return authenticateStatusCode, err
}

func getSessionDataValue(sessionData *securityprotocol.SessionData) (string, error) {
	sessionDataBytes, marshalErr := json.Marshal(sessionData)
	if marshalErr != nil {
		return "", marshalErr
	}
	encodedData := base64.StdEncoding.EncodeToString(sessionDataBytes)
	return encodedData, nil

}

func (a *SamlServiceProvider) CreateLogoutResponse(logoutRequest *saml2.LogoutRequest, w http.ResponseWriter) (int, error) {

	status := saml2.StatusCodeSuccess
	relayState := ""

	responseDocTree, err := a.SamlServiceProvider.BuildLogoutResponseDocument(status, logoutRequest.ID)
	if err != nil {
		a.Logger.Errorf("Error building logout response: %s", err.Error())
		return http.StatusInternalServerError, err
	}

	responseBytes, err := a.SamlServiceProvider.BuildLogoutResponseBodyPostFromDocument(relayState, responseDocTree)
	if err != nil {
		a.Logger.Errorf("Error building logout response post from document: %s", err.Error())
		return http.StatusInternalServerError, err
	}

	w.Write(responseBytes)
	return http.StatusOK, err
}

func (a *SamlServiceProvider) ParseLogoutPayload(r *http.Request) (*saml2.LogoutRequest, *types.LogoutResponse, error) {

	encodedRequest, err := ioutil.ReadAll(r.Body)
	if err != nil {
		a.Logger.Errorf("Error reading body of logout request: %s", err.Error())
		return nil, nil, err
	}
	encodedRequestString := string(encodedRequest)
	a.Logger.Debugf("Considering logout payload: %s", encodedRequestString)
	if len(encodedRequest) == 0 {
		return nil, nil, nil
	}

	if strings.HasPrefix(encodedRequestString, "SAMLResponse=") {
		urlEncoded := encodedRequestString[13:len(encodedRequestString)]
		urlDecoded, err := url.QueryUnescape(urlEncoded)
		if err != nil {
			// Lets assume it was not urlDecoded
			urlDecoded = urlEncoded
		}
		a.Logger.Debugf("Processing payload: as SAMLResponse %s", urlDecoded)
		logoutResponse, err := a.SamlServiceProvider.ValidateEncodedLogoutResponsePOST(urlDecoded)
		if err != nil {
			a.Logger.Errorf("Error validating encoded logout response (decoded payload: %s) (error: %s)", urlDecoded, err.Error())
			return nil, logoutResponse, err
		}

		if logoutResponse == nil {
			a.Logger.Errorf("Could not validate logoutResponse: %s", encodedRequestString)
			return nil, nil, errors.New("Could not validate logoutResponse")
		}
		return nil, logoutResponse, nil
	}

	if strings.HasPrefix(encodedRequestString, "SAMLRequest=") {
		urlEncoded := encodedRequestString[12:len(encodedRequestString)]
		urlDecoded, err := url.QueryUnescape(urlEncoded)
		if err != nil {
			// Lets assume it was not urlDecoded
			urlDecoded = urlEncoded
		}
		a.Logger.Debugf("Processing payload: as SAMLRequest %s", urlDecoded)
		logoutRequest, err := a.SamlServiceProvider.ValidateEncodedLogoutRequestPOST(urlDecoded)

		if err != nil {
			a.Logger.Errorf("Error validating encoded logout request (decoded payload: %s) (error: %s)", urlDecoded, err.Error())
			return nil, nil, err
		}

		if logoutRequest == nil {
			a.Logger.Errorf("Could not validate logoutrequest: %s", encodedRequestString)
			return nil, nil, errors.New("Could not validate logout request")
		}
		return logoutRequest, nil, nil
	}

	a.Logger.Debugf("Could not determine payload: %s", encodedRequestString)
	return nil, nil, nil
}

func (a SamlServiceProvider) GenerateAuthenticationRequest(w http.ResponseWriter, r *http.Request) (int, error) {
	a.Logger.Debugf("No Session found, redirecting to IDP")
	relayState := buildUrl(a.externalUrl, r.RequestURI)

	err := a.SamlServiceProvider.AuthRedirect(w, r, relayState)
	if err != nil {
		a.Logger.Errorf("Error generating authentication request: %s", err.Error())
		return http.StatusInternalServerError, err
	}
	return http.StatusFound, nil
}

func (provider *SamlServiceProvider) Metadata() (*types.EntityDescriptor, error) {
	spMetadata, err := provider.SamlServiceProvider.Metadata()
	if err != nil {
		provider.Logger.Errorf("Error getting metadata from samlprovider: %s", err.Error())
		return spMetadata, err
	}
	spMetadata.SPSSODescriptor.SingleLogoutServices = []types.Endpoint{{
		Binding:  saml2.BindingHttpPost,
		Location: provider.SamlServiceProvider.ServiceProviderSLOURL,
	}}
	return spMetadata, nil
}
