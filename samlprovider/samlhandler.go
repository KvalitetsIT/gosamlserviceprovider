package samlprovider

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
	"github.com/google/uuid"
	"github.com/russellhaering/gosaml2/types"
	"go.uber.org/zap"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"github.com/beevik/etree"
)

type SamlHandler struct {
	callbackPath    string
	logoutPath      string
	metadataPath    string
	sloCallbackPath string
	logoutLandingPage string

	cookieDomain string
	cookiePath   string
	cookieHttpOnly bool

	sessionHeaderName  string
	sessionExpiryHours string

	provider *SamlServiceProvider
	Logger   *zap.SugaredLogger
}

func NewSamlHandler(config *SamlServiceProviderConfig, provider *SamlServiceProvider) *SamlHandler {
	s := new(SamlHandler)
	config.Logger.Debugf("Configuring SamlHandler: %v", config)
	s.logoutPath = config.SamlLogoutPath
	s.metadataPath = config.SamlMetadataPath
	s.callbackPath = config.SamlSSOPath
	s.sloCallbackPath = config.SamlSLOPath
	s.cookieDomain = config.CookieDomain
	s.cookiePath = config.CookiePath
	s.cookieHttpOnly = config.CookieHttpOnly
	s.sessionHeaderName = config.SessionHeaderName
	s.sessionExpiryHours = config.SessionExpiryHours

	if (config.LogoutLandingPage == "") {
		s.logoutLandingPage = config.ExternalUrl
	} else {
		s.logoutLandingPage = config.LogoutLandingPage
	}

	s.provider = provider
	s.Logger = config.Logger
	return s
}

func (handler *SamlHandler) isSamlProtocol(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, handler.callbackPath) {
		return true
	}
	if strings.HasPrefix(r.URL.Path, handler.metadataPath) {
		return true
	}
	if strings.HasPrefix(r.URL.Path, handler.logoutPath) {
		return true
	}
	if strings.HasPrefix(r.URL.Path, handler.sloCallbackPath) {
		return true
	}
	return false
}

func (handler *SamlHandler) GetSessionId(r *http.Request) string {
	sessionId := r.Header.Get(handler.sessionHeaderName)
	cookie, _ := r.Cookie(handler.sessionHeaderName)
	if sessionId != "" {
		handler.Logger.Debugf("SessionId: %v found in Header", sessionId)
		return sessionId
	}
	if cookie != nil {
		handler.Logger.Debugf("SessionId: %v found in Cookie", cookie.Value)
		return cookie.Value
	}
	return ""
}

func (handler *SamlHandler) Handle(w http.ResponseWriter, r *http.Request) (int, error) {
	if strings.HasPrefix(r.URL.Path, handler.callbackPath) {
		return handler.handleSamlLoginResponse(w, r)
	}

	if strings.HasPrefix(r.URL.Path, handler.metadataPath) {
		return handler.handleMetadata(w, r)
	}

	if strings.HasPrefix(r.URL.Path, handler.logoutPath) {
		return handler.handleSLO(r, w)

	}
	if strings.HasPrefix(r.URL.Path, handler.sloCallbackPath) {
		return handler.handleSLOCallback(r, w)

	}
	return http.StatusOK, nil
}

func (handler *SamlHandler) handleSLOCallback(r *http.Request, w http.ResponseWriter) (int, error) {
	sessionId := handler.GetSessionId(r)
	if sessionId == "" {
		handler.Logger.Warnf("No sessionId provided for logout")
		return http.StatusBadRequest, nil
	}
	handler.Logger.Debugf("Received logout callback from IDP for session: %s ", sessionId)

	logoutRequest, _, err := handler.provider.ParseLogoutPayload(r)
	if (err != nil) {
		return http.StatusBadRequest, err
	}

	cookie := http.Cookie{
		Name:     handler.sessionHeaderName,
		MaxAge:   -1,
		Domain:   handler.cookieDomain,
		Path:     handler.cookiePath,
		HttpOnly: handler.cookieHttpOnly,
	}

	handler.Logger.Debugf("Clearing session cookie")
	http.SetCookie(w, &cookie)
	handler.Logger.Debugf("Deleting session data from cache")
	err = handler.provider.sessionCache.DeleteSessionData(sessionId)
	if (err != nil) {
		handler.Logger.Errorf("Unable to delete session data: %s", err.Error())
		return http.StatusInternalServerError, err
	}
	handler.Logger.Debugf("The user is succesfully logged out in this application")

	if (logoutRequest != nil) {
		handler.provider.CreateLogoutResponse(logoutRequest, w)
		return http.StatusOK, nil
	}

	http.Redirect(w, r, handler.logoutLandingPage, http.StatusFound)
	return http.StatusFound, nil
}

func (handler *SamlHandler) handleSLO(r *http.Request, w http.ResponseWriter) (int, error) {
	sessionId := handler.GetSessionId(r)
	if (sessionId == "") {
		handler.Logger.Warnf("No sessionId provided for logout")
		return http.StatusBadRequest, nil
	}
	handler.Logger.Debugf("Initiating log out of session: %s ", sessionId)
	session, err := handler.provider.sessionCache.FindSessionDataForSessionId(sessionId)
	if (err != nil) {
		handler.Logger.Errorf("Cannot lookup session: %s", err)
		return http.StatusInternalServerError, err
	}
	if (session == nil) {
		handler.Logger.Warnf("No session found for id: %v", sessionId)
		return http.StatusInternalServerError, err
	}
	//TODO these should be found on the SessionData directly
	nameIDs := ExtractNameID(session.Authenticationtoken)
	if nameIDs == "" {
		handler.Logger.Warnf("NameID not found on session")
		return http.StatusInternalServerError, err
	}
	sessionIndex := ExtractSessionIndex(session.Authenticationtoken)
	if sessionIndex == "" {
		handler.Logger.Warnf("SessionIndex not found on session")
		return http.StatusInternalServerError, err
	}
	handler.Logger.Debugf("Sending logout request to IDP with NameID: %s SessionIndex: %s", nameIDs, sessionIndex)
	logoutRequestDocument, _ := handler.provider.SamlServiceProvider.BuildLogoutRequestDocument(nameIDs, sessionIndex)
	logoutURLRedirect, _ := handler.provider.SamlServiceProvider.BuildLogoutURLRedirect("", logoutRequestDocument)
	http.Redirect(w, r, logoutURLRedirect, http.StatusFound)
	return http.StatusFound, nil
}


func (handler *SamlHandler) handleMetadata(w http.ResponseWriter, r *http.Request) (int, error) {
	spMetadata, _ := handler.provider.Metadata()
	spMetadataXml, _ := xml.MarshalIndent(spMetadata, "", "  ")
	w.Write(spMetadataXml)
	return http.StatusOK, nil
}

func (handler *SamlHandler) handleSamlLoginResponse(w http.ResponseWriter, r *http.Request) (int, error) {
	handler.Logger.Debugf("Processing Login callback")
	err := r.ParseForm()
	if err != nil {
		handler.Logger.Warnf("Error parsing form data: %v", err)
		return http.StatusBadRequest, nil
	}

	samlResponse := r.FormValue("SAMLResponse")
	assertionInfo, err := handler.provider.SamlServiceProvider.RetrieveAssertionInfo(samlResponse)
	if err != nil {
		handler.Logger.Warnf("Invalid assertions: %v", err)
		fmt.Fprintf(w, "Invalid assertions: %s", err.Error())
		return http.StatusForbidden, nil
	}
	if assertionInfo.WarningInfo.InvalidTime {
		handler.Logger.Warnf("Invalid assertions: %v", "InvalidTime")
		fmt.Fprintf(w, "Invalid assertions: %s", "InvalidTime")
		return http.StatusForbidden, nil
	}
	if assertionInfo.WarningInfo.NotInAudience {
		handler.Logger.Warnf("Invalid assertions: %v", "UserNotInAudience")
		fmt.Fprintf(w, "Invalid assertions: %s", "UserNotInAudience")
		return http.StatusForbidden, nil
	}
	handler.Logger.Debugf("Succesfully validate SAML assertion")
	cert, err := handler.provider.SamlServiceProvider.GetDecryptCertificate()
	if (err != nil) {
		handler.Logger.Errorf("Error creating sessionData: %s", err.Error())
		return http.StatusInternalServerError, nil
	}
	assertionXml, err := GetSignedAssertions(samlResponse, cert)
	if (err != nil) {
		handler.Logger.Errorf("Error getting SignedAssertion: %s", err.Error())
		return http.StatusInternalServerError, nil
	}

	sessionDataCreator, err := securityprotocol.NewSamlSessionDataCreatorWithAssertionAndClientCert(uuid.New().String(), assertionXml, &assertionInfo.Assertions[0], "")
	if (err != nil) {
		handler.Logger.Errorf("Error creating sessionData: %s", err.Error())
		return http.StatusBadRequest, nil
	}
	handler.Logger.Debugf("Creating session data")
	sessionData, err := sessionDataCreator.CreateSessionData()
	if (err != nil) {
		handler.Logger.Errorf("Error creating sessionData: %s", err.Error())
		return http.StatusBadRequest, nil
	}
	handler.Logger.Debugf("Adding NameID and SessionIndex to session data")
	//TODO These should be saved somewhere in the SessionData
	/*sessionData.UserAttributes["NameID"] = []string{assertionInfo.NameID}
	sesionData.SessionAttributes["SessionIndex"] = assertionInfo.SessionIndex*/
	hours, err := strconv.Atoi(handler.sessionExpiryHours)
	if (err != nil) {
	  hours = 3
	}
	expiry := time.Now().Add(time.Duration(hours) * time.Hour)
	sessionData.Timestamp = expiry
	err = handler.provider.sessionCache.SaveSessionData(sessionData)
	if (err != nil) {
		handler.Logger.Errorf("Error saving sessionData: %s", err.Error())
		return http.StatusBadRequest, nil
	}

	handler.Logger.Debugf("SessionData saved for id: %v => %v", sessionData.Sessionid, sessionData.UserAttributes)
	handler.Logger.Debugf("Setting session cookie: %v => %v", handler.provider.sessionHeaderName, sessionData.Sessionid)
	cookie := http.Cookie{
		Name:     handler.provider.sessionHeaderName,
		Value:    sessionData.Sessionid,
		Expires:  expiry,
		Domain:   handler.cookieDomain,
		Path:     handler.cookiePath,
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)
	w.Header().Add(handler.provider.sessionHeaderName, sessionData.Sessionid)
	relayState := r.FormValue("RelayState")
	handler.Logger.Debugf("Redirecting to original URL: %v", relayState)
	http.Redirect(w, r, relayState, http.StatusFound)

	return http.StatusFound, nil
}

func GetSignedAssertions(samlResponse string, cert *tls.Certificate) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return "", err
	}
	pattern := regexp.MustCompile("(?s)(<([^:]*:)?Assertion.*Assertion>)")
	assertions := pattern.FindString(string(decoded))


	if (len(assertions) == 0) {
		//TODO optionally decrypt
		encryptedPattern := regexp.MustCompile("(?s)(<([^:]*:)?EncryptedAssertion.*EncryptedAssertion>)")
		encryptedAssertion := encryptedPattern.FindString(string(decoded))

		if (len(encryptedAssertion) > 0) {

			namespace := regexp.MustCompile("(?s)<([[:alpha:]][^:][[:alpha:]]*)?(:)?EncryptedAssertion>")
			encryptedAssertionNoNamespace := namespace.ReplaceAllString(encryptedAssertion,"<${1}${2}EncryptedAssertion xmlns:${1}=\"urn:oasis:names:tc:SAML:2.0:assertion\">" )

			ea := new(types.EncryptedAssertion)
			err = xml.Unmarshal([]byte(encryptedAssertionNoNamespace), ea)
			if err != nil {
				return "", err
			}
			decryptedAssertion, err := ea.DecryptBytes(cert)
			return string(decryptedAssertion), err
		}
	}

	namespace := regexp.MustCompile("(?s)<([^:]*)?(:)?Assertion xmlns=\"([^\"]*)\"")
	assertions = namespace.ReplaceAllString(assertions,"<${1}${2}Assertion xmlns=\"$3\" xmlns:${1}=\"$3\"" )
	return assertions, nil
}


func ExtractNameID(assertionXml string) string {
    decoded,_ := base64.StdEncoding.DecodeString(assertionXml)
    document := etree.NewDocument()
    document.ReadFromString(string(decoded))
    elements := document.FindElements("//NameID")
    if len(elements) == 1 {
        return elements[0].Text()
    }
    return ""
}

func ExtractSessionIndex(assertionXml string) string {
    decoded,_ := base64.StdEncoding.DecodeString(assertionXml)
    document := etree.NewDocument()
    document.ReadFromString(string(decoded))
    elements := document.FindElements("//AuthnStatement")
    if len(elements) == 1 {
        return elements[0].SelectAttrValue("SessionIndex","")
    }
    return ""
}
