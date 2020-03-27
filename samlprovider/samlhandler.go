package samlprovider

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
	"github.com/google/uuid"
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

	cookieDomain string
	cookiePath   string

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
	s.sessionHeaderName = config.SessionHeaderName
	s.sessionExpiryHours = config.SessionExpiryHours

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

func (handler *SamlHandler) GetSessionId(r *http.Request) (string, error) {
	sessionId := r.Header.Get(handler.sessionHeaderName)
	cookie, _ := r.Cookie(handler.sessionHeaderName)
	if sessionId != "" {
		handler.Logger.Debugf("SessionId: %v found in Header", sessionId)
		return sessionId, nil
	}
	if cookie != nil {
		handler.Logger.Debugf("SessionId: %v found in Cookie", cookie.Value)
		return cookie.Value, nil
	}
	return "", nil
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
	sessionId, err := handler.GetSessionId(r)
	if err != nil {
		handler.Logger.Warnf("Unable to extraxt sessionID from request: %v", err)
		return http.StatusInternalServerError, err
	}
	if sessionId == "" {
		handler.Logger.Warnf("No sessionId provided for logout")
		return http.StatusBadRequest, nil
	}
	handler.Logger.Debugf("Received logout callback from IDP for session: %s ", sessionId)
	cookie := http.Cookie{
		Name:     handler.sessionHeaderName,
		MaxAge:   -1,
		Domain:   handler.cookieDomain,
		Path:     handler.cookiePath,
		HttpOnly: true,
	}
	handler.Logger.Debugf("Clearing session cookie")
	http.SetCookie(w, &cookie)
	handler.Logger.Debugf("Deleting session data from cache")
	err = handler.provider.sessionCache.DeleteSessionData(sessionId)
	if err != nil {
		handler.Logger.Warnf("Unable to delete session data", err)
		return http.StatusInternalServerError, err
	}
	fmt.Fprintf(w, "You are succesfully logged out")
	return http.StatusOK, nil
}

func (handler *SamlHandler) handleSLO(r *http.Request, w http.ResponseWriter) (int, error) {
	sessionId, err := handler.GetSessionId(r)
	if err != nil {
		handler.Logger.Warnf("Unable to extraxt sessionID from request: %v", err)
		return http.StatusInternalServerError, err
	}
	if sessionId == "" {
		handler.Logger.Warnf("No sessionId provided for logout")
		return http.StatusBadRequest, nil
	}
	handler.Logger.Debugf("Initiating log out of session: %s ", sessionId)
	session, err := handler.provider.sessionCache.FindSessionDataForSessionId(sessionId)
	if err != nil {
		handler.Logger.Warnf("Cannot lookup session: %v", err)
		return http.StatusInternalServerError, err
	}
	if session == nil {
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
	assertionXml, _ := GetSignedAssertions(samlResponse)
	//handler.provider.SamlServiceProvider.
	sessionDataCreator, err := securityprotocol.NewSamlSessionDataCreatorWithAssertionAndClientCert(uuid.New().String(), assertionXml, &assertionInfo.Assertions[0], "")
	if err != nil {
		handler.Logger.Warnf("Error creating sessionData: %v", err)
		fmt.Println("Error creating sessionData: " + err.Error())
		return http.StatusBadRequest, nil
	}
	handler.Logger.Debugf("Creating session data")
	sessionData, err := sessionDataCreator.CreateSessionData()
	if err != nil {
		handler.Logger.Warnf("Error creating sessionData: %v", err)
		fmt.Println("Error creating sessionData: " + err.Error())
		return http.StatusBadRequest, nil
	}
	handler.Logger.Debugf("Adding NameID and SessionIndex to session data")
	//TODO These should be saved somewhere in the SessionData
	/*sessionData.UserAttributes["NameID"] = []string{assertionInfo.NameID}
	sesionData.SessionAttributes["SessionIndex"] = assertionInfo.SessionIndex*/
	hours, err := strconv.Atoi(handler.sessionExpiryHours)
	if err != nil {
	  hours = 3
	}
	expiry := time.Now().Add(time.Duration(hours) * time.Hour)
	sessionData.Timestamp = expiry
	err = handler.provider.sessionCache.SaveSessionData(sessionData)
	if err != nil {
		handler.Logger.Warnf("Error saving sessionData: %v", err)
		fmt.Println("Error saving sessionData: " + err.Error())
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

func GetSignedAssertions(samlResponse string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return "", err
	}
	//TODO optionally decrypt
	pattern := regexp.MustCompile("(<([^:]*:)?Assertion.*Assertion>)")
	assertions := pattern.FindString(string(decoded))

	namespace := regexp.MustCompile("<([^:]*)?(:)?Assertion xmlns=\"([^\"]*)\"")
    assertions = namespace.ReplaceAllString(assertions,"<${1}${2}Assertion xmlns=\"$3\" xmlns:${1}=\"$3\"" )
	return assertions, nil
}

func GetSignedAssertionsWithEtree(samlResponse string) (string,error) {
    decoded,_ := base64.StdEncoding.DecodeString(samlResponse)
    xml := string(decoded)
    document := etree.NewDocument()
    document.ReadFromString(xml)
    assertions := document.FindElements("//Assertion")[0]
    assertionDocument := etree.NewDocument()
    assertionDocument.SetRoot(assertions.Copy())
    assertionXml, _ := assertionDocument.WriteToString()
    return assertionXml,nil
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