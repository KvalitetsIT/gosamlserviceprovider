package gosamlserviceprovider

import (
	"encoding/xml"
	"fmt"
	securityprotocol "github.com/KvalitetsIT/gosecurityprotocol"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"net/http"
	"net/url"
	"strings"
)

type SamlHandler struct {
	callbackPath    string
	logoutPath      string
	metadataPath    string
	sloCallbackPath string

	cookieDomain string
	cookiePath   string

	sessionHeaderName string

	provider *SamlServiceProvider
	Logger   *zap.SugaredLogger
}

func NewSamlHandler(config *SamlServiceProviderConfig, provider *SamlServiceProvider) *SamlHandler {
	s := new(SamlHandler)
	config.Logger.Debugf("Configuring SamlHandler: %v", config)
	s.logoutPath = config.SamlLogoutUrl
	s.metadataPath = config.SamlMetadataUrl
	callback, err := getUrlPath(config.AssertionConsumerServiceUrl)
	if err != nil {
		config.Logger.Warnf("Unable to parse callback URL: %v", err)
	}
	s.callbackPath = callback

	sloCallbackPath, err := getUrlPath(config.SLOConsumerServiceUrl)
	if err != nil {
		config.Logger.Warnf("Unable to parse SLO URL: %v", err)
	}
	s.sloCallbackPath = sloCallbackPath

	s.cookieDomain = config.CookieDomain
	s.cookiePath = config.CookiePath
	s.sessionHeaderName = config.SessionHeaderName

	s.provider = provider
	s.Logger = config.Logger
	return s
}

func getUrlPath(urlString string) (string, error) {
	parsedUrl, err := url.Parse(urlString)
	if err != nil {
		return "", err
	}
	return parsedUrl.Path, nil
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
		Path:     "/",
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
	nameIDs := session.UserAttributes["NameID"]
	if nameIDs == nil || len(nameIDs) != 1 {
		handler.Logger.Warnf("NameID not found on session")
		return http.StatusInternalServerError, err
	}
	sessionIndex := session.SessionAttributes["SessionIndex"]
	if sessionIndex == "" {
		handler.Logger.Warnf("SessionIndex not found on session")
		return http.StatusInternalServerError, err
	}
	handler.Logger.Debugf("Sending logout request to IDP with NameID: %s SessionIndex: %s", nameIDs[0], sessionIndex)
	logoutRequestDocument, _ := handler.provider.SamlServiceProvider.BuildLogoutRequestDocument(nameIDs[0], sessionIndex)
	logoutURLRedirect, _ := handler.provider.SamlServiceProvider.BuildLogoutURLRedirect("", logoutRequestDocument)
	http.Redirect(w, r, logoutURLRedirect, http.StatusFound)
	return http.StatusFound, nil
}

func (handler *SamlHandler) handleMetadata(w http.ResponseWriter, r *http.Request) (int, error) {
	spMetadata, _ := handler.provider.SamlServiceProvider.MetadataWithSLO(24)
	spMetadataXml, _ := xml.MarshalIndent(spMetadata, "", "")
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

	assertionInfo, err := handler.provider.SamlServiceProvider.RetrieveAssertionInfo(r.FormValue("SAMLResponse"))
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
	assertionXml, _ := xml.Marshal(assertionInfo.Assertions[0])
	sessionDataCreator, err := securityprotocol.NewSamlSessionDataCreatorWithId(uuid.New().String(), string(assertionXml))
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
	//TODO shouldn't these be saved in the SAMLSessionDataCreator module??
	handler.Logger.Debugf("Adding NameID and SessionIndex to session data")
	sessionData.UserAttributes["NameID"] = []string{assertionInfo.NameID}
	sessionData.SessionAttributes["SessionIndex"] = assertionInfo.SessionIndex
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
		Expires:  *assertionInfo.SessionNotOnOrAfter,
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)
	w.Header().Add(handler.provider.sessionHeaderName, sessionData.Sessionid)
	relayState := r.FormValue("RelayState")
	handler.Logger.Debugf("Redirecting to original URL: %v", relayState)
	http.Redirect(w, r, relayState, http.StatusFound)
	return http.StatusFound, nil
}
