package samlprovider

import (
	"io/ioutil"
	"testing"
	"gotest.tools/assert"
)


func TestGetSignedAssertions(t *testing.T)  {
    bytes, _ := ioutil.ReadFile("./testdata/samlresponse.base64")
    encoded := string(bytes)
    assertionXml, _ := GetSignedAssertions(encoded, nil)
    ioutil.WriteFile("./testdata/etree.xml", []byte(assertionXml), 0644)
    calculated,_ := GetSignedAssertions(encoded, nil)
    ioutil.WriteFile("./testdata/regex.xml", []byte(calculated), 0644)
}



func TestExtractNameID(t *testing.T)  {
    bytes, _ := ioutil.ReadFile("./testdata/authenticationToken.base64")
    encoded := string(bytes)
    NameID := ExtractNameID(encoded)
    assert.Equal(t,NameID,"testbruger1")

}

func TestExtractSessionIndex(t *testing.T)  {
    bytes, _ := ioutil.ReadFile("./testdata/authenticationToken.base64")
    encoded := string(bytes)
    SessionIndex := ExtractSessionIndex(encoded)
    assert.Equal(t,SessionIndex,"97deb2ce-ca07-41da-b076-429a35d3b559::9db5d2e7-13c5-4d4f-8b49-079649ca20bd")

}

