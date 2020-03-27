package samlprovider

import (
	"io/ioutil"
	"testing"
)


func TestGetSignedAssertions(t *testing.T)  {
    bytes, _ := ioutil.ReadFile("./testdata/samlresponse.base64")
    encoded := string(bytes)
    assertionXml, _ := GetSignedAssertionsWithEtree(encoded)
    ioutil.WriteFile("./testdata/etree.xml", []byte(assertionXml), 0644)
    calculated,_ := GetSignedAssertions(encoded)
    ioutil.WriteFile("./testdata/regex.xml", []byte(calculated), 0644)

}