package samlprovider

import (
	"encoding/xml"
	"github.com/russellhaering/gosaml2/types"
	"strings"
)

type EntitiesDescriptor struct {
	XMLName           xml.Name `xml:"EntitiesDescriptor"`
	EntityDescriptors types.EntityDescriptor
}

func EntityDescriptor(bodyBytes []byte) ([]byte, error) {
	idpMetadata := string(bodyBytes)
	if strings.Contains(idpMetadata, "EntitiesDescriptor") {
		descriptors := &EntitiesDescriptor{}
		xml.Unmarshal(bodyBytes, descriptors)
		return xml.Marshal(descriptors.EntityDescriptors)
	} else {
		return bodyBytes, nil
	}
}
