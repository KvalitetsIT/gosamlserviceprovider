<?php
/**
 * SAML 2.0 remote SP metadata for simpleSAMLphp.
 *
 * See: https://simplesamlphp.org/docs/stable/simplesamlphp-reference-sp-remote
 */

/*
 * Example simpleSAMLphp SAML 2.0 SP
 */
$metadata['dev:oth:citizen'] = array (
  'entityid' => 'dev:oth:citizen',
  'contacts' => 
  array (
  ),
  'metadata-set' => 'saml20-sp-remote',
  'AssertionConsumerService' => 
  array (
    0 => 
    array (
      'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      'Location' => 'http://localhost:8082/client-citizen/saml/SSO',
      'index' => 0,
      'isDefault' => true,
    ),
    1 => 
    array (
      'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact',
      'Location' => 'http://localhost:8082/client-citizen/saml/SSO',
      'index' => 1,
    ),
  ),
  'SingleLogoutService' => 
  array (
    0 => 
    array (
      'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      'Location' => 'http://localhost:8082/client-citizen/saml/SingleLogout',
    ),
    1 => 
    array (
      'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
      'Location' => 'http://localhost:8082/client-citizen/saml/SingleLogout',
    ),
  ),
  'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  'keys' => 
  array (
    0 => 
    array (
      'encryption' => false,
      'signing' => true,
      'type' => 'X509Certificate',
      'X509Certificate' => 'MIIDdzCCAl+gAwIBAgIEcD+HLjANBgkqhkiG9w0BAQsFADBsMRAwDgYDVQQGEwdVbmtub3duMRAw
DgYDVQQIEwdVbmtub3duMRAwDgYDVQQHEwdVbmtub3duMRAwDgYDVQQKEwdVbmtub3duMRAwDgYD
VQQLEwdVbmtub3duMRAwDgYDVQQDEwdVbmtub3duMB4XDTE1MDgxMjEwMzUzMFoXDTE1MTExMDEw
MzUzMFowbDEQMA4GA1UEBhMHVW5rbm93bjEQMA4GA1UECBMHVW5rbm93bjEQMA4GA1UEBxMHVW5r
bm93bjEQMA4GA1UEChMHVW5rbm93bjEQMA4GA1UECxMHVW5rbm93bjEQMA4GA1UEAxMHVW5rbm93
bjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ5LpUcYDhTN4fWUsdXnrIkN/r+d+Kqf
3Fa5VIh+Y65HYnYgoTbBn1jnIhWmgyGllGlwC8FoQ1ALbP6Ai1blWiDj+yujQkHiKJx9cPjyTsj+
oDSqYQh/UK1jh80Jk8RQOnT8EKWP8SUDsH7Md2oTTC+Go8bTCA9rYIIwBeQpuFKxsduu8xlXaOME
9SbBh3f7cyar/xam/d+FvfrdUqdgYNaB7c3wzfgUSRpHS/zbzeSP7RlBdaijkyRAUJKSFHxkrRLZ
CQ25gFzc4G8GmtDsWyhREB62iQsWNOvrLibdDO3Gh2OIPSNFb3vVFOH9b9gS7luA5eRjR0E42H+p
Vzf0mukCAwEAAaMhMB8wHQYDVR0OBBYEFGlPJyPlsCqcrRxOIlXwYB01oUc1MA0GCSqGSIb3DQEB
CwUAA4IBAQBgneEvpuQDfGeYrZCFAZDyrmWUwlMrzd/8ZbNC3ukXOoVH9AckQDtJXpoKFxcakPE1
BCBAhuxwHpzczhwKnkOppdTdVpjfAujVurIcDCM5s9PNECpP0xBNTfqgyI3Z6TUcTQJmLZwAa9u2
oIaHOyxluj8GAunHS/ikaNl343+jvqWqx1jbbvG+Th5sJW0Py4/g89sA+QV83Ih9r9M+NopZIazo
SvM7+7UK/VuUuBzb3C5TsCQfNq9i61viFw4O/MwkmeSl6idh/fjc5zcsevf4UTuaYqcs7C9cwnt+
MjrAkTi/eIf9ZlkJ2faUt5DEgccALJHrV76uzPgE1GrcAurU',
    ),
    1 => 
    array (
      'encryption' => true,
      'signing' => false,
      'type' => 'X509Certificate',
      'X509Certificate' => 'MIIDdzCCAl+gAwIBAgIEcD+HLjANBgkqhkiG9w0BAQsFADBsMRAwDgYDVQQGEwdVbmtub3duMRAw
DgYDVQQIEwdVbmtub3duMRAwDgYDVQQHEwdVbmtub3duMRAwDgYDVQQKEwdVbmtub3duMRAwDgYD
VQQLEwdVbmtub3duMRAwDgYDVQQDEwdVbmtub3duMB4XDTE1MDgxMjEwMzUzMFoXDTE1MTExMDEw
MzUzMFowbDEQMA4GA1UEBhMHVW5rbm93bjEQMA4GA1UECBMHVW5rbm93bjEQMA4GA1UEBxMHVW5r
bm93bjEQMA4GA1UEChMHVW5rbm93bjEQMA4GA1UECxMHVW5rbm93bjEQMA4GA1UEAxMHVW5rbm93
bjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ5LpUcYDhTN4fWUsdXnrIkN/r+d+Kqf
3Fa5VIh+Y65HYnYgoTbBn1jnIhWmgyGllGlwC8FoQ1ALbP6Ai1blWiDj+yujQkHiKJx9cPjyTsj+
oDSqYQh/UK1jh80Jk8RQOnT8EKWP8SUDsH7Md2oTTC+Go8bTCA9rYIIwBeQpuFKxsduu8xlXaOME
9SbBh3f7cyar/xam/d+FvfrdUqdgYNaB7c3wzfgUSRpHS/zbzeSP7RlBdaijkyRAUJKSFHxkrRLZ
CQ25gFzc4G8GmtDsWyhREB62iQsWNOvrLibdDO3Gh2OIPSNFb3vVFOH9b9gS7luA5eRjR0E42H+p
Vzf0mukCAwEAAaMhMB8wHQYDVR0OBBYEFGlPJyPlsCqcrRxOIlXwYB01oUc1MA0GCSqGSIb3DQEB
CwUAA4IBAQBgneEvpuQDfGeYrZCFAZDyrmWUwlMrzd/8ZbNC3ukXOoVH9AckQDtJXpoKFxcakPE1
BCBAhuxwHpzczhwKnkOppdTdVpjfAujVurIcDCM5s9PNECpP0xBNTfqgyI3Z6TUcTQJmLZwAa9u2
oIaHOyxluj8GAunHS/ikaNl343+jvqWqx1jbbvG+Th5sJW0Py4/g89sA+QV83Ih9r9M+NopZIazo
SvM7+7UK/VuUuBzb3C5TsCQfNq9i61viFw4O/MwkmeSl6idh/fjc5zcsevf4UTuaYqcs7C9cwnt+
MjrAkTi/eIf9ZlkJ2faUt5DEgccALJHrV76uzPgE1GrcAurU',
    ),
  ),
  'validate.authnrequest' => true,
  'saml20.sign.assertion' => true,
);
