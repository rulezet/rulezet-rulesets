rule sha384_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6b9c4b5380f3fd4ef46a47990a63551dbc3bf112dd1375e493f1e83c1e85a0e7fc75e3d39a69a1652304d6995c6e583b"
    $a1="6b9c4b5380f3fd4ef46a47990a63551dbc3bf112dd1375e493f1e83c1e85a0e7fc75e3d39a69a1652304d6995c6e583b"
    $a2="a8a30f05f7fcd4254c4f62146b345af017a22306a7aa989c544bf41709cfc830f6313bc14ea4d47a02cdf9767750280b"
    $a3="6b9c4b5380f3fd4ef46a47990a63551dbc3bf112dd1375e493f1e83c1e85a0e7fc75e3d39a69a1652304d6995c6e583b"
    $a4="6cd6e255b7f726821099ba11765af0902d128c2d29bdeccd0bb1d907cd347b909e48c27008375e291e03b1c594e04803"
    $a5="6b9c4b5380f3fd4ef46a47990a63551dbc3bf112dd1375e493f1e83c1e85a0e7fc75e3d39a69a1652304d6995c6e583b"
    $a6="6b9c4b5380f3fd4ef46a47990a63551dbc3bf112dd1375e493f1e83c1e85a0e7fc75e3d39a69a1652304d6995c6e583b"
    $a7="4b7d79fd9e55caac33d50b5d5337899adc8be5e7a1c55446f514104a427cf9859c47284a663af817bd3b2478a578ea4e"
    $a8="a8a30f05f7fcd4254c4f62146b345af017a22306a7aa989c544bf41709cfc830f6313bc14ea4d47a02cdf9767750280b"
    $a9="4b7d79fd9e55caac33d50b5d5337899adc8be5e7a1c55446f514104a427cf9859c47284a663af817bd3b2478a578ea4e"
    $a10="6cd6e255b7f726821099ba11765af0902d128c2d29bdeccd0bb1d907cd347b909e48c27008375e291e03b1c594e04803"
    $a11="4b7d79fd9e55caac33d50b5d5337899adc8be5e7a1c55446f514104a427cf9859c47284a663af817bd3b2478a578ea4e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}