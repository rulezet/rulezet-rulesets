rule sha1_hashed_default_creds_comcast_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comcast_smc."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="08772351b878d7d36631955c017fd53079c2445b"
    $a1="8f198fad85c1ade2c1fa575158726672d789eeea"
    $a2="ece362775003aa2cc452ed00d3c1fa5e0f7bf77a"
    $a3="8f198fad85c1ade2c1fa575158726672d789eeea"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}