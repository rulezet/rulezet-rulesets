rule sha1_hashed_default_creds_myiosoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for myiosoft."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="89e495e7941cf9e40e6980d14a16bf023ccd4c91"
    $a1="89e495e7941cf9e40e6980d14a16bf023ccd4c91"
condition:
    ($a0 and $a1)
}