rule sha256_hashed_default_creds_weblogic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for weblogic."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8443a814600766bbf5bc87725ebc9c7635651af65c3f67ef86a25d11e24559cc"
    $a1="bbc5e661e106c6dcd8dc6dd186454c2fcba3c710fb4d8e71a60c93eaf077f073"
condition:
    ($a0 and $a1)
}