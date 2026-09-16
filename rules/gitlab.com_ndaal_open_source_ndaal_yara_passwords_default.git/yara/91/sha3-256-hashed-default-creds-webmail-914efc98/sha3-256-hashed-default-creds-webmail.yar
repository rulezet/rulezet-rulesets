rule sha3_256_hashed_default_creds_webmail
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webmail."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ee66b0d22776c2f9f070b5b971f35a64d56dc2ee50a839fa8dfe1d510dd3b2fd"
    $a1="a3b7526009c38f90a86e2b5f93522c2aa32fc3b955ff985c80f4b97ebd3025f3"
condition:
    ($a0 and $a1)
}