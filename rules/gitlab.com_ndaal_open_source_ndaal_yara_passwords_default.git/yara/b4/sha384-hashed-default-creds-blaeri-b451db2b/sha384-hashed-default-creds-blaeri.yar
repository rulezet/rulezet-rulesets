rule sha384_hashed_default_creds_blaeri
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for blaeri."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2358c960f2c8b666b3ac4c09ef55d38889d2149932684a328f4572d616dfc0d0f19b565e20b3b3d5f5a38ad456b23dea"
    $a1="750a96e77d7cd98497f73687cd5252b9c3f7def02e6c3b6dcc0b10b44fc1e24fc6ab91d642d04252e69edac6dde0555e"
condition:
    ($a0 and $a1)
}