rule nthash_hashed_default_creds_hosting_controller
{
    meta:
        id = "1HYAQyFEMdN82znnw1MXcz"
        fingerprint = "f079d6227fedf402340ae2ffc10286e140e73bff5f28e69e294aa77eb7254c31"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hosting_controller."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9e26c320b1dbf48a02cdef09c1d85ab0"
    $a1="83f77f64c068e95c64b8daef11b0279a"
condition:
    ($a0 and $a1)
}