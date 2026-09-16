rule sha3_256_hashed_default_creds_darkman
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for darkman."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="08ef0fddbc3238b40f0884d2299f1b91a6692f96d160388c9fd8bde732ac1921"
    $a1="08ef0fddbc3238b40f0884d2299f1b91a6692f96d160388c9fd8bde732ac1921"
condition:
    ($a0 and $a1)
}