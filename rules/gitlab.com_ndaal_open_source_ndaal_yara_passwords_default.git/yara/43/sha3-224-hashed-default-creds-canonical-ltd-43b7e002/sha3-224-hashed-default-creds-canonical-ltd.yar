rule sha3_224_hashed_default_creds_canonical_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canonical_ltd."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="effd0fd96c25b5d2012f3678f922700b9a70a1e48e3c96591a3e91c6"
    $a1="effd0fd96c25b5d2012f3678f922700b9a70a1e48e3c96591a3e91c6"
condition:
    ($a0 and $a1)
}