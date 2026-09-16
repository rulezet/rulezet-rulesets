rule sha224_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c7c7018f6e341a1a8587d2bd0568fa57f0828f4d495d78f1560f41e"
    $a1="71c634a9ebaed1ce7b347ced5a1f71047da0bb1fe2163d9ad8d2a1b0"
condition:
    ($a0 and $a1)
}