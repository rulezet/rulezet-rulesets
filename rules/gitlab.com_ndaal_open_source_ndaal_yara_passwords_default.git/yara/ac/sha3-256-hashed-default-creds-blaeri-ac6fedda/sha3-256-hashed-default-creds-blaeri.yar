rule sha3_256_hashed_default_creds_blaeri
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for blaeri."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f5168c85667a567430d7ad26ea6d4994a4f8c975b52c80f7d9c25d2178ac6d9b"
    $a1="f889e440a20c266a1465a46c857e15097bdd74c5677eea575363ba1668388594"
condition:
    ($a0 and $a1)
}