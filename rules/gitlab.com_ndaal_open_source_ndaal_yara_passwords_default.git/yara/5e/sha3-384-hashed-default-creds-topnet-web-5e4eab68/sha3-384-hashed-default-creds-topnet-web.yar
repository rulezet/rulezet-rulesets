rule sha3_384_hashed_default_creds_topnet_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for topnet_web."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="27681473ca9f5a75fb7ee8d50bbbcdc38650bb5133641d9fb50f864faaa2949144144a5dbb817bf7c0b92f7eb4996744"
    $a1="27681473ca9f5a75fb7ee8d50bbbcdc38650bb5133641d9fb50f864faaa2949144144a5dbb817bf7c0b92f7eb4996744"
condition:
    ($a0 and $a1)
}