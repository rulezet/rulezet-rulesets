rule mysql41_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*04FA1C7BAE48871D1C541B0B7180DEC994478503"
    $a1="*EE9872CA8DB79E5FC4D539EC55FE38399FBCB524"
    $a2="*04FA1C7BAE48871D1C541B0B7180DEC994478503"
    $a3="*91323F01AC53E6A371EC6C603E07D953D8380147"
    $a4="*04FA1C7BAE48871D1C541B0B7180DEC994478503"
    $a5="*39D3BCB34AE5C2C0F33A47AA9CA8CEE64F9C5D38"
    $a6="*845A9ADD7E1A82B6459804066B3A45D0025897B6"
    $a7="*AF57748CB0F2DEEA7E473FE7CBCC2A135071A202"
    $a8="*DE597F01CC5D219FFE5896B9A8119B950125DC7C"
    $a9="*DE597F01CC5D219FFE5896B9A8119B950125DC7C"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}