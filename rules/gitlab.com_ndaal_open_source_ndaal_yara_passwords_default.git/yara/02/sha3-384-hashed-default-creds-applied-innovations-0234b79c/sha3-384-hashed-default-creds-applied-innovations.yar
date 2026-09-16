rule sha3_384_hashed_default_creds_applied_innovations
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for applied_innovations."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cc471d8ee5472e526907d8aa92bec785d881ecf0c50835a045cb38c1583d770746cb09c658b2448ba2d5280ff35b0bcd"
    $a1="cc471d8ee5472e526907d8aa92bec785d881ecf0c50835a045cb38c1583d770746cb09c658b2448ba2d5280ff35b0bcd"
condition:
    ($a0 and $a1)
}