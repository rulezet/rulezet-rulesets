rule sha3_256_hashed_default_creds_data_general
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for data_general."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d238602e3435b266dbc0153b200e85e208a20a0bae71010a6324eb0497804eae"
    $a1="d238602e3435b266dbc0153b200e85e208a20a0bae71010a6324eb0497804eae"
    $a2="47cc398a83c553ffd38e80272ef38d2f8b72fffed1194327a4e41c9a7b2c16e9"
    $a3="47cc398a83c553ffd38e80272ef38d2f8b72fffed1194327a4e41c9a7b2c16e9"
    $a4="d238602e3435b266dbc0153b200e85e208a20a0bae71010a6324eb0497804eae"
    $a5="47cc398a83c553ffd38e80272ef38d2f8b72fffed1194327a4e41c9a7b2c16e9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}