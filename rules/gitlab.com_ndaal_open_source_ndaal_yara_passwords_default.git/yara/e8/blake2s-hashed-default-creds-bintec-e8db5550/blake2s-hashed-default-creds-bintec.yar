rule blake2s_hashed_default_creds_bintec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bintec."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="45c063a26a91b200f726efdf577837cc040ebd4d660d77900b77cb292454c6fd"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="714239f10c6ac8224044d36c0f0dab36fed60c6cd6aa5935c125d1f5af0e827e"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="f1ccc580d8ddebe1404dfd59b57a710a542cdde71ee235d4b019338dd98e570d"
    $a5="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}