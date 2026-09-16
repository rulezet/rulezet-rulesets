rule blake2s_hashed_default_creds_acti_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a076a699190673026fe44f7b523d321fcae79e70945007bdb1c86295a11c4135"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="a076a699190673026fe44f7b523d321fcae79e70945007bdb1c86295a11c4135"
    $a3="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
    $a4="ba2649757ec72ed0b9bd8b3063687767946145f13abcb38e2718fdaad6c771e0"
    $a5="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a6="ba2649757ec72ed0b9bd8b3063687767946145f13abcb38e2718fdaad6c771e0"
    $a7="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}