rule mysql323_hashed_default_creds_huawei
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43e9a4ab75570f5b"
    $a1="43e9a4ab75570f5b"
    $a2="0d4eee4271ec016d"
    $a3="43e9a4ab75570f5b"
    $a4="2b9b085368cb6279"
    $a5="43e9a4ab75570f5b"
    $a6="43e9a4ab75570f5b"
    $a7="43e9a4ab75570f5b"
    $a8="2b7cbeff40c935d0"
    $a9="43e9a4ab75570f5b"
    $a10="6ba6d4922026041c"
    $a11="43e9a4ab75570f5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}