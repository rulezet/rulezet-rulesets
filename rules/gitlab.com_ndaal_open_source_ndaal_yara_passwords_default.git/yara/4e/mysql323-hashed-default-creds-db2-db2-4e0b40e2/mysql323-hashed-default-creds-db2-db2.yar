rule mysql323_hashed_default_creds_db2_db2
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for db2_db2."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="739ce4c8509ce556"
    $a1="4a8c7fa84123f1b6"
    $a2="07b8ccb920b44c8b"
    $a3="07b8ccb920b44c8b"
    $a4="4d1d4213573466fe"
    $a5="4d1d4213573466fe"
    $a6="181655df42bba4a6"
    $a7="181655df42bba4a6"
    $a8="671d8175396232a5"
    $a9="671d8175396232a5"
    $a10="51f0d6fd3b37828d"
    $a11="671d8175396232a5"
    $a12="610b3e1144881d76"
    $a13="671d8175396232a5"
    $a14="59a965115d6fbb2e"
    $a15="671d8175396232a5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}