rule mysql323_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7dc3ee2d6b0f3b5a"
    $a1="7dc3ee2d6b0f3b5a"
    $a2="0a1838273cbc9961"
    $a3="43e9a4ab75570f5b"
    $a4="14e43c2d31dcbdd1"
    $a5="533bd8590690a0f1"
    $a6="2e12a3be3ee1107c"
    $a7="2e12a3be3ee1107c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}