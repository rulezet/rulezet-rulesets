rule mysql323_hashed_default_creds_allied_telesyn
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for allied_telesyn."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5336eb751494bdb1"
    $a1="5336eb751494bdb1"
    $a2="43e9a4ab75570f5b"
    $a3="5336eb751494bdb1"
    $a4="7923eae65177ac3c"
    $a5="2ac90b9577c33931"
    $a6="7923eae65177ac3c"
    $a7="5336eb751494bdb1"
    $a8="411305f40cbc0383"
    $a9="411305f40cbc0383"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}