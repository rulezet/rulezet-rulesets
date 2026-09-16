rule md5_hashed_default_creds_utstarcom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for utstarcom."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="10c0a96806ba3909e06aee543721d424"
    $a1="10c0a96806ba3909e06aee543721d424"
    $a2="4b493c01a534432d820bf225e3f6c29d"
    $a3="77e69c137812518e359196bb2f5e9bb9"
    $a4="06e3d36fa30cea095545139854ad1fb9"
    $a5="06e3d36fa30cea095545139854ad1fb9"
    $a6="96f9963e25520a9011c82401920794f0"
    $a7="96f9963e25520a9011c82401920794f0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}