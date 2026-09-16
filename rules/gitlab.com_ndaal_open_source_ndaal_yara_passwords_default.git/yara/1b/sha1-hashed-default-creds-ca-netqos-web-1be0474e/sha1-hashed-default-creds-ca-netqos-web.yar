rule sha1_hashed_default_creds_ca_netqos_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_netqos_web."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d122031b45f83cd889411f3fa8c802028947947a"
    $a1="a0c03f2fb811382d9406ea3fe5a61da90476088f"
    $a2="d122031b45f83cd889411f3fa8c802028947947a"
    $a3="fcb8c0b1b38715e1b9c7758b0f93976aaff65c5d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}