rule md5_hashed_default_creds_unknown
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unknown."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="79f153f88a6cdcf25f5acba2fb0f7c8e"
    $a1="79f153f88a6cdcf25f5acba2fb0f7c8e"
    $a2="4b583376b2767b923c3e1da60d10de59"
    $a3="4b583376b2767b923c3e1da60d10de59"
    $a4="098f6bcd4621d373cade4e832627b4f6"
    $a5="098f6bcd4621d373cade4e832627b4f6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}