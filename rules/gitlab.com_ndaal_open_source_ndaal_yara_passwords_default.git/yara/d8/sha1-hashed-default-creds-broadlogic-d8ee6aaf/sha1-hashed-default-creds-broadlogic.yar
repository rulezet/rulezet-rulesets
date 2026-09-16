rule sha1_hashed_default_creds_broadlogic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for broadlogic."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="30e0c5f0ec5359f21e34af3691470c1b91865295"
    $a1="30e0c5f0ec5359f21e34af3691470c1b91865295"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="2fc42d37fee2c81d767e09fb298b70c748940f86"
    $a5="2fc42d37fee2c81d767e09fb298b70c748940f86"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}