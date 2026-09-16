rule md5_hashed_default_creds_everfocus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for everfocus."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="4b583376b2767b923c3e1da60d10de59"
    $a3="4b583376b2767b923c3e1da60d10de59"
    $a4="09348c20a019be0318387c08df7a783d"
    $a5="09348c20a019be0318387c08df7a783d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}