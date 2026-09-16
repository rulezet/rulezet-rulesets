rule md5_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f00bbb7747929fafa9d1afd071dba78e"
    $a1="8ed402b3fa6caca988fed664221109cb"
    $a2="6c42fa77b9f40225d7c5fc8cbf546536"
    $a3="e247f7ff59733a80d262995fc00fb3ec"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}