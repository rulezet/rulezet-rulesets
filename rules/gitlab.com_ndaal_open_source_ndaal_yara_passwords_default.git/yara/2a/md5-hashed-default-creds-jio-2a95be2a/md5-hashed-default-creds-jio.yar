rule md5_hashed_default_creds_jio
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jio."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b5ddb6ac69b07d3473ca6e99c7ff8e95"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="200ceb26807d6bf99fd6f4f0d1ca54d4"
    $a3="200ceb26807d6bf99fd6f4f0d1ca54d4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}