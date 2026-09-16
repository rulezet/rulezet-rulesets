rule md5_hashed_default_creds_rsa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rsa."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c93ccd78b2076528346216b3b2f701e6"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="7e27f238e794d145f1450749d47ee1eb"
    $a3="200ceb26807d6bf99fd6f4f0d1ca54d4"
    $a4="cdd1c82491d1228637c228f1d79133f7"
    $a5="eb0a191797624dd3a48fa681d3061212"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}