rule md5_hashed_default_creds_conceptronic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for conceptronic."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="81dc9bdb52d04dc20036dbd8313ed055"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="5f4dcc3b5aa765d61d8327deb882cf99"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="5f4dcc3b5aa765d61d8327deb882cf99"
    $a5="294de3557d9d00b3d2d8a1e6aab028cf"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}