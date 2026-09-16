rule md5_hashed_default_creds_bintec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bintec."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ba7378764c1eb4f960f228b99df48ef1"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="bf4302b914c2b60ad4586d574cd6dcb9"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="bafd7322c6e97d25b6299b5d6fe8920b"
    $a5="e3afed0047b08059d0fada10f400c1e5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}