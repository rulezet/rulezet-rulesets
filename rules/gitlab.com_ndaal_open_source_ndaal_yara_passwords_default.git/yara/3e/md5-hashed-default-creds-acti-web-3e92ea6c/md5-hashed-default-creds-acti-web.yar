rule md5_hashed_default_creds_acti_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acti_web."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="827ccb0eea8a706c4c34a16891f84e7b"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="827ccb0eea8a706c4c34a16891f84e7b"
    $a3="e3afed0047b08059d0fada10f400c1e5"
    $a4="e10adc3949ba59abbe56e057f20f883e"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="e10adc3949ba59abbe56e057f20f883e"
    $a7="e3afed0047b08059d0fada10f400c1e5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}