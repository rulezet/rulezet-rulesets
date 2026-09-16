rule md5_hashed_default_creds_toshiba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toshiba."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e10adc3949ba59abbe56e057f20f883e"
    $a1="e3afed0047b08059d0fada10f400c1e5"
    $a2="e10adc3949ba59abbe56e057f20f883e"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="ea5621eae3562b1e958727cb73a96f3b"
    $a5="63a9f0ea7bb98050796b649e85481845"
    $a6="82a3f212c95c1516907f27e1220c6f13"
    $a7="1b3231655cebb7a1f783eddf27d254ca"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}