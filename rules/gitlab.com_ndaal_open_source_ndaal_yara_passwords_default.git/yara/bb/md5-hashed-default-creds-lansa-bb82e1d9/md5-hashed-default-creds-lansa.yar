rule md5_hashed_default_creds_lansa
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lansa."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="e77989ed21758e78331b20e477fc5582"
    $a3="e77989ed21758e78331b20e477fc5582"
    $a4="5f4dcc3b5aa765d61d8327deb882cf99"
    $a5="f3d2c5c3f699dd46a4de2a6a5d2fe088"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}