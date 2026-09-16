rule md5_hashed_default_creds_conexant
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for conexant."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a2="f26dfe6efab2afc84ad45bc4585202da"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="6b001a7f02f2581ff3541cede5745065"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="697efa94ad1e665c4d0edd4c810db6fb"
    $a7="21232f297a57a5a743894a0e4a801fc3"
    $a8="5f4dcc3b5aa765d61d8327deb882cf99"
    $a9="21232f297a57a5a743894a0e4a801fc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}