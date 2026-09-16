rule md5_hashed_default_creds_motorola
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for motorola."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f3395cd54cf857ddf8f2056768ff49ae"
    $a1="8fb04719a494ab06d32d66deab3c0a56"
    $a2="750379b5926e9f728aa6c253d37e3792"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="5f4dcc3b5aa765d61d8327deb882cf99"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="3ddaeb82fbba964fb3461d4e4f1342eb"
    $a7="aaabf0d39951f3e6c3e8a7911df524c2"
    $a8="99cc2f5f84d520057c50a0eb4da15beb"
    $a9="eb919176ebac2099dd026ec41524b707"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}