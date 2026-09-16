rule md5_hashed_default_creds_red_hat_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for red_hat_inc."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="f11903d870bd5136fdf72d2265ef7952"
    $a3="f11903d870bd5136fdf72d2265ef7952"
    $a4="7694f4a66316e53c8cdd9d9954bd611d"
    $a5="f11903d870bd5136fdf72d2265ef7952"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}