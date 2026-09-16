rule md5_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1e484417af914a45f47ab8e9c929f29a"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="0937f5e3acc79ea0b744477f87be7eab"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="c63c8e81ee04bc68e22b895d04ac3912"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="8023a34e58c3afc66ba7d4dfe33b1931"
    $a7="21232f297a57a5a743894a0e4a801fc3"
    $a8="1096b613a98fc4282b1d97ff092f7807"
    $a9="21232f297a57a5a743894a0e4a801fc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}