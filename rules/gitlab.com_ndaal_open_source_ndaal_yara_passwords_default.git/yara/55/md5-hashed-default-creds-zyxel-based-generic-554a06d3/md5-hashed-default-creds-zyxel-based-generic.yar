rule md5_hashed_default_creds_zyxel_based_generic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel_based_generic."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cfcd208495d565ef66e7dff9f98764da"
    $a1="21232f297a57a5a743894a0e4a801fc3"
condition:
    ($a0 and $a1)
}