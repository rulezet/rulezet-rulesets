rule md5_hashed_default_creds_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for brother."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9df3b01c60df20d13843841ff0d4482c"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="9df3b01c60df20d13843841ff0d4482c"
    $a3="ee11cbb19052e40b07aac0ca060c23ee"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}