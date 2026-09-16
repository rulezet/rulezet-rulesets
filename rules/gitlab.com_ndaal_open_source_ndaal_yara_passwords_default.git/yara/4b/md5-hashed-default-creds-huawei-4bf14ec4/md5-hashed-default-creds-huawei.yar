rule md5_hashed_default_creds_huawei
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="352123f707d76f96c761d132f1dc44f0"
    $a2="9e02ab0751b2d310062bc25016bdc1cf"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="7f447cd6560ebd9c5df28e745dd36db2"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="21232f297a57a5a743894a0e4a801fc3"
    $a7="21232f297a57a5a743894a0e4a801fc3"
    $a8="663505a27f7a862be0ceaeb0583fe8b7"
    $a9="21232f297a57a5a743894a0e4a801fc3"
    $a10="e656d4813e5a4a7cf7cc63cf93e804e9"
    $a11="21232f297a57a5a743894a0e4a801fc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}