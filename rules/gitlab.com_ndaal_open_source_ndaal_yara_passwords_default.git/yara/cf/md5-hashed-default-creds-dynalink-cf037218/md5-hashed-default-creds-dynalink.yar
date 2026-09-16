rule md5_hashed_default_creds_dynalink
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dynalink."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="2c17c6393771ee3048ae34d6b380c5ec"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="a9980d0515266cf3d7c2ac48762c8457"
    $a5="98946f32af70032a70d06094f23b170d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}