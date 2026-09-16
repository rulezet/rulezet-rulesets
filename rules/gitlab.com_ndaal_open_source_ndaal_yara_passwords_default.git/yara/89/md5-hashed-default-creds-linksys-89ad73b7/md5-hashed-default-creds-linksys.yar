rule md5_hashed_default_creds_linksys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for linksys."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="15c99006972867f49d22cddb3668c921"
    $a1="63a9f0ea7bb98050796b649e85481845"
    $a2="21232f297a57a5a743894a0e4a801fc3"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="81dc9bdb52d04dc20036dbd8313ed055"
    $a5="d8b58f7bfce28eefcc1cdd5b95c3b663"
    $a6="21232f297a57a5a743894a0e4a801fc3"
    $a7="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a8="6925768658dae93ff72aa07cbfd4d64c"
    $a9="ee11cbb19052e40b07aac0ca060c23ee"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}