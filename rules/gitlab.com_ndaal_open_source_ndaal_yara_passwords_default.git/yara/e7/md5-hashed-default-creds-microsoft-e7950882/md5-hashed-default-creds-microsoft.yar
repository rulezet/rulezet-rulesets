rule md5_hashed_default_creds_microsoft
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for microsoft."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ee11cbb19052e40b07aac0ca060c23ee"
    $a1="35e1ceaca6f425dc87a2125f559f4d6d"
    $a2="21232f297a57a5a743894a0e4a801fc3"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="8f9bfe9d1345237cb3b2b205864da075"
    $a5="8f9bfe9d1345237cb3b2b205864da075"
    $a6="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a7="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a8="adb831a7fdd83dd1e2a309ce7591dff8"
    $a9="adb831a7fdd83dd1e2a309ce7591dff8"
    $a10="34e0191c2017290f555a5d9df88e678c"
    $a11="34e0191c2017290f555a5d9df88e678c"
    $a12="c802b2915a2b522195f0af53803f2b1b"
    $a13="95d702b3326babf519dcff7cb920af47"
    $a14="3dc26fe31c029961d36811193e69c919"
    $a15="3dc26fe31c029961d36811193e69c919"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}