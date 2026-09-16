rule md5_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b3eaf71561d6b92546e8cf29a296873f"
    $a1="52c6aaca28a6b621abae2db20e887dd7"
    $a2="a1117d0ea5902113aacced93179f5b04"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="b3eaf71561d6b92546e8cf29a296873f"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="947f01331ab0db1b086a4fc91e7bda93"
    $a7="257c2d1a0423a6a7c108632a8f963932"
    $a8="21232f297a57a5a743894a0e4a801fc3"
    $a9="21232f297a57a5a743894a0e4a801fc3"
    $a10="b3eaf71561d6b92546e8cf29a296873f"
    $a11="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a12="3f77ca96fb71e9443ba4034fac80fc25"
    $a13="9fd977dad8b0e2231b7a2112faa889df"
    $a14="8b263081d8170d67ef0f9e567508cef5"
    $a15="e3afed0047b08059d0fada10f400c1e5"
    $a16="9b343ab63586ac023b7d8d2a75498e06"
    $a17="c21f969b5f03d33d43e04f8f136e7682"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}