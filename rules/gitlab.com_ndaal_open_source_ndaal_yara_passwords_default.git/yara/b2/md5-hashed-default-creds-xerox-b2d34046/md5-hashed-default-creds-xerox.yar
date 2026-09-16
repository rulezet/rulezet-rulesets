rule md5_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8b32e336e963681392fb0ffef072829a"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="3d2172418ce305c7d16d4b05597c6a59"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="21232f297a57a5a743894a0e4a801fc3"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="934b535800b1cba8f96a5d72f72f1611"
    $a7="21232f297a57a5a743894a0e4a801fc3"
    $a8="8b32e336e963681392fb0ffef072829a"
    $a9="b0baee9d279d34fa1dfd71aadb908c3f"
    $a10="b59c67bf196a4758191e42f76670ceba"
    $a11="21232f297a57a5a743894a0e4a801fc3"
    $a12="5f527beb9badf1e4fb844b4021f6ca1e"
    $a13="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a14="8d2a959e6b154ec9215882b82f28cfcb"
    $a15="54af60422aadb2c3de1d87ecde30700e"
    $a16="dcaa9fd4f23aaf0c29f540becf35b46f"
    $a17="0303ca0d2ed059ada202ebfb296bd0fd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}