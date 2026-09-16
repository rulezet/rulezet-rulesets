rule md5_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f4dcc3b5aa765d61d8327deb882cf99"
    $a1="63a9f0ea7bb98050796b649e85481845"
    $a2="b5fc7cf71753113d743849ecbcda43d8"
    $a3="eb61eead90e3b899c6bcbe27ac581660"
    $a4="b142f1a08905b899c1b16b92fc833ff7"
    $a5="0bc4c0e4bf3b3e69f3f09160084a120e"
    $a6="f670c738217ee0cfd4690405cf32c7bb"
    $a7="0bc4c0e4bf3b3e69f3f09160084a120e"
    $a8="808d75d6687c8f4f398a8d35a513076d"
    $a9="21232f297a57a5a743894a0e4a801fc3"
    $a10="099ebea48ea9666a7da2177267983138"
    $a11="1c6e980e0eee73a9a9512439f56665c5"
    $a12="21232f297a57a5a743894a0e4a801fc3"
    $a13="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a14="21232f297a57a5a743894a0e4a801fc3"
    $a15="21232f297a57a5a743894a0e4a801fc3"
    $a16="d0d50fbf63607c93ec29f515ac4e580c"
    $a17="21232f297a57a5a743894a0e4a801fc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}