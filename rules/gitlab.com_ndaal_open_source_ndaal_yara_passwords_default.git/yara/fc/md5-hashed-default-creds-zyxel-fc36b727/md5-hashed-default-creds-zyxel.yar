rule md5_hashed_default_creds_zyxel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zyxel."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="81dc9bdb52d04dc20036dbd8313ed055"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="81dc9bdb52d04dc20036dbd8313ed055"
    $a3="81dc9bdb52d04dc20036dbd8313ed055"
    $a4="81dc9bdb52d04dc20036dbd8313ed055"
    $a5="add6bb58e139be103324d04d82d8f545"
    $a6="81dc9bdb52d04dc20036dbd8313ed055"
    $a7="63a9f0ea7bb98050796b649e85481845"
    $a8="710da64c4140daa8285202d5588cbcaf"
    $a9="e615e186d3d5f8cad91b7b0cc81b3479"
    $a10="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a11="81dc9bdb52d04dc20036dbd8313ed055"
    $a12="21232f297a57a5a743894a0e4a801fc3"
    $a13="21232f297a57a5a743894a0e4a801fc3"
    $a14="4a7d1ed414474e4033ac29ccb8653d9b"
    $a15="21232f297a57a5a743894a0e4a801fc3"
    $a16="79e89232beb2e344a63294dfa51e4b13"
    $a17="e3afed0047b08059d0fada10f400c1e5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}