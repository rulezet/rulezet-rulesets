rule md5_hashed_default_creds_d_link
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for d_link."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="81dc9bdb52d04dc20036dbd8313ed055"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="5f4dcc3b5aa765d61d8327deb882cf99"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="b3d97784cd08a6031de824786b186667"
    $a7="21232f297a57a5a743894a0e4a801fc3"
    $a8="2a2786774a5720ffe083c34dc85a4803"
    $a9="fd96a7703f670abb3f424980cfd0b53a"
    $a10="4c9184f37cff01bcdc32dc486ec36961"
    $a11="21232f297a57a5a743894a0e4a801fc3"
    $a12="6034373627436e5c9df0ae1229172d4b"
    $a13="6034373627436e5c9df0ae1229172d4b"
    $a14="0eabcec1c08e988a3327bdc3995af6ad"
    $a15="21232f297a57a5a743894a0e4a801fc3"
    $a16="a01e9a7609e4f717e131caea698976e0"
    $a17="21232f297a57a5a743894a0e4a801fc3"
    $a18="21232f297a57a5a743894a0e4a801fc3"
    $a19="a95e5b907382390a35a27fff925f15a4"
    $a20="21232f297a57a5a743894a0e4a801fc3"
    $a21="63a9f0ea7bb98050796b649e85481845"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21)
}