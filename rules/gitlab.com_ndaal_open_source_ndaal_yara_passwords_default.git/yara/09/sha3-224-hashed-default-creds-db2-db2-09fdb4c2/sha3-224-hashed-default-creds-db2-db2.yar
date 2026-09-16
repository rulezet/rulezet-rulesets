rule sha3_224_hashed_default_creds_db2_db2
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for db2_db2."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="08212cf33081e27a009858c2af540145b6a4539ce4b2336fd8e8dc25"
    $a1="e763cf4d4305979a2cedd11a7a1d8e7568bfd1f29496987ae00bdc79"
    $a2="61099482c43bf31c34699e9d57645cb1e50a32ec77e3faa16f0b0b86"
    $a3="61099482c43bf31c34699e9d57645cb1e50a32ec77e3faa16f0b0b86"
    $a4="b508e30c8f3417c52c2f36e45dab5a21c6d9914c67ae2a1281000fa2"
    $a5="b508e30c8f3417c52c2f36e45dab5a21c6d9914c67ae2a1281000fa2"
    $a6="97ee1ec1e0083803a23989529638c71f99a9ed518a092ad391a74dec"
    $a7="97ee1ec1e0083803a23989529638c71f99a9ed518a092ad391a74dec"
    $a8="278f4d29543ae91140af391085f127188d9c1418adc52e5756901fd3"
    $a9="278f4d29543ae91140af391085f127188d9c1418adc52e5756901fd3"
    $a10="f08fe17613bd7fd9968bf0d2de0717b017bad0a3c9c2b92c3feb573b"
    $a11="278f4d29543ae91140af391085f127188d9c1418adc52e5756901fd3"
    $a12="c6d03611c648198aead4cd584b11b6b1f8c8535fc467c7976a198a1c"
    $a13="278f4d29543ae91140af391085f127188d9c1418adc52e5756901fd3"
    $a14="e4d404dee09a360cbf2513803e38892b546e80286cee71bfc4016c0e"
    $a15="278f4d29543ae91140af391085f127188d9c1418adc52e5756901fd3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}