rule blake2b_hashed_default_creds_janitza
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for janitza."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="515e81585b8440e6055ad7e37ae7b38621dcb0b50520feb6080b4351a7245ad936fe03554f194655420230d048d09fec173345148b7397d2d19f8135bdf9de27"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="515e81585b8440e6055ad7e37ae7b38621dcb0b50520feb6080b4351a7245ad936fe03554f194655420230d048d09fec173345148b7397d2d19f8135bdf9de27"
    $a3="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a4="b1c5f49c045e587ef1a068b2f944c3ca0c388f46511680f1bd6bd5ad5fe2a9ab1610e58894c6f3cc2ea46a5462514349396340c61e278c79ac72d6e9f56c1661"
    $a5="83acae50ee3c1005a9bf2201fb04346756185e2281a56bf4a73a5cf1d151fd785cb932f9bf5b30229548cbf98c40549b4b993ce1403da69ebedff5e07e2308bd"
    $a6="515e81585b8440e6055ad7e37ae7b38621dcb0b50520feb6080b4351a7245ad936fe03554f194655420230d048d09fec173345148b7397d2d19f8135bdf9de27"
    $a7="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}