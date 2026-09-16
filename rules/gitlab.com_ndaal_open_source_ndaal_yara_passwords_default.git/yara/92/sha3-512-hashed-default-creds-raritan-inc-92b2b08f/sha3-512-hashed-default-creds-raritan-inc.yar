rule sha3_512_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="61098a6dbe7a295c9189dbf9c9f7ecdedd6e956ddef82665be76ed0667d0fd1515c0e6b6c9e58977529620971a9f85dce5bc35daa815e776a6014e534ab01425"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="61098a6dbe7a295c9189dbf9c9f7ecdedd6e956ddef82665be76ed0667d0fd1515c0e6b6c9e58977529620971a9f85dce5bc35daa815e776a6014e534ab01425"
    $a3="3a2079e49f06fc48a28bb1f133c15d34f9e8e38138ebfe24173a70ffb2617b0649b4f77ae6ef5c2ea8c0f89e5d6a5f92a9b285608bb49efc1e7571db5e46e45e"
    $a4="649c3606bd57ca8ff7cdeabf3a0c6377fa08ff31cc5eef953602f76f4f63a5a145f5996ee3f197746e2d26e3729047a9104f35a0973f3c15ebb4a7703882c109"
    $a5="d82f2a6fe4ed94b3654417f8b07149e0602f1a7ee82c15d9ce0e90c73409b2c42de74783a6c66b4ddcb9ac4ac47ee218e9d151c24dd383fc056003389c9bcc91"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}