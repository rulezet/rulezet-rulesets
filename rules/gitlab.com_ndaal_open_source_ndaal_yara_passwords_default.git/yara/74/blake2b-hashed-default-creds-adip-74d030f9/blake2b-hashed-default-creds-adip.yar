rule blake2b_hashed_default_creds_adip
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adip."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="c8f5598d157e1578ec5d081f4743dd12da7dd225019ab9d01f52f3d6e3fc8f8438d8ac52c4d74062a24336f3c0113fb1f93e5b84604936ce0996e613985d840a"
    $a2="2f6c18f7e5a3be1f7db74b1750bdd5421217e3d6cdc639c6f9f233fe61557f2103280d5cf92ddaa200af773bf44e6185725f7081d8cde88fea51869ccfb6ea01"
    $a3="c8f5598d157e1578ec5d081f4743dd12da7dd225019ab9d01f52f3d6e3fc8f8438d8ac52c4d74062a24336f3c0113fb1f93e5b84604936ce0996e613985d840a"
    $a4="7632c06bda5f566f8e921a3c25714fb6d8c7a53da096609aa8db793ccd3bfbcfb24fea36294fae132d2e7cb2ddb9339742c788078309691e0a1dcb48260dd56c"
    $a5="c8f5598d157e1578ec5d081f4743dd12da7dd225019ab9d01f52f3d6e3fc8f8438d8ac52c4d74062a24336f3c0113fb1f93e5b84604936ce0996e613985d840a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}