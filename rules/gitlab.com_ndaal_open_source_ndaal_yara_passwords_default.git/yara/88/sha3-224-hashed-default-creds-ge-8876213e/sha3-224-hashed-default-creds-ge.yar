rule sha3_224_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8ef5d89bbb08949f8f27ec72cdf1ea2bfbf1802d0692eb6364c4f2fe"
    $a1="ad5963666585f7f94bfc5531ca8e0cdc0f3f658e81891e7a018870c8"
condition:
    ($a0 and $a1)
}