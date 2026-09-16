rule blake2s_hashed_default_creds_sybase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f645ae114819272a88025c3b85c285eecd80d45302d8125fd1e27a7c90f84fd7"
    $a1="97da8c4c23c3c98b0495850e1a2d831648deccfadcb9897cf0a7d9da1bee7004"
    $a2="296a10c1711fe7f1786f3fae5fe592a6f6d2eadbed291c7d26e516f2e6b70532"
    $a3="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}