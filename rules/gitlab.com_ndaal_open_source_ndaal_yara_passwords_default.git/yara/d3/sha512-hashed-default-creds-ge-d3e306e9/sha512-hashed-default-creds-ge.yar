rule sha512_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5ef0e70b6323d222ecb08a092967dbea8c15080ae7df565459f23eb80863581b821ce9e084b3de6fe4ed0cc5300c69e26fc3171b9da9c388e024fc5ce2762fd2"
    $a1="b63c0df879111f6ab1a8432ffa84e1adf0da3a995483fbed364d9b5395c05097cf5f1deae4426478fa7fcd124609c7ca59ed37ca75f9b99af990aa04d332e1aa"
condition:
    ($a0 and $a1)
}