rule sha224_hashed_default_creds_toplayer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for toplayer."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb97fd1a7c0a206965223185cf1a1affdd01ff52279a98457dac8693"
    $a1="19e44e0486c72a88c0bc2053dd530e4d82913b6aa1da9e10ef6340a4"
condition:
    ($a0 and $a1)
}