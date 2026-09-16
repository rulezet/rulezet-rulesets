rule md5_hashed_default_creds_nice_systems_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nice_systems_ltd."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ea8f45e704491cbbfb206a3ef729b363"
    $a1="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a2="ea8f45e704491cbbfb206a3ef729b363"
    $a3="da006d16b9128ad99906f58087b3af29"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}