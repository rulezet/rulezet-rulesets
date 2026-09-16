rule blake2s_hashed_default_creds_arun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for arun."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8d1b22cd2c5ae063dc4c2bb433689fc3499c3fb751913991ea605d87da346f8c"
    $a1="e906644ad861b58d47500e6c636ee3bf4cb4bb00016bb352b1d2d03d122c1605"
condition:
    ($a0 and $a1)
}