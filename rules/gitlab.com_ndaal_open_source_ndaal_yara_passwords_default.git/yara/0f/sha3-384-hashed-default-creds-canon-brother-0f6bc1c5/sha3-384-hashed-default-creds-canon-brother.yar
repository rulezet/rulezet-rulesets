rule sha3_384_hashed_default_creds_canon_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fdcb5d0c3a29b9fa052bd1ee6e24a2f5d22871f87f8e655c6adb30e17d7a37601343c7a6abb41a7c126c64f81d7eaf35"
    $a1="fdcb5d0c3a29b9fa052bd1ee6e24a2f5d22871f87f8e655c6adb30e17d7a37601343c7a6abb41a7c126c64f81d7eaf35"
condition:
    ($a0 and $a1)
}