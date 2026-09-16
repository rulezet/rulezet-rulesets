rule mysql41_hashed_default_creds_powerchute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*F0E9B6F452739D92FDAB32EBE6768FCBAA44DC45"
    $a1="*F0E9B6F452739D92FDAB32EBE6768FCBAA44DC45"
condition:
    ($a0 and $a1)
}