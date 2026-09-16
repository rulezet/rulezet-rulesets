rule blake2s_hashed_default_creds_360_systems
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for 360_systems."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e5509bb5cc9c58b36ac26478cdb1bd131ecffaad0e05aa871518f6d249161d90"
    $a1="e5509bb5cc9c58b36ac26478cdb1bd131ecffaad0e05aa871518f6d249161d90"
condition:
    ($a0 and $a1)
}