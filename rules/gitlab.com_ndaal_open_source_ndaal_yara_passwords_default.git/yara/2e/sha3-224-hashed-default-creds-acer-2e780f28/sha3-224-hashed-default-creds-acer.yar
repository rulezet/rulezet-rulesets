rule sha3_224_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eee9ea7585172d022712be451b8554c75dbfda3e2dad7c6ead64ccb7"
    $a1="eee9ea7585172d022712be451b8554c75dbfda3e2dad7c6ead64ccb7"
condition:
    ($a0 and $a1)
}