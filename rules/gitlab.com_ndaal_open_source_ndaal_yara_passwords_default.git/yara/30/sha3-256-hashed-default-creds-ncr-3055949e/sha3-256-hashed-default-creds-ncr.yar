rule sha3_256_hashed_default_creds_ncr
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncr."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="09d583c51f7781a4c0d5b3dae75c82684f799f3c81871aa274aaf9019f963844"
    $a1="09d583c51f7781a4c0d5b3dae75c82684f799f3c81871aa274aaf9019f963844"
condition:
    ($a0 and $a1)
}