rule sha3_512_hashed_default_creds_ibm_was_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_was_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8dd2120641ef9de1ceee1a6d1a6684225d2424f10c51a3ace90a0fcdd395c7308497ec37fd422d8e653abad8660e8f0f6fb044ff6babf96fd2e91365fb9f39d7"
    $a1="8dd2120641ef9de1ceee1a6d1a6684225d2424f10c51a3ace90a0fcdd395c7308497ec37fd422d8e653abad8660e8f0f6fb044ff6babf96fd2e91365fb9f39d7"
condition:
    ($a0 and $a1)
}