rule sha256_hashed_default_creds_nai
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nai."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fde8ea7c0c0712008c2962b0d019b9df2457c09ebfc83254e71d908e6f42da18"
    $a1="fde8ea7c0c0712008c2962b0d019b9df2457c09ebfc83254e71d908e6f42da18"
    $a2="240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}