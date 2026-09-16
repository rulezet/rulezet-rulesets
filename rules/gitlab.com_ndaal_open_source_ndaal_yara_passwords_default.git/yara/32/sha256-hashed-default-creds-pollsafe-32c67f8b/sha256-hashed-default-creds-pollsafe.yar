rule sha256_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8f0ad38086075b37a535d141659ca0d0c98cee5987db82a325d3772e4dee2ee1"
    $a1="20bd5a6217e1d0b1a819794f3ff85c5f5d7380b6c6e734799e1be5d42b6b7cac"
condition:
    ($a0 and $a1)
}