rule sha256_hashed_default_creds_garrettcom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for garrettcom."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6ee4a469cd4e91053847f5d3fcb61dbcc91e8f0ef10be7748da4c4a1ba382d17"
    $a1="6ee4a469cd4e91053847f5d3fcb61dbcc91e8f0ef10be7748da4c4a1ba382d17"
condition:
    ($a0 and $a1)
}