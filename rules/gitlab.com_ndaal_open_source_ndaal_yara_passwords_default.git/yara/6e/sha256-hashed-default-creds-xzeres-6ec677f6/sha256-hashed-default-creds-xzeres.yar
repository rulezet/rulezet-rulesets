rule sha256_hashed_default_creds_xzeres
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xzeres."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7cd7daa72e252b87c857cdc16b32a5f8a50472011c3f189519ba849a1c401432"
    $a1="3d88eee185288c2628121c261f7cc8c4974511d3e11fdc282d99765bdd4abad9"
condition:
    ($a0 and $a1)
}