rule nthash_hashed_default_creds_inova
{
    meta:
        id = "2Zeuj5WM8aZBsr3gfDObaD"
        fingerprint = "cec468c023c80c90909bbcccc674b167fa1fe8b5d15f30680c4434c6a280616c"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for inova."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="131227cb32cbabf1145575fedc7f75f9"
    $a1="b991c53aa9d1a8248de6bc7468361fd0"
condition:
    ($a0 and $a1)
}