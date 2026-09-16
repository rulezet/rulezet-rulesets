rule blake2b_hashed_default_creds_applied_innovations
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for applied_innovations."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7cc5f24d15ba4a33efa4bdf7f2ec730a2810d77dcff37fc85f96ad8f774a6f4be551b6463d15acf295f2d808e87667a60c8a9c2dbcea6a3bae06d02b609e92ee"
    $a1="7cc5f24d15ba4a33efa4bdf7f2ec730a2810d77dcff37fc85f96ad8f774a6f4be551b6463d15acf295f2d808e87667a60c8a9c2dbcea6a3bae06d02b609e92ee"
condition:
    ($a0 and $a1)
}