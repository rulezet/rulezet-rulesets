rule sha3_256_hashed_default_creds_emachines
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emachines."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="af150451dad13e62e51a5013f1251b0036cab8c2be852ef6d1ad3a9dbd880a13"
    $a1="9aabf55861738adec39ad8c97b79b5a5f4f702242e4eb5d8f14c2842d5a6ca77"
condition:
    ($a0 and $a1)
}