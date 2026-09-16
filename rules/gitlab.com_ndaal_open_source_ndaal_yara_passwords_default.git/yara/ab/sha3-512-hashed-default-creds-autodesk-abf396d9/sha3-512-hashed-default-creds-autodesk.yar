rule sha3_512_hashed_default_creds_autodesk
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for autodesk."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4ade0b0ea8c2b24e383116cd15713284b90e31b6099358a148de7a7ad4937b4b6d35584a0fd66e2bdada1f9169b0d2591fa71a4523971f57ab6e4a87831d093c"
    $a1="4ade0b0ea8c2b24e383116cd15713284b90e31b6099358a148de7a7ad4937b4b6d35584a0fd66e2bdada1f9169b0d2591fa71a4523971f57ab6e4a87831d093c"
condition:
    ($a0 and $a1)
}