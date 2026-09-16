rule sha3_384_hashed_default_creds_t_com
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for t_com."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3585407605e2829c3c05bd9eeebbf1937964118376dc2ee7a80f526ad453d2c05be1fbcb94949a04e074392520b4ed63"
    $a1="48d4dcaa1018f1a9985dc15277b4df6148b5528ed6220fee6ab75bc30a7d996e4703532d5d5be61a00c3f8de676512bc"
condition:
    ($a0 and $a1)
}