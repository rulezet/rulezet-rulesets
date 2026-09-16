rule sha3_256_hashed_default_creds_redhat
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for redhat."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="af16935d9e0aee09f0f8aaacb78b1edddf83a35a91af6b9655935983c3878bb8"
    $a1="af16935d9e0aee09f0f8aaacb78b1edddf83a35a91af6b9655935983c3878bb8"
    $a2="8a5e1d339fafc39350fd8cf1d7ca7982091c27f6b77f75bd4ddab3df425b4f8c"
    $a3="af16935d9e0aee09f0f8aaacb78b1edddf83a35a91af6b9655935983c3878bb8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}