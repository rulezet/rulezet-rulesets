rule sha224_hashed_default_creds_openwave
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openwave."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d21a5001b684045b598c50be9122da36b93c99c0998d8b54c81738ec"
    $a1="3a418de52c68aba860a624226c0d7688c0065cce087b26a9a2620ce7"
    $a2="3bd4ec8f039e6eb9a1a288e594c8a3c22b66ce51f8d5a919f2e90c73"
    $a3="31a97dd618f14542b2694706a865537fc1303f3072c8cfd61369cc9f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}