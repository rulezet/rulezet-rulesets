rule sha3_512_hashed_default_creds_intermec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intermec."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="04dd4d7bc62495261f16c4aa2f5315a2b684e7d232a02fa4376c79fd2102c5f102c44008a784bd538d9cfc2be18a0224a118a74b71e10f4f784c8029ccfaad12"
    $a1="04dd4d7bc62495261f16c4aa2f5315a2b684e7d232a02fa4376c79fd2102c5f102c44008a784bd538d9cfc2be18a0224a118a74b71e10f4f784c8029ccfaad12"
condition:
    ($a0 and $a1)
}