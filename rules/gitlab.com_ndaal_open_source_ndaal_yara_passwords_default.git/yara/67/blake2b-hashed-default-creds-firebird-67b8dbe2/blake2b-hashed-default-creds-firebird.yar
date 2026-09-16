rule blake2b_hashed_default_creds_firebird
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for firebird."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="95634d08635b26a78df2c5dc103556cc1a15ca5858c8bda7e04b16f9e68a8644eff5d2508be346a0c3ce742f064aa9abcc65e60302b589ecf88178ebcf9bd9ab"
    $a1="21121986da4c2c50df04d001ee5caab03158348b7874d5ab1743b423996756598585b35c5f127a8f6d7cd9414ee5a72d91d09bb0926ed81a82de548dd3e424a9"
condition:
    ($a0 and $a1)
}