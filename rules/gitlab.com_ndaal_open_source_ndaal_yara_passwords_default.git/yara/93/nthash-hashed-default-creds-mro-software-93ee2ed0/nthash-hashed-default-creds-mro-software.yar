rule nthash_hashed_default_creds_mro_software
{
    meta:
        id = "H2qLSnadtwQ7MWMQRW0fe"
        fingerprint = "46972b180ad068936b0b1aeefd82283a08a798dd3e2bb213d7e7f7d9ed10272d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mro_software."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="94aa68f72ab39cfec7ffcb58dca3358c"
    $a1="0a269520f8ad21768813edb0d05ad7f1"
condition:
    ($a0 and $a1)
}