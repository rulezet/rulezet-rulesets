rule nthash_hashed_default_creds_accelerated
{
    meta:
        id = "jPIJd7fXYmyOef33OE8ld"
        fingerprint = "bc6b988c273d233ca1e7be9bb7583c6c630ad8add66d04cb9ec6561faf613f94"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for accelerated."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="655177bbe1b65e07ecefa3e84363d605"
    $a1="94aa68f72ab39cfec7ffcb58dca3358c"
condition:
    ($a0 and $a1)
}