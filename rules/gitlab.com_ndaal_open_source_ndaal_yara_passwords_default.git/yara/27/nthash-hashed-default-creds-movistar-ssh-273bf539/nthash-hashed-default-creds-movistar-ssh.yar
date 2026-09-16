rule nthash_hashed_default_creds_movistar_ssh
{
    meta:
        id = "2LCqgv9V8mIZMQHdaPNaUE"
        fingerprint = "c0659d7650833ef8f37783642cdfcbd7b6b43be7fbddf658ee706e6a36bc8c08"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for movistar_ssh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a1="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a2="209c6174da490caeb422f3fa5a7ae634"
    $a3="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}