rule nthash_hashed_default_creds_hitron_technologies
{
    meta:
        id = "4VspWEkSdq9FIkF8M1rJKd"
        fingerprint = "1cd25363a1b3466b36570adf8816d75038239c3923f7b46102e6067207c54ebe"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hitron_technologies."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8846f7eaee8fb117ad06bdd830b7586c"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="c1c8397921294b56956360c7dd10f433"
    $a3="6faade66dc67b12ac2448fa79ff57198"
    $a4="8846f7eaee8fb117ad06bdd830b7586c"
    $a5="6c5ec0cf3aa0cfb9b96139eac847b13f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}