rule nthash_hashed_default_creds_intellitouch
{
    meta:
        id = "1kT0AbrSpx8qMo0a7uEH7C"
        fingerprint = "925aa815ca86795de0312461ae7b5b6f50c36432d8ed34dd12d9a6b8992fbd4e"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for intellitouch."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ce21f17c0aee7fb9ceba532d0546ad6"
    $a1="a4141712f19e9dd5adf16919bb38a95c"
condition:
    ($a0 and $a1)
}