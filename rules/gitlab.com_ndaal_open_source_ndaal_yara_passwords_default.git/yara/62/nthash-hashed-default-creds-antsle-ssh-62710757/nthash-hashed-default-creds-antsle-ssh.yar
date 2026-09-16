rule nthash_hashed_default_creds_antsle_ssh
{
    meta:
        id = "1o9cFwuD4ej1HZuRCy6Tvi"
        fingerprint = "be7ced926e745b4961caadb4f17127e9ff69d1422ed55e7a55db8e3357635071"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for antsle_ssh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cfdfe8a97acd1b7d95aecea6eb19e7a6"
    $a1="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1)
}