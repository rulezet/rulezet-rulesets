rule nthash_hashed_default_creds_ubiquiti_ssh
{
    meta:
        id = "7muVigpzfR3zHKLfMxnZ7t"
        fingerprint = "f49b6e2e8d110a5b87556c0da4c3b4cdb4f893f40d890bfcf593228ca46d7734"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ubiquiti_ssh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="db17d3fa744d127d0d5702eb1d913bb5"
    $a3="329153f560eb329c0e1deea55e88a1e9"
    $a4="db17d3fa744d127d0d5702eb1d913bb5"
    $a5="db17d3fa744d127d0d5702eb1d913bb5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}