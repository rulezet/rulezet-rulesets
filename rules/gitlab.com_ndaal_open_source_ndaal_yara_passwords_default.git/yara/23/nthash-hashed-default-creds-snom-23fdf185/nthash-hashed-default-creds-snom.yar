rule nthash_hashed_default_creds_snom
{
    meta:
        id = "2YAPMjXVfMAxckil1iaB8m"
        fingerprint = "be7663c322635e46e58a04ebe6a315e1da14a2f4758cff9b078b6b93697f395b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for snom."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ea7c23f2efca850e3fb547ca12567c33"
    $a1="d144986c6122b1b1654ba39932465528"
condition:
    ($a0 and $a1)
}