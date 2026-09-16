rule nthash_hashed_default_creds_cassandra
{
    meta:
        id = "ZaYWkL74sFuYt3hnXIVEC"
        fingerprint = "09870cb7bf9cdf2d43375161eb00f8a168f142588f63e1ff3068de8e4ee095e3"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cassandra."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e26f35f4ff58a7604fe2e559dd93770d"
    $a1="e26f35f4ff58a7604fe2e559dd93770d"
condition:
    ($a0 and $a1)
}