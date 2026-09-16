rule nthash_hashed_default_creds_offensive_security
{
    meta:
        id = "4Kzm7kIFjbO043NPPtD3Bs"
        fingerprint = "9693ec521cc12455f8ae218545d268d3d474bcb4fd660d0fb6f6fc23e7fbbf0b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for offensive_security."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="afc44ee7351d61d00698796da06b1ebf"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="fc9417a516bcedc3a39a05a108eda4f6"
    $a3="fc9417a516bcedc3a39a05a108eda4f6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}