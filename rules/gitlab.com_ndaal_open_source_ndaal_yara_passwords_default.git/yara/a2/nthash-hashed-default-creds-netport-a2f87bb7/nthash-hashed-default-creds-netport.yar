rule nthash_hashed_default_creds_netport
{
    meta:
        id = "55YejyvZyNBxJo7HAXG5XQ"
        fingerprint = "45c61b5921947b2ea810d87a7cea4d5758b7ae345b26487eb9e4f60fd4df28a7"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netport."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e6aebf95ee750d35a58d279ad1fbf32b"
    $a1="e6aebf95ee750d35a58d279ad1fbf32b"
condition:
    ($a0 and $a1)
}