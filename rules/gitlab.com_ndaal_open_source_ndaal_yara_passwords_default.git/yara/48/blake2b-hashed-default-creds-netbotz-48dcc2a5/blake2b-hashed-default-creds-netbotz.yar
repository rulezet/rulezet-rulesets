rule blake2b_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="461bc42bd3e2d8bdd1a6df215eb8ea1dd9d1f0077615bba69c5cae5d449ad066db0d1b88c3e5d343eb01625ac324c7cafa724e2c0ee6072cd2c917a76a3ed959"
    $a1="461bc42bd3e2d8bdd1a6df215eb8ea1dd9d1f0077615bba69c5cae5d449ad066db0d1b88c3e5d343eb01625ac324c7cafa724e2c0ee6072cd2c917a76a3ed959"
condition:
    ($a0 and $a1)
}