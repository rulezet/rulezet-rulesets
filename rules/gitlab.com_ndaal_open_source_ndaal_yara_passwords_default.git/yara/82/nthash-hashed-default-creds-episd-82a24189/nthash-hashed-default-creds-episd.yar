rule nthash_hashed_default_creds_episd
{
    meta:
        id = "6Ez2aLPQkGwDPg454y60FX"
        fingerprint = "993759fd70e9c9ccf25052218b6695f8d2537a3b2c55f131b831539da68fe7d2"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for episd."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5410adee1789c54a601f249e359297c2"
    $a1="2b2ac2d1c7c8fda6cea80b5fad7563aa"
condition:
    ($a0 and $a1)
}