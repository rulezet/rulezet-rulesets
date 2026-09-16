rule nthash_hashed_default_creds_alien_technology
{
    meta:
        id = "1x4flSB8mNOTbvYkbDkYQL"
        fingerprint = "d0a5a1a4174f5973779eeb54bda37b3f953e26ca5505623b644096cd5f26f703"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for alien_technology."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4d35384faded595fbbc632a056a62e05"
    $a1="4d35384faded595fbbc632a056a62e05"
    $a2="4d35384faded595fbbc632a056a62e05"
    $a3="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}