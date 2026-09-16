rule nthash_hashed_default_creds_otrs_inc
{
    meta:
        id = "5OD2pluYFqhl2edc6eM0kC"
        fingerprint = "8e6a0b53bd8730b5b456ba8c235b50f5889c4637418e90d6c35491e981c9c613"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for otrs_inc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="329153f560eb329c0e1deea55e88a1e9"
    $a1="c1b85a47673fadaa2ef0e4109c5d0faa"
condition:
    ($a0 and $a1)
}