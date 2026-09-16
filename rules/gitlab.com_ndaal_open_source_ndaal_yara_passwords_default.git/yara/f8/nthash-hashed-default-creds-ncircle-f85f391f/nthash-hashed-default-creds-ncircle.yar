rule nthash_hashed_default_creds_ncircle
{
    meta:
        id = "HXsjnnoiUJWMSN09x8b7q"
        fingerprint = "9b100319cd2d047af0377b84f87bed36345ea68c911f95a4a2ab804910d55715"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ncircle."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="94e6c2c6207802a22ba57cc99e10fe3f"
    $a1="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1)
}