rule nthash_hashed_default_creds_radio_shack
{
    meta:
        id = "2nqLYb6qAWvDsiJklO8UXj"
        fingerprint = "63fefa4f450b70eb512e6de244c35bb87eebb58a714ab4b8b2f8b64f29dfec59"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radio_shack."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="439482dc37b90b83bd7c1c33d5eb5bbf"
    $a1="85209dc141c8e381e708acd9fee861ac"
condition:
    ($a0 and $a1)
}