rule nthash_hashed_default_creds_netgenesis
{
    meta:
        id = "4ZTQV4wVLgkhEYy86gSjB8"
        fingerprint = "d3f0c59a1a43a770cc578a7916d8f018f95e4da282c3ebb3a1d1f4ae4392911f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netgenesis."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a4eaa8026240f72609008e8b5e1fe1d8"
    $a1="a4eaa8026240f72609008e8b5e1fe1d8"
condition:
    ($a0 and $a1)
}