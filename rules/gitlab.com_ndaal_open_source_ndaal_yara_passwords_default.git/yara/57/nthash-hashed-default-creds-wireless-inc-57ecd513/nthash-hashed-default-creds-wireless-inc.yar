rule nthash_hashed_default_creds_wireless_inc
{
    meta:
        id = "25wRdGdWQfm7JQ11jEzvDu"
        fingerprint = "f3c6798de720e80fac783b0bc7a5b5b3bd9adfb92c2c72c2d885ea5c403dc663"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wireless_inc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0e8e21058dee56e0d14c51759c9d1a9c"
    $a1="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1)
}