rule nthash_hashed_default_creds_keyscan
{
    meta:
        id = "6sEG4uWNr38kVetfrAJvfA"
        fingerprint = "fd54ddedb9f532cdbaf6898b03acbf96ca6c39849d711a98b38415417e387d72"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for keyscan."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6ee2955e4ebf1dab38c100ca98e3fa05"
    $a1="0368d2d1e90503f9b9f9f114160febe2"
condition:
    ($a0 and $a1)
}