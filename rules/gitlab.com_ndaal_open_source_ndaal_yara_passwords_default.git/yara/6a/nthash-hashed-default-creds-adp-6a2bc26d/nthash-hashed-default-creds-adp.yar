rule nthash_hashed_default_creds_adp
{
    meta:
        id = "pkAsiiTjrUanS9eICWhE"
        fingerprint = "6e939273e4e8e9831e5927a516a2ba5fa817ace5ac75d7e97614cd4fd8832fcf"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adp."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6d3986e540a63647454a50e26477ef94"
    $a1="cc607a8ad1d888e0ffbbc71539e6d864"
condition:
    ($a0 and $a1)
}