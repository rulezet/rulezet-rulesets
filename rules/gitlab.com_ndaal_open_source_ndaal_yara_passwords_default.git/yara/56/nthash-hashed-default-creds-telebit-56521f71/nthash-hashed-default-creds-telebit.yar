rule nthash_hashed_default_creds_telebit
{
    meta:
        id = "6ggTV4PUIbOGhHBUMjvEHD"
        fingerprint = "6cfaf03c1ad7ed2ea4edf6bc89b994e3c541633642be22af2d6e82b1b70ca14d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telebit."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e6aebf95ee750d35a58d279ad1fbf32b"
    $a1="e6aebf95ee750d35a58d279ad1fbf32b"
    $a2="1c4ff44400517285296ff2ad764c064a"
    $a3="27db353b7291d17f3ebc1fdc672a4630"
    $a4="39fe310c851e7b1e7f4aa1772787724f"
    $a5="27db353b7291d17f3ebc1fdc672a4630"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}