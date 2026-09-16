rule nthash_hashed_default_creds_bosch_rps_mssql
{
    meta:
        id = "5Ht7ybrhpDVj6YuXT5wvj9"
        fingerprint = "518224460a74b1b9dca29201eacb8c0421a4138f8a33958bf7aa33d34148046a"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch_rps_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0868559b70b22aa06876307ff3fb46d7"
    $a1="9cb285c0622b8e5e8181a2b3d1654c17"
condition:
    ($a0 and $a1)
}