rule nthash_hashed_default_creds_telestream_vantage_mssql
{
    meta:
        id = "6TLh3Hvsk0AYZmeD77zriU"
        fingerprint = "588c93f2a34875d4a5f35164ab419d61163ec0efa8ca5174d8b6206ad5a70294"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for telestream_vantage_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3e168c5f2e53f5fd9db4a149bb57a15f"
    $a1="9cb285c0622b8e5e8181a2b3d1654c17"
condition:
    ($a0 and $a1)
}