rule nthash_hashed_default_creds_utc_fcwnx_mssql
{
    meta:
        id = "P5wY9oYpuGsMSCvXrqn5S"
        fingerprint = "8c51014547f8210b6ed0e4f0678c4e8b33ff0e0b6f20c8bb59c13a9cb5309933"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for utc_fcwnx_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c2beb161f1b20358b8f8f3615a278e2"
    $a1="9cb285c0622b8e5e8181a2b3d1654c17"
condition:
    ($a0 and $a1)
}