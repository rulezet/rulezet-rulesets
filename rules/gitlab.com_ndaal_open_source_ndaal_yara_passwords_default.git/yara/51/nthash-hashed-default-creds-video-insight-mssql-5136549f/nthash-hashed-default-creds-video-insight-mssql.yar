rule nthash_hashed_default_creds_video_insight_mssql
{
    meta:
        id = "wPtx5EDt152hFi9TWW0Tx"
        fingerprint = "f953df1bb4274552a0b68a2194b8aec6c0f42fb864df28f3ba9ff80ee8958aa1"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for video_insight_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b6b9ee692e61f86603c0144c885c7c42"
    $a1="9cb285c0622b8e5e8181a2b3d1654c17"
condition:
    ($a0 and $a1)
}