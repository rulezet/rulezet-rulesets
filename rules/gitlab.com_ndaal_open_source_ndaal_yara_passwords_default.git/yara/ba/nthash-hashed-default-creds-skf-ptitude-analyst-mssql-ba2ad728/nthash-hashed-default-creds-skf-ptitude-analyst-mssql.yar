rule nthash_hashed_default_creds_skf_ptitude_analyst_mssql
{
    meta:
        id = "5IyyUbGFM3tHuNbRP65aPR"
        fingerprint = "e646b4826036650e8436b717e6653ac011e3b159d44caccd2d9ad4fb0090e25a"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for skf_ptitude_analyst_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e6a2c80c1c08e9f942788812a32f65d8"
    $a1="9cb285c0622b8e5e8181a2b3d1654c17"
condition:
    ($a0 and $a1)
}