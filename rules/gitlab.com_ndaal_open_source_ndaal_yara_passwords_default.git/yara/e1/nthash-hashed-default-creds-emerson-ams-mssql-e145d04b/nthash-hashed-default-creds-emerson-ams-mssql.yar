rule nthash_hashed_default_creds_emerson_ams_mssql
{
    meta:
        id = "5v6bLp2fLDmpB2AqIF3zy6"
        fingerprint = "c192b8080a7900bb0f15a42d21629a1cc5609bd7431200640f0eaf3a428c78b0"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for emerson_ams_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f9db9fa4489c727bbdadc3493ee51b6"
    $a1="9cb285c0622b8e5e8181a2b3d1654c17"
condition:
    ($a0 and $a1)
}