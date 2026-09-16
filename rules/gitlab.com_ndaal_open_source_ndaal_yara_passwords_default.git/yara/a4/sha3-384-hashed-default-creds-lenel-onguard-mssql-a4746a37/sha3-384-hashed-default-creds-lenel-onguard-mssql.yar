rule sha3_384_hashed_default_creds_lenel_onguard_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lenel_onguard_mssql."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3d68cc4553d6275b12cafedfb75dea359b6e558d1294ea858bafff63a5eab5ddc48e97755cf9f19ee7f38ac8f76107f7"
    $a1="4426c0a1df8e673fc52d7cd73daecd204aa2c1eb4d49315d4e37e2a4b6fde15472eddf535d38e3c5fc3e8498a58c5ba9"
condition:
    ($a0 and $a1)
}