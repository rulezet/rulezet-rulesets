rule sha512_hashed_default_creds_lasa_aims_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lasa_aims_mssql."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4c5bc412b9af5b52063ed1bbd577f1faa55d95d3706500d45d219340709e4e50dfec14b2e4dca3970d08934498ce0d82d2b652ca4a5fa7d2e51442d6519d93c6"
    $a1="238b90e6e2382ddafadc35266b2fa9a371fb3962b675ccab1b5538321f469070d0f3762f29b21ac7ad772eb6bd299d09f8e75d38ed8b7067965d5d5f26ebc3f5"
    $a2="4c5bc412b9af5b52063ed1bbd577f1faa55d95d3706500d45d219340709e4e50dfec14b2e4dca3970d08934498ce0d82d2b652ca4a5fa7d2e51442d6519d93c6"
    $a3="b6d398e188218d67f3d4939f9e1f6dba57f7e01063c50f585c53ab0bd4f804f1651bf41d32749c2d2dd2b2581b86a0effe5ba7d12fc364a5990908624be5d129"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}