rule nthash_hashed_default_creds_easywinart_mssql
{
    meta:
        id = "5sW1uYcLwm2a094Tgh0Bqg"
        fingerprint = "f11dcaf6da8fc83e4750dd5b532f5ab7c74d8710700adac10ed0f963fc723276"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for easywinart_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1debcdca784f46e7e1b915ec7301fa1a"
    $a1="9cb285c0622b8e5e8181a2b3d1654c17"
condition:
    ($a0 and $a1)
}