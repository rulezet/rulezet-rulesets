rule nthash_hashed_default_creds_aris_mssql
{
    meta:
        id = "5ubLIV8IDI8H74AB4PjeO2"
        fingerprint = "3ed987794275227ce5678147516b28cda0c6a0f68cf6442a2be8c04fcedbf19d"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aris_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e9c71cd4d73bf86f97d4abcc7434810b"
    $a1="f898ee8aa6bb673e4be812151df93e22"
condition:
    ($a0 and $a1)
}