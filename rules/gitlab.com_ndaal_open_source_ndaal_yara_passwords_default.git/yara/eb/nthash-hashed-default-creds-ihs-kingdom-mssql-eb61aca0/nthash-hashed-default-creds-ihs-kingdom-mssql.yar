rule nthash_hashed_default_creds_ihs_kingdom_mssql
{
    meta:
        id = "5CWul2RZzCKZQ4RSKoRMOq"
        fingerprint = "4027de6ea1cf391fd143a2f2fb902af8c3746b079dcbcc76e3e17b8a8ea428fe"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ihs_kingdom_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3d9931d8e8df922f508b32ee5553390b"
    $a1="9cb285c0622b8e5e8181a2b3d1654c17"
condition:
    ($a0 and $a1)
}