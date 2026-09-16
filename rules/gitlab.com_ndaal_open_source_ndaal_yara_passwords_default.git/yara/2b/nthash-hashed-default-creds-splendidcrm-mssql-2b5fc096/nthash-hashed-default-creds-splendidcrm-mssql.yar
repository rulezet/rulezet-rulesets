rule nthash_hashed_default_creds_splendidcrm_mssql
{
    meta:
        id = "1ltsVtbAIsSVMqwsKESLCn"
        fingerprint = "a817b228bfb0189e4d1a22cf562406fc399ce7bdcdbf9327588c92af25acc719"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for splendidcrm_mssql."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c19c26b60b4039b2ed8492625472f92a"
    $a1="9cb285c0622b8e5e8181a2b3d1654c17"
condition:
    ($a0 and $a1)
}