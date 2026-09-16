rule blake2s_hashed_default_creds_mcafee
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mcafee."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="31fda5a72bb24db49b13054be61607ac7df48d30f1742db30bf9d89e4f9e9663"
    $a1="cd8d976c68b4d40f5c51feffa27fcd7d5a4cdbccc6588f47f51957389f9432f5"
    $a2="251aba9d7cff47e60f7e1d9f229dc6427f8ad760f77845b8fb30c7250587b6f4"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="7c45880ed4fe8cdc628cccc4e9974b5f9bfde12491ec03c51c0dd45b8edb547f"
    $a5="add2c0b54bf4697eb0aca52551a61d99d759644cfa2828b41004b9e77313f1b7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}