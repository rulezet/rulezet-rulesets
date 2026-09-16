rule sha3_384_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c9a9f1fe5c2f7e69c342bedb55caaa6d54303c596f89734b36fc7603602eb3f13b25db9d916ab415cc55e03c9f0453ac"
    $a1="be66f54d071afe509f093ce39a02f1a7611035d17014ea0e01dc82a4c41997cbde86c2b667e08c34383508ce96a7289f"
    $a2="c9a9f1fe5c2f7e69c342bedb55caaa6d54303c596f89734b36fc7603602eb3f13b25db9d916ab415cc55e03c9f0453ac"
    $a3="f1489c225acb5ebe3c774772b80f34fb955dddc69a8c66f210e63eddc681aae0b3a5374624666a60cb41cd809d077c27"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}