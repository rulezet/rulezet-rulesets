rule blake2s_hashed_default_creds_dotnetnuke_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dotnetnuke_corporation."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f7b113ff801fb50023a83c2c33c2732f3506a821f7c5a80dcdf8d5a9f43eb043"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="6c59e495a609f814a354b7e23f9999b165ca4ace840cb56ead4c51d66fb9e978"
    $a3="473a20f542b5b6a611556a801d03a37bc325d068ae6a88f9e071046f8b37d01f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}