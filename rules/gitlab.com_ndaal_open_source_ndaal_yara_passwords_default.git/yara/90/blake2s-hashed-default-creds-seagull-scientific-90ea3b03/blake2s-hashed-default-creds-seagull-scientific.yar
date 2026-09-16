rule blake2s_hashed_default_creds_seagull_scientific
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for seagull_scientific."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="6204076fc988d9c8ba327799ea12528be066aad0192027adfcd3b505067edd3e"
    $a2="d8a1c8b86992301ad37a36d12d5e68f44e68912a17ebebfb62ca216c0d35a547"
    $a3="d8a1c8b86992301ad37a36d12d5e68f44e68912a17ebebfb62ca216c0d35a547"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}