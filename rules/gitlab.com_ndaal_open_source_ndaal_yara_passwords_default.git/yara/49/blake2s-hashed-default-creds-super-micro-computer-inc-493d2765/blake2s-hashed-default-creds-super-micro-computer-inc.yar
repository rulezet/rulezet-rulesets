rule blake2s_hashed_default_creds_super_micro_computer_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for super_micro_computer_inc."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6204076fc988d9c8ba327799ea12528be066aad0192027adfcd3b505067edd3e"
    $a1="6204076fc988d9c8ba327799ea12528be066aad0192027adfcd3b505067edd3e"
condition:
    ($a0 and $a1)
}