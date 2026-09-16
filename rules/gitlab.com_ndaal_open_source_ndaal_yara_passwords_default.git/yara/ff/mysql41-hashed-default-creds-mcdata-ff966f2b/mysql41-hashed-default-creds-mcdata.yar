rule mysql41_hashed_default_creds_mcdata
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mcdata."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a1="*A306E1FA191E2E149F608FF5E6DB287EC237CB1E"
    $a2="*66A9BDFBFB94F03EB50B36E9DA5F9672FAB82041"
    $a3="*918FAC6BBB0AD63425BD3DCDC6B06683029E7E50"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}