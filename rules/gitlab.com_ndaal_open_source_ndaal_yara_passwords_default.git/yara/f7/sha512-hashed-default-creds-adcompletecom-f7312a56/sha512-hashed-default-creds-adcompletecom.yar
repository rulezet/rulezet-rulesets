rule sha512_hashed_default_creds_adcompletecom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for adcompletecom."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43192475f95e3820fe441daaff7c84d9b73ca3a5afc7309ae03f783151b6b0976e4d68cd990f97ad0d65ca640d35a407199d6d7510f1dff5477b8cfce1531475"
    $a1="43192475f95e3820fe441daaff7c84d9b73ca3a5afc7309ae03f783151b6b0976e4d68cd990f97ad0d65ca640d35a407199d6d7510f1dff5477b8cfce1531475"
condition:
    ($a0 and $a1)
}