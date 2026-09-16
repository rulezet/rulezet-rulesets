rule nthash_hashed_default_creds_sma_solar_technology
{
    meta:
        id = "7NA8Pom7YSdW0gjeB1wVip"
        fingerprint = "d462818c203efba843abbe32e4f673d0acdf64bb0b2a1322b8f666e418c2f905"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sma_solar_technology."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5c1fa6977c9371431587369eb81c95c9"
    $a1="9db5a70db9fefabe408c978e8a130e22"
condition:
    ($a0 and $a1)
}