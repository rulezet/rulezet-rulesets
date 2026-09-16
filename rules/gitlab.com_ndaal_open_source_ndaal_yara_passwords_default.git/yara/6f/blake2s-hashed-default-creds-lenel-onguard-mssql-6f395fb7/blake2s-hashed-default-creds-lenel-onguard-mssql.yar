rule blake2s_hashed_default_creds_lenel_onguard_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lenel_onguard_mssql."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2e45e80b631b9023517089ea2ef621c68ff33438f6a7235537521407ce2af920"
    $a1="9588bee56590a6531ff34fcfabc4c530b85d17a442b1347937cff4438e520cee"
condition:
    ($a0 and $a1)
}