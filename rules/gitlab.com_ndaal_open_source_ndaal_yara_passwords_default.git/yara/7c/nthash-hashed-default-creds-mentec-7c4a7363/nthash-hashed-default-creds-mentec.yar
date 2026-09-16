rule nthash_hashed_default_creds_mentec
{
    meta:
        id = "Pufjf9NzhyQV5lIRvSILG"
        fingerprint = "84a700c242c3bf70da17d7228b65fa3a7198ac09b7b7d71655b62253219bc636"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mentec."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2742d4e8bbcce1bd5df44a9cbe8f5849"
    $a1="caad23747fa118cba06e69eb3175c995"
condition:
    ($a0 and $a1)
}