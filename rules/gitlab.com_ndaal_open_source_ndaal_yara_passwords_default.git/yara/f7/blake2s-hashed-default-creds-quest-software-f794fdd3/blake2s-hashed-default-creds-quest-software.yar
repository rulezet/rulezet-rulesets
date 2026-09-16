rule blake2s_hashed_default_creds_quest_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for quest_software."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d660f01b3c91789204fa16a9d6d281c52b7467524d0b577df194ede5829d30a4"
    $a1="d660f01b3c91789204fa16a9d6d281c52b7467524d0b577df194ede5829d30a4"
condition:
    ($a0 and $a1)
}