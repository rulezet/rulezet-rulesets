rule sha256_hashed_default_creds_quest_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for quest_software."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="14408fcdc99674131790d7311784649636897036c340a2a15c82c8a60df95a0b"
    $a1="14408fcdc99674131790d7311784649636897036c340a2a15c82c8a60df95a0b"
condition:
    ($a0 and $a1)
}