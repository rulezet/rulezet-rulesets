rule nthash_hashed_default_creds_quest_software
{
    meta:
        id = "60CNc4i9ok4cabfoQxrvdm"
        fingerprint = "8a54787a299c33add1432b095c6bef1c2ffbf4bce820737eacaccc05d5b8ea19"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for quest_software."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c613174bcf7444b97d2a4e6eb07f5a2"
    $a1="8c613174bcf7444b97d2a4e6eb07f5a2"
condition:
    ($a0 and $a1)
}