rule blake2s_hashed_default_creds_liebert
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for liebert."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="95d539301bfc53cced586ddcd21deacd7409afcb10d2fe2137407110b68f14b0"
    $a1="95d539301bfc53cced586ddcd21deacd7409afcb10d2fe2137407110b68f14b0"
condition:
    ($a0 and $a1)
}