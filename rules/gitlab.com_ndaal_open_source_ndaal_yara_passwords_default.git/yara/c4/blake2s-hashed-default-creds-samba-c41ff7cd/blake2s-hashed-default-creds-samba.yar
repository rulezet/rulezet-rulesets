rule blake2s_hashed_default_creds_samba
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for samba."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e5b3fd72350137e302475ed0363d8f4d7c2313aceb9f31d2a0aa45509de7c8c7"
    $a1="e5b3fd72350137e302475ed0363d8f4d7c2313aceb9f31d2a0aa45509de7c8c7"
condition:
    ($a0 and $a1)
}