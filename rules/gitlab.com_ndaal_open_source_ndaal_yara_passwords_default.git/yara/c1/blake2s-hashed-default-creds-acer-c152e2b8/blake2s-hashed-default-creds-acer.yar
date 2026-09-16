rule blake2s_hashed_default_creds_acer
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for acer."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="197dd409b8e7170377488c35c3c56d0797cb84e8563b222f8f5b1fa0156a4a9d"
    $a1="197dd409b8e7170377488c35c3c56d0797cb84e8563b222f8f5b1fa0156a4a9d"
condition:
    ($a0 and $a1)
}