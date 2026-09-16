rule blake2s_hashed_default_creds_exabyte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for exabyte."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="26a0c206749275a782fb6e04ce614a135bcee9ae1dfa3cf9d321e263bfa101ea"
    $a1="e06f7374ab7dc222d4086d9afc52ba24ddc4ac30018b423a2356ac6eb9fddaff"
condition:
    ($a0 and $a1)
}