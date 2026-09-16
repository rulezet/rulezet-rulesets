rule blake2s_hashed_default_creds_trafficware
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for trafficware."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dce4c0bc28ebe91daf7cce528339b1ef6339fa012f4510b4faaf20a14d071edb"
    $a1="dce4c0bc28ebe91daf7cce528339b1ef6339fa012f4510b4faaf20a14d071edb"
condition:
    ($a0 and $a1)
}