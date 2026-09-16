rule blake2s_hashed_default_creds_kodi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodi."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c97c5737fb17579fe5b7edf1189b7f0f00c3d945d8e782f66a35b51c1aa214f2"
    $a1="c97c5737fb17579fe5b7edf1189b7f0f00c3d945d8e782f66a35b51c1aa214f2"
condition:
    ($a0 and $a1)
}