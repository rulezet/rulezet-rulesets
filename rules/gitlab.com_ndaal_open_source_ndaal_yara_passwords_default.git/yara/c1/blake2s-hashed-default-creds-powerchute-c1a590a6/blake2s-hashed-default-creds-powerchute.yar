rule blake2s_hashed_default_creds_powerchute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for powerchute."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2fd8220eef3549107072fff7ad9b61d609d1e616e603132170fdf50487035ef7"
    $a1="2fd8220eef3549107072fff7ad9b61d609d1e616e603132170fdf50487035ef7"
condition:
    ($a0 and $a1)
}