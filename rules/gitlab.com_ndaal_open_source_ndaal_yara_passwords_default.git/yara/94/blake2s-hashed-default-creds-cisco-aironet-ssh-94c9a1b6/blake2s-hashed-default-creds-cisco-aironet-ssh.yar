rule blake2s_hashed_default_creds_cisco_aironet_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cisco_aironet_ssh."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bad09a0fcdb04bfbe31c7ecec2ece19776acabbd6261e6c34adfa0a538270198"
    $a1="bad09a0fcdb04bfbe31c7ecec2ece19776acabbd6261e6c34adfa0a538270198"
condition:
    ($a0 and $a1)
}