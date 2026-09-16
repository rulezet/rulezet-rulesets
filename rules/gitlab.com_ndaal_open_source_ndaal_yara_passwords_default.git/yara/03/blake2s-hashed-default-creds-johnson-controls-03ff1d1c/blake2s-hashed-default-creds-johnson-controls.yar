rule blake2s_hashed_default_creds_johnson_controls
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for johnson_controls."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8523939fc72e236fb366f328392ad8616932d5ff9c04b849532dd4d7e5f0a310"
    $a1="04339265cbd585598dff41824389171eb4cb8bb7c70e6a45975486c2d641fecf"
condition:
    ($a0 and $a1)
}