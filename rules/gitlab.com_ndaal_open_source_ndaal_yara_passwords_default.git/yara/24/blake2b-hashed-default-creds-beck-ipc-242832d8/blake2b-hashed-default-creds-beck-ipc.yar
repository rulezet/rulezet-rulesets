rule blake2b_hashed_default_creds_beck_ipc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for beck_ipc."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="457b017ba59d6d3671494e09a38934a7295f116a6551b46aadebc4acb2c8ef20dfa070fd337344061f2a34fab8a5c1b5dd3ab9fb1f22d92f6c840b2c6c59fbc9"
    $a1="457b017ba59d6d3671494e09a38934a7295f116a6551b46aadebc4acb2c8ef20dfa070fd337344061f2a34fab8a5c1b5dd3ab9fb1f22d92f6c840b2c6c59fbc9"
condition:
    ($a0 and $a1)
}