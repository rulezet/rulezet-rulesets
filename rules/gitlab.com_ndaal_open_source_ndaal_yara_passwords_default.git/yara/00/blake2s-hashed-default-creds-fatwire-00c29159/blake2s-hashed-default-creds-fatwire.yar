rule blake2s_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6c8bf8ccb7ea986068d8d44dd08afb35b30f7729bdbd9de3a2ac891752a7585f"
    $a1="6c8bf8ccb7ea986068d8d44dd08afb35b30f7729bdbd9de3a2ac891752a7585f"
    $a2="aba602c6cde7862e4ecdb38559be007f9af4ab2d7b5cc0a8d5df4abfb4916582"
    $a3="187dd1868f0c27d2e8397572d328f7b68e9694f023f92e217795b39e524e8774"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}