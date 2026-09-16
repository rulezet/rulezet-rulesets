rule sha256_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e35bd923db41777ba04b35a60180face8ae9980185bb1c20f769252d435cb89e"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="e35bd923db41777ba04b35a60180face8ae9980185bb1c20f769252d435cb89e"
    $a3="9a59f8de5c30f0b090106ddd0b380079180ffe58e76555e7e00b896157538c51"
    $a4="2fee81287225ebdaf3e72b1f8653be61698d05852741ce8614f88ee06c006bb0"
    $a5="70f1e97bc20f97d4a3c23722c7d0499d301afecf0c91273f8842bc8d682fab00"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}