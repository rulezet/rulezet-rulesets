rule mysql323_hashed_default_creds_apc_network_management_card_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc_network_management_card_web."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7cdcc46a2c1a585d"
    $a1="7cdcc46a2c1a585d"
    $a2="7cdcc46a2c1a585d"
    $a3="0dd0751e564477c7"
    $a4="7cdcc46a2c1a585d"
    $a5="55743dec57707aa0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}