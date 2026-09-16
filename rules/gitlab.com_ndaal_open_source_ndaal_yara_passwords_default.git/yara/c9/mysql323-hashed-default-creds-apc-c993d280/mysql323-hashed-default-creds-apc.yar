rule mysql323_hashed_default_creds_apc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for apc."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7cdcc46a2c1a585d"
    $a1="69ddad3d54a22b52"
    $a2="7cdcc46a2c1a585d"
    $a3="7cdcc46a2c1a585d"
    $a4="7345b60a0a7868dd"
    $a5="1dbd4d345146e009"
    $a6="7cdcc46a2c1a585d"
    $a7="55743dec57707aa0"
    $a8="7cdcc46a2c1a585d"
    $a9="0dd0751e564477c7"
    $a10="0dd0751e564477c7"
    $a11="0dd0751e564477c7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}