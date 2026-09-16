rule mysql41_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4641A030E43CF6B1B0A11F630D156E2500CA0BF2"
    $a1="*4641A030E43CF6B1B0A11F630D156E2500CA0BF2"
    $a2="*EC42B280643D13F3BF89ED2EC99BE05B2FB5AE9D"
    $a3="*4641A030E43CF6B1B0A11F630D156E2500CA0BF2"
    $a4="*656356A25E1A77D26C33E42D2F5C8FDFF140BC24"
    $a5="*4641A030E43CF6B1B0A11F630D156E2500CA0BF2"
    $a6="*4641A030E43CF6B1B0A11F630D156E2500CA0BF2"
    $a7="*4D0DD2673C1DE57138354E81A957460B774C4BC2"
    $a8="*EC42B280643D13F3BF89ED2EC99BE05B2FB5AE9D"
    $a9="*4D0DD2673C1DE57138354E81A957460B774C4BC2"
    $a10="*656356A25E1A77D26C33E42D2F5C8FDFF140BC24"
    $a11="*4D0DD2673C1DE57138354E81A957460B774C4BC2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}