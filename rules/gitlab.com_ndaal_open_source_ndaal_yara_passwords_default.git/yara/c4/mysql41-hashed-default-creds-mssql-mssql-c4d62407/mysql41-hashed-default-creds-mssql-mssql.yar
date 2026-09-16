rule mysql41_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*EF23B7D8B076353461321AE54C8DB2DA734D1E44"
    $a1="*AD7D041242E9B18AC223D6BDA09E2E0690115320"
    $a2="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    $a3="*4D0DD2673C1DE57138354E81A957460B774C4BC2"
    $a4="*B867055C61BEA33BAB533EF0900D1B193FBE6844"
    $a5="*4D0DD2673C1DE57138354E81A957460B774C4BC2"
    $a6="*4D0DD2673C1DE57138354E81A957460B774C4BC2"
    $a7="*4D0DD2673C1DE57138354E81A957460B774C4BC2"
    $a8="*97834F5F96357F6E82AEB7FE1FE91759EF69396F"
    $a9="*4D0DD2673C1DE57138354E81A957460B774C4BC2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}