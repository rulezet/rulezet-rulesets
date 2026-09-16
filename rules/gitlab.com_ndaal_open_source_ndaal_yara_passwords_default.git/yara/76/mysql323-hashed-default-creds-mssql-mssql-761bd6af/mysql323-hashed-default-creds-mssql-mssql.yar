rule mysql323_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="739ce4c8509ce556"
    $a1="410b87716417800e"
    $a2="5d2e19393cc5ef67"
    $a3="077ff75a4925858c"
    $a4="605d63e76a0fcaa8"
    $a5="077ff75a4925858c"
    $a6="077ff75a4925858c"
    $a7="077ff75a4925858c"
    $a8="0de0d2393651b07f"
    $a9="077ff75a4925858c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}