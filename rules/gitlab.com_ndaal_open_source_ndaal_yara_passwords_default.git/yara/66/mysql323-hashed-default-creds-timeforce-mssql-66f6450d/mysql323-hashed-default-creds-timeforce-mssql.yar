rule mysql323_hashed_default_creds_timeforce_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for timeforce_mssql."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3c6e08027e7f9aac"
    $a1="077ff75a4925858c"
    $a2="4e5699227f8a9f0c"
    $a3="077ff75a4925858c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}