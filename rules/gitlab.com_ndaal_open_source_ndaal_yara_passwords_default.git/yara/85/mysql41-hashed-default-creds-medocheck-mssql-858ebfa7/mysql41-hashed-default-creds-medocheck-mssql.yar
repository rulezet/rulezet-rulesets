rule mysql41_hashed_default_creds_medocheck_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for medocheck_mssql."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*C1D9985513B000E0F5DE9EDDCD5372BA7D8B82D0"
    $a1="*316FFE861D0BFCA4F205E00605ADCDB8EC7BCD8B"
condition:
    ($a0 and $a1)
}