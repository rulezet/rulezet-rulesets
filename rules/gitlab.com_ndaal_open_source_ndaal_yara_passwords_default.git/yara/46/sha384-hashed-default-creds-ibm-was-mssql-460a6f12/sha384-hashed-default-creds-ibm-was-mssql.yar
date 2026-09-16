rule sha384_hashed_default_creds_ibm_was_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_was_mssql."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="573efba8477ee21f309d7e3275c7cf0887a87ed148a448e057ab443a98c56b61a00bbaeaabe6036e62aec60c2de86f52"
    $a1="573efba8477ee21f309d7e3275c7cf0887a87ed148a448e057ab443a98c56b61a00bbaeaabe6036e62aec60c2de86f52"
condition:
    ($a0 and $a1)
}