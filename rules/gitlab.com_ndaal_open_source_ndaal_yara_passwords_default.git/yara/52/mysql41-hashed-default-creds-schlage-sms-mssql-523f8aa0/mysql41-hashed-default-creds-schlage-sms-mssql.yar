rule mysql41_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*6C370B79FA6C66B01F1E41711BFBF46DFD29762D"
    $a1="*4D0DD2673C1DE57138354E81A957460B774C4BC2"
    $a2="*6C370B79FA6C66B01F1E41711BFBF46DFD29762D"
    $a3="*CE624A915A6ECB07B43AF7BFB6F35EE40D616583"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}