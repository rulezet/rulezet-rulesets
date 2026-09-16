rule mysql41_hashed_default_creds_ibm_maximo_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_maximo_mssql."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*B6A5CDC8F71C47EB0E332DC13BBAFFCCE94FC507"
    $a1="*B6A5CDC8F71C47EB0E332DC13BBAFFCCE94FC507"
    $a2="*53DD281F9F440143A2A7E16FEB92FAC462A4DDC4"
    $a3="*53DD281F9F440143A2A7E16FEB92FAC462A4DDC4"
    $a4="*7410A43B8B1756BFBF9F92D02759D1BD53C69598"
    $a5="*7410A43B8B1756BFBF9F92D02759D1BD53C69598"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}