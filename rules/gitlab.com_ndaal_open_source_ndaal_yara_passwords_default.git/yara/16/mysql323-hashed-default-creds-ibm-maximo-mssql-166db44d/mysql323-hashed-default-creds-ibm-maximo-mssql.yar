rule mysql323_hashed_default_creds_ibm_maximo_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_maximo_mssql."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="10da43215c436dfa"
    $a1="10da43215c436dfa"
    $a2="13be984a6212af91"
    $a3="13be984a6212af91"
    $a4="360653004ccc3ce9"
    $a5="360653004ccc3ce9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}