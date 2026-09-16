rule md5_hashed_default_creds_ibm_maximo_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_maximo_mssql."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cfc38813ee2f95d252773707d75466f8"
    $a1="cfc38813ee2f95d252773707d75466f8"
    $a2="bf090d435d40fdda5140c4ec65670344"
    $a3="bf090d435d40fdda5140c4ec65670344"
    $a4="951ac5658efd8732a33c6e2fc568856a"
    $a5="951ac5658efd8732a33c6e2fc568856a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}